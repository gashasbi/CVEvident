# Getting started

This guide takes you from a source checkout to a saved analysis report and a working local CVE database.

## 1. Install

CVEvident requires Python 3.10 or newer. From the repository root, create and activate a virtual environment, then install the project:

```bash
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
python -m pip install .
```

Windows PowerShell activation:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install .
```

To run the test suite from a development checkout, install the test extra and use pytest:

```bash
python -m pip install -e ".[test]"
python -m pytest -q
```

For streaming import of large NVD JSON feeds, the optional `bulk` extra adds `ijson`:

```bash
python -m pip install -e ".[bulk]"
```

## 2. Initialize and check the local database

```bash
cvevident init-db
cvevident doctor
cvevident stats
```

The default SQLite database is `~/.cvevident/cvevident.sqlite3`. CVEvident creates the database directory when needed. To use a dedicated database for a project or experiment, pass `--db` before the subcommand:

```bash
cvevident --db ./work/cvevident.sqlite3 init-db
cvevident --db ./work/cvevident.sqlite3 doctor
```

`CVEVIDENT_HOME` can override the directory used by the default database. Source cache files default to `~/.cvevident/cache`; relevant synchronization commands accept `--cache-dir` or `--cache-file`. Explicit `--db` paths are useful for keeping test and operational data separate.

## 3. Analyze one file

```bash
cvevident analyze ./input/suspicious.pdf \
  --format json \
  --output ./reports/suspicious.json
```

Available output formats are `json`, `markdown`, and `html`. The default is JSON. If `--output` is omitted or set to `-`, the report is written to standard output. If a path is supplied, CVEvident writes the report there and prints a small JSON confirmation to standard output.

The input is read with a 100 MiB maximum by default. Set `--max-bytes` when a legitimate file requires a different limit; a larger limit also allows a larger input to be read and should be chosen deliberately.

## 4. Add optional product context

Product context is an explicit query against locally imported affected-product records. For example:

```bash
cvevident analyze ./input/document.pdf \
  --target-product "Acme Reader" \
  --target-vendor acme \
  --target-version 2.4 \
  --format markdown \
  --output ./reports/document.md
```

This may return CVE candidates related to the supplied product identity. It does not identify the analyzed file as that product and does not prove that the file is vulnerable.

## 5. Analyze multiple inputs

```bash
cvevident analyze-batch ./incoming \
  --recursive \
  --max-files 500 \
  --reports-dir ./reports/individual \
  --output ./reports/summary.json
```

Batch scanning is non-recursive by default. `--max-files` limits the number of unique files selected. The summary records per-file success or failure and can report partial results if discovery, analysis, or report writing fails. Individual reports, when requested, are JSON.

## 6. Populate the local CVE database

Import existing data files or use explicit synchronization commands:

```bash
cvevident sync-kev
cvevident sync-epss
cvevident sync-nvd --days 7
cvevident stats
```

The NVD modified-date command only retrieves recently modified records; it does **not** build a complete historical CVE database from scratch. Read [Local CVE data](local-cve-data.md) before downloading annual feeds or preparing a populated database.

## 7. Inspect or replay saved results

Every successful analysis is stored in the database. The report includes an `analysis_id`. Use it to rebuild a saved report in another format:

```bash
cvevident show-analysis 1 --format html --output ./reports/replayed.html
```

Replace `1` with the ID returned by your own analysis. The underlying file is not re-analyzed by `show-analysis`; the stored report data is rendered again.

## Troubleshooting

- Run `cvevident --help` or `cvevident COMMAND --help` to see command options.
- If you use a non-default database, place `--db PATH` **before** the subcommand.
- Run `cvevident doctor` to check database integrity and schema compatibility.
- If an analysis is `partial`, read the warnings: a resource limit, malformed structure, ambiguity, or parser recovery may have limited inspection.
- If a source synchronization fails, check network access and the detailed source state with `cvevident stats`; do not interpret missing local data as proof that no CVE exists.
