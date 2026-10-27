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

A report can be saved even when the primary OOXML, OpenDocument, legacy Office, or RTF parser reports `failed`; in that case `analyze` returns exit code `1` and the report records the parser failure. A CLI, database, or output-write error returns exit code `2`. A nonzero exit code is a processing signal, not a malware verdict. Inspect the report status and warnings before interpreting the result.

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

Batch scanning is non-recursive by default. `--max-files` limits the number of unique files selected. The summary records per-file success or failure and can report partial results if discovery, analysis, or report writing fails. Individual reports, when requested, are JSON. Parser-reported failures are counted as file failures even when a report file is preserved; report-write failures are identified separately. The command returns `0` for a summary status of `ok`, `1` for `partial` or `failed`, and `2` if the summary itself cannot be written or another handled operational error occurs. A failure for one file does not stop processing later files.

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

When an analysis report is stored, it includes an `analysis_id`, including reports whose primary parser reported a failure. Use that ID to render the saved report in another format:

```bash
cvevident show-analysis 1 --format html --output ./reports/replayed.html
```

Replace `1` with an analysis ID from your database. The underlying file is not re-analyzed by `show-analysis`; the stored report data is rendered again. If the ID is absent, the command returns `1`. If the stored summary or evidence details contain malformed JSON, it reports an operational error and returns `2` rather than rendering a partial report.

## Troubleshooting

- Run `cvevident --help` or `cvevident COMMAND --help` to see command options.
- If you use a non-default database, place `--db PATH` **before** the subcommand.
- Run `cvevident doctor` to check database integrity and schema compatibility.
- If an analysis is `partial`, read the warnings: a resource limit, malformed structure, ambiguity, or parser recovery may have limited inspection.
- If a source synchronization fails, check network access and the detailed source state with `cvevident stats`; do not interpret missing local data as proof that no CVE exists.
