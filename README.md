# CVEvident

**CVEvident is a local-first tool for evidence-led static document triage and local CVE context.** It inspects supported documents without executing their content, records observations with source locations where available, and can compare those observations with vulnerability data already stored in a local SQLite database.

CVEvident is designed to help an analyst answer questions such as: *What structural features are present in this document? What parts were inspected? What could not be inspected? Is there an exact hash match in a locally maintained reference-sample collection? Which CVE records may be relevant to a product name I supplied?*

It is not a malware verdict engine, a dynamic sandbox, a document renderer, or proof that a file exploits a vulnerability.

## What it does

- **Static file triage:** examines PDF, modern Office Open XML, legacy OLE/CFB Office, OpenDocument, and RTF files within configured resource limits.
- **Content-aware identification:** uses file signatures and package metadata where available instead of trusting the filename alone; mismatches and incomplete parsing are reported.
- **Evidence and traceability:** records file identity, parser observations, bounded structural findings, warnings, and source-location details when the parser can provide them.
- **Local CVE context:** searches vulnerability and affected-product records imported from NVD, CISA's Known Exploited Vulnerabilities (KEV) catalog, and FIRST EPSS data.
- **Exact reference-sample matching:** can compare a file's SHA-256 with metadata registered in a local reference-sample collection. This is an exact byte-identity match, not a conclusion about related files.
- **Reusable reports:** emits JSON, Markdown, or HTML reports and stores analysis records and evidence in SQLite for later retrieval.
- **Batch workflows:** analyzes multiple files or directories, tracks per-file failures, and can write individual JSON reports plus a summary.

## What it does not do

CVEvident does not execute macros, scripts, JavaScript, RTF field instructions, or embedded content. It does not open or fetch hyperlinks and external relationships, decrypt protected documents, extract embedded attachments for recursive analysis, render documents, or perform dynamic execution. It does not claim complete semantic understanding of a document or calculate a definitive file-to-CVE attribution.

A missing indicator does not mean that a file is safe. A product-context match is a retrieval lead, not file attribution. See [Analysis and reports](docs/analysis-and-reports.md) and [Security and limitations](docs/security-and-limitations.md).

## Get started

### Requirements

- Python 3.10 or newer
- A supported operating system with a working Python environment
- Network access only if you choose to synchronize public vulnerability data; local file analysis uses the local database and does not need to contact data providers

### Install from a source checkout

```bash
git clone https://github.com/gashasbi/CVEvident.git
cd CVEvident
python -m venv .venv
```

Activate the virtual environment, then install the project:

```bash
# Linux / macOS
source .venv/bin/activate
python -m pip install .
```

On Windows PowerShell, activate with:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install .
```

Check the command-line interface and create the local database:

```bash
cvevident --help
cvevident init-db
cvevident doctor
```

By default, the database is stored at `~/.cvevident/cvevident.sqlite3`. Use `--db PATH` before a subcommand to select a different database. The `CVEVIDENT_HOME` environment variable can change the directory used for the default database.

### Analyze a document

```bash
cvevident analyze ./document.pdf --format json --output ./reports/document.json
```

Other report formats are available:

```bash
cvevident analyze ./document.docx --format markdown --output ./reports/document.md
cvevident analyze ./document.odt --format html --output ./reports/document.html
```

The report is written to the requested path. Use `--format json`, `--format markdown`, or `--format html`; JSON is the default. For a product-context search, supply the product details explicitly:

```bash
cvevident analyze ./document.pdf \
  --target-product "Acme Reader" \
  --target-vendor acme \
  --target-version 2.4 \
  --format json --output ./reports/document.json
```

The optional product fields are used to retrieve local affected-product context. They do not assert that the analyzed file contains or belongs to that product.

### Analyze a directory

```bash
cvevident analyze-batch ./incoming-documents \
  --recursive \
  --max-files 500 \
  --reports-dir ./reports/files \
  --output ./reports/batch-summary.json
```

Batch mode is non-recursive unless `--recursive` is supplied. It writes JSON summaries and, when requested, one JSON report per analyzed file. The file-count limit and input-byte limit help bound the work performed.

## Using local CVE data

The database starts locally and is not pre-populated with a complete vulnerability catalogue. Import data you already have or explicitly synchronize a source:

```bash
# Download and import public source data
cvevident sync-kev
cvevident sync-epss

# Import recently modified NVD CVEs (incremental; not a full initial import)
cvevident sync-nvd --days 7

# Or download and verify one annual NVD feed
cvevident sync-nvd-year 2025

# Inspect the local database
cvevident stats
cvevident doctor
```

`sync-nvd-years` can populate a larger historical range, but may consume substantial bandwidth, disk space, and time. Review [Local CVE data](docs/local-cve-data.md) before doing a full initial load. Synchronization commands contact the relevant data providers; ordinary `analyze` commands do not download vulnerability feeds.

Search imported records with:

```bash
cvevident search "remote code execution" --limit 20
cvevident show-cve CVE-2024-12345
cvevident search-product "Acme Reader" --vendor acme --version 2.4
```

The CVE identifier above is an illustrative command argument; use the identifier you actually want to look up. Product search is based on local affected-product CPE fields and uses conservative matching. It does not evaluate all NVD applicability logic. See [Local CVE data](docs/local-cve-data.md).

## Command overview

| Command | Purpose |
|---|---|
| `init-db` | Create or upgrade the local SQLite database |
| `stats` | Show local record counts and source synchronization state |
| `doctor` | Check database integrity and schema compatibility |
| `analyze` | Analyze one file and emit a report |
| `analyze-batch` | Analyze files and directories in a bounded batch |
| `show-analysis` | Rebuild a saved report by its analysis ID |
| `import-nvd` | Import a local NVD 2.0 JSON or JSON.GZ file |
| `import-kev` | Import a local CISA KEV JSON file |
| `import-epss` | Import a local FIRST EPSS CSV or CSV.GZ file |
| `import-samples` | Import reference-sample metadata (not sample bytes) |
| `sync-nvd` | Synchronize recently modified NVD records |
| `sync-nvd-year` / `sync-nvd-years` | Download, verify, and import annual NVD feeds |
| `sync-kev` / `sync-epss` | Download and import the current KEV or EPSS dataset |
| `sync-all` | Attempt the incremental NVD, KEV, and EPSS synchronization steps |
| `search` / `show-cve` | Search or display locally imported CVE records |
| `search-product` | Retrieve locally imported CVEs using affected-product context |

The global `--db` option must appear before the command, for example `cvevident --db ./data/local.sqlite3 stats`.

## Documentation

- [Getting started](docs/getting-started.md) — installation, first analysis, and common workflows
- [Supported formats](docs/supported-formats.md) — supported families and what is inspected
- [Analysis and reports](docs/analysis-and-reports.md) — evidence, statuses, report formats, and replay
- [Local CVE data](docs/local-cve-data.md) — imports, synchronization, freshness, and product-context limits
- [Office Open XML triage](docs/office-triage.md) — package structure, indicators, and boundaries
- [Legacy Office, OpenDocument, and RTF](docs/legacy-and-open-document-triage.md) — scope of the other document parsers
- [Security and limitations](docs/security-and-limitations.md) — resource caps, safe handling, and interpretation

## Project principles

1. **Local-first:** document analysis and report persistence happen locally.
2. **Evidence before conclusions:** the report describes observed structures and data provenance rather than making a malware verdict.
3. **Bounded inspection:** input size, archive contents, parser traversal, and displayed examples have limits.
4. **Honest uncertainty:** unsupported or incomplete paths are reported instead of being silently treated as fully analyzed.
5. **Separate evidence bases:** exact sample-hash matches and product-context CVE retrieval are kept distinct.

## License

[MIT](LICENSE)
