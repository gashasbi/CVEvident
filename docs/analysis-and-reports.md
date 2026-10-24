# Analysis and reports

CVEvident reports describe the bytes that were read, the structural observations made by the relevant parser, the inspection limitations, and any optional context retrieved from the local database. Reports are intended to preserve evidence and uncertainty, not to make a binary safe/malicious decision.

## Run an analysis

```bash
cvevident analyze ./document.pdf --format json
cvevident analyze ./document.docx --format markdown --output ./reports/document.md
cvevident analyze ./document.odt --format html --output ./reports/document.html
```

Supported report formats are:

- **JSON** — machine-readable report data; default format.
- **Markdown** — human-readable report with sections for the applicable analysis results and evidence.
- **HTML** — report suitable for viewing in a browser.

When `--output` is omitted or is `-`, the report goes to standard output. When a file path is supplied, CVEvident writes the report to that path and prints a JSON output confirmation.

## What a report contains

The exact fields depend on the document family and on what could be inspected. Common information includes:

- file name, byte size, and SHA-256 digest;
- parser status, structural observations, evidence records, and warnings;
- analysis coverage information and limitations where available;
- local reference-sample matches based on exact SHA-256;
- optional product-context CVE candidates, when a product query is supplied;
- evidence traceability and CVE association bases;
- an `analysis_id` for retrieving the saved result.

Parser-specific sections such as `structural_analysis`, `office_analysis`, `legacy_office_analysis`, `odf_analysis`, or `rtf_analysis` appear when relevant. These sections should be interpreted in the context of their warnings and scope declarations.

## Verdicts and parser status are different

CVEvident uses a cautious assessment model. The overall verdict is generally `not_assessed`: parser observations are not sufficient to decide that a file is malicious or safe. A parser's status describes its own inspection result; it is not a malware verdict.

- **Parsed** generally means the parser completed the portion of work it defines, not that every semantic feature of the file was understood.
- **Partial** means some inspection was limited or skipped, for example because of a malformed structure, ambiguous archive member, or a resource budget.
- **Failed** indicates that the selected parser could not carry out its intended inspection path.
- **Unsupported** indicates that the parser did not recognize a supported structure or format.

Status values can differ by parser, so always read the report fields and warnings rather than assuming every parser uses identical semantics.

## Evidence bases must remain distinct

CVEvident may report two different kinds of CVE-related context:

1. **Exact reference-sample match:** the analyzed file's SHA-256 exactly matches a registered sample metadata record. This identifies the same bytes as that sample record. The quality and meaning of any label or CVE link depend on the source and provenance stored with that record.
2. **Product-context retrieval:** a user-supplied product name, optional vendor, and optional version are compared with locally imported affected-product records. This is a candidate retrieval result, not proof that the file is the product, contains the product, or is affected by the CVE.

These bases are intentionally kept separate. CVE links from sample metadata retain their recorded provenance and verification state; lexical product matches are not converted into file attribution. KEV and EPSS are vulnerability-level signals, not document evidence.

## Replay a saved report

Analysis reports are persisted in SQLite. Use the returned analysis ID to render the saved report again:

```bash
cvevident show-analysis 12 --format markdown --output ./reports/analysis-12.md
```

Replace `12` with an analysis ID from your local database. This command renders the stored analysis record; it does not repeat the original file inspection.

## Batch reports

```bash
cvevident analyze-batch ./documents \
  --recursive \
  --max-files 500 \
  --reports-dir ./reports/per-file \
  --output ./reports/summary.json
```

Batch mode produces a JSON summary. If `--reports-dir` is supplied, it also writes individual JSON reports. The summary records discovery and per-file failures, duplicate paths, file-limit conditions, and whether report files were written. The batch exit status may be nonzero when some inputs fail or the file cap is reached; inspect the summary before treating the batch as complete.

## Handling reports

Reports may include file paths, hashes, package-member names, URLs that appeared in the input, product names, CVE metadata, and other contextual strings. Treat report files according to the sensitivity of the analyzed material. Review and redact them before sharing when necessary.
