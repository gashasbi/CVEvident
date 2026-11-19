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

## Unified parser coverage

Every analyzed report includes `analysis_coverage.parser_coverage`, regardless of which supported parser was selected. It uses the same domain names and status vocabulary for PDF, OOXML, OpenDocument, legacy OLE/CFB Office, and RTF:

- `format_identification` — whether the input was identified as a supported format;
- `container_structure` — inspection of the format's structural container or syntax;
- `content_inspection` — bounded static inspection of the content representation supported by that parser;
- `embedded_object_inventory` — inventory or indicators for embedded objects;
- `external_reference_inventory` — inventory or indicators for external references;
- `active_content_indicators` — static indicators for macros, scripts, actions, fields, or related content;
- `semantic_interpretation` — full semantic interpretation, which is currently reported as `not_inspected` and excluded from the declared static-scope overall status.

Each domain reports `status`, `in_declared_scope`, `inspected_count`, `inspected_unit`, `observed_count`, `limit_reached`, `scope`, and `limitations`. The `observed_count` is an indicator count, not a count of malicious objects. Some domains aggregate multiple indicator counters, which can overlap and do not represent unique objects; `observed_count_semantics` explains the count. A zero count does not prove absence outside the inspected scope.

Normalized domain statuses are:

- `complete` — the parser completed that domain within its declared static scope;
- `partial` — some inspection was performed, but a parser warning or limit prevents a completeness claim;
- `not_inspected` — the domain was not examined, including deliberately out-of-scope semantic interpretation;
- `not_applicable` — the domain does not apply to the selected format;
- `failed`, `unavailable`, `unsupported`, or `unknown` — the parser could not provide a reliable result for that domain.

`overall_status` summarizes only domains marked `in_declared_scope`. The existing `analysis_coverage` fields, including `parser_status`, `complete_for_declared_static_scope`, and `feature_assessments`, remain available for compatibility. `parser_coverage` is the normalized cross-parser view; its `complete` status does not mean full semantic validation or file safety.

## Verdicts and parser status are different

CVEvident uses a cautious assessment model. The overall verdict is generally `not_assessed`: parser observations are not sufficient to decide that a file is malicious or safe. A parser's status describes its own inspection result; it is not a malware verdict.

- **Parsed** generally means the parser completed the portion of work it defines, not that every semantic feature of the file was understood.
- **Partial** means some inspection was limited or skipped, for example because of a malformed structure, ambiguous archive member, or a resource budget.
- **Failed** indicates that the selected parser could not carry out its intended inspection path.
- **Unsupported** indicates that the parser did not recognize a supported structure or format.

Status values can differ by parser, so always read the report fields and warnings rather than assuming every parser uses identical semantics. A report may be saved and assigned an `analysis_id` even when its primary format parser reports `failed`.

## CLI exit status and report persistence

The exit code describes the command's processing outcome; it is not a malware verdict.

- **`analyze`:** returns `0` when the command completes without a primary-parser failure. It returns `1` when the selected primary parser for OOXML, OpenDocument, legacy Office, or RTF reports `failed`, even if the report was successfully printed or written and saved. A PDF structural warning or partial structural result does not automatically make the command fail. An operational error such as a database or output-write failure returns `2`.
- **`analyze-batch`:** returns `0` when its summary status is `ok`; it returns `1` when the summary is `partial` or `failed`. A parser-reported failure is represented in that file's result with `status: error`, `analysis_status: failed`, and `stage: analysis`. If the report was written, `report_path` can still be present. A failed report write uses `stage: report_write` and does not imply that the analysis itself failed. The batch continues with later inputs.
- **`show-analysis`:** returns `0` when a saved analysis is found and rendered, `1` when the ID is not found, and `2` for supported operational errors such as malformed stored JSON or a failed output write.

When `--output PATH` is supplied, a successful write prints a small JSON confirmation to standard output instead of printing the full report there. Consequently, a parser failure can return `1` while the requested report file was still written successfully. Read the report's parser status and warnings as well as the exit code.

## CVE correlation and applicability

CVEvident keeps four independent association bases:

1. **Exact reference-sample match:** the analyzed file's SHA-256 exactly matches a registered sample metadata record. This identifies the same bytes as that sample record. The quality and meaning of any label or CVE link depend on the source and provenance stored with that record.
2. **Product-context retrieval:** an operator-supplied product name, optional vendor, and optional version are compared with locally imported affected-product records. When no product is supplied, a product name/version may be inherited only from curated metadata attached to an exact SHA-256 reference-sample match; ambiguous sample identities do not trigger a search. Generic parser features are never promoted to product identities. This is a candidate retrieval result, not proof that the file is the product or is affected by the CVE.
3. **Environment CPE applicability:** one or more operator-supplied target CPE 2.3 identifiers are evaluated against the locally stored NVD configuration tree. Candidate retrieval includes both `vulnerable=true` and `vulnerable=false` CPE rows because platform CPEs may be required by NVD configuration logic. The evaluator preserves NVD `AND`, `OR`, and `negate` relationships and uses three-valued logic. Exact CPE components and simple dotted-numeric version ranges are supported; unsupported version syntax, invalid CPEs, and missing configuration data remain unknown. Candidate retrieval respects `--candidate-limit`; if truncated, the report marks retrieval as partial and states that CVEs outside the candidate set were not evaluated. This result applies to the supplied environment, not to the file.
4. **Source-backed parser evidence rules:** imported rules connect an exact parser evidence type/key (and optional exact value) to a CVE using a cited advisory or other reviewed source. Rules may be grouped with explicit `AND`/`OR` logic within one CVE and parser family. A positive match retains the evidence ID, source, confidence, and verification state; `validation_status` distinguishes verified from unverified matches. A missing observation is `NO_MATCH` only when its declared parser coverage domain is complete; otherwise it remains `UNKNOWN`.

The combined `correlation_status` is:

- `MATCH` only when at least one source-backed parser rule matches and the supplied environment is applicable;
- `PARTIAL` when one side matches but the other side is unknown or not configured;
- `NO_MATCH` when the evaluated rule or environment conditions contradict the configured relationship;
- `UNKNOWN` when the available data cannot support a determination.

These statuses describe the configured correlation criteria only. They do not establish that the file is malicious, that the file itself is the vulnerable product, or that an exploit succeeds. A generic marker such as VBA, OLE, JavaScript, or an external link is never mapped to a CVE unless an explicit source-backed rule has been imported. KEV and EPSS remain vulnerability-level signals, not document evidence.

Product-context results include three explanation areas:

- `ranking_explanation` reports the name-match class, matching vendor/product terms, version-match status, lexical relevance score, KEV/EPSS values, and the sort order used for retrieval. The score is not a probability, confidence estimate, or exploitability rating.
- `applicability_context` explains the CPE row used for retrieval. It is not the complete NVD configuration result; the latter is reported separately when `--environment-cpe` is supplied.
- `query_ambiguity` summarizes distinct vendor/product identities found across matching CPE rows before the result limit is applied. The displayed identity list can be truncated for large result sets.
- `product_identity_discovery` records whether the product was operator-supplied, inherited from exact-SHA curated sample metadata, ambiguous, or unavailable.
- `retrieval_completeness` identifies candidate-limit truncation. A result with no truncation observed is still limited by the records and historical years present in the local NVD database.
- Local NVD freshness reports list annual feed years with successful and partial/failed local imports. This is observed import history, not a claim that the full historical NVD range is present.

Read [CVE evidence rules](cve-evidence-rules.md) for the rule format, import command, exact matching behavior, and environment CPE examples.

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
