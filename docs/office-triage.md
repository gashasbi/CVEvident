# Office Open XML triage

CVEvident inspects Microsoft Office Open XML (OOXML) documents as bounded ZIP packages. It uses package content types to identify the main document family, then inspects selected XML and relationship parts for structural indicators. It does not render the document or attempt to reproduce all of Word, Excel, or PowerPoint semantics.

## Supported package families

| Family | Supported extensions |
|---|---|
| Word | `.docx`, `.docm`, `.dotx`, `.dotm` |
| Excel | `.xlsx`, `.xlsm`, `.xltx`, `.xltm`, `.xlsb`, `.xlam` |
| PowerPoint | `.pptx`, `.pptm`, `.ppsx`, `.ppsm`, `.potx`, `.potm`, `.ppam`, `.sldx`, `.sldm` |

The package is identified from `[Content_Types].xml` and the package structure, not from the filename alone. A filename/content mismatch is reported. A ZIP archive without a recognized Office main content type is not treated as an Office document.

## What is inspected

Within the declared limits, the parser inventories package members and selected XML parts. Depending on the file and the parts that can be safely inspected, findings may include:

- VBA project binaries, ActiveX parts, embedded-object parts, and custom UI parts;
- package relationships with external targets, including a bounded number of target examples;
- Excel external-link parts and selected formula indicators associated with external content;
- Word field instructions and `altChunk` indicators;
- path-traversal-like or absolute package member names, duplicate names, encrypted members, and unreadable or malformed XML;
- package main-part identity, parser status, counts of inspected XML parts/bytes, warnings, and truncation indicators.

The presence of an indicator is contextual. For example, a macro-enabled document is not automatically malicious, and an external relationship is not proof that the relationship was used.

## Safety boundaries

- Macros, scripts, hyperlinks, external relationships, and embedded objects are not executed, opened, followed, or fetched.
- Package members are not extracted to disk by this analyzer.
- XML containing DTD/entity declarations is not processed as ordinary application XML.
- The analyzer does not decrypt password-protected content or recursively inspect embedded attachments.
- It does not decompile VBA or fully interpret the meaning of Word, Excel, or PowerPoint content.

Password-protected OOXML may be wrapped in an OLE/CFB container. Such input is not decrypted; use the report's format/status fields and warnings to understand what was recognized.

## Resource limits

The default bounded-inspection limits include:

| Limit | Default |
|---|---:|
| Input file size | 100 MiB |
| ZIP member count | 10,000 |
| Declared total uncompressed package size | 512 MiB |
| Individual XML part | 4 MiB |
| Total XML bytes read for inspection | 32 MiB |
| XML parts inspected | 300 |
| Compression ratio for selected members | 1,000:1 |
| External relationship examples shown | 25 |
| Package-part inventory examples shown | 80 |

The input-size cap can be changed with the `analyze` command's `--max-bytes` option. The other limits are parser configuration defaults rather than CLI flags. If the analyzer skips content, encounters ambiguity, or reaches a cap, it records warnings and may use a `partial` status rather than claiming complete inspection.

## Example

```bash
cvevident analyze ./document.docm \
  --format json \
  --output ./reports/document.json
```

To inspect the human-readable output, use `--format markdown` or `--format html`. For an explanation of report interpretation and evidence bases, see [Analysis and reports](analysis-and-reports.md). For package families outside OOXML, see [Legacy Office, OpenDocument, and RTF triage](legacy-and-open-document-triage.md).
