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
- package relationships with external targets, including a bounded number of target examples and separate counts for external `attachedTemplate`, hyperlink, and external-link-path relationships;
- Excel external-link parts, `connections.xml` metadata, query-table parts, and selected formula indicators associated with external content;
- Word field instructions and `altChunk` indicators;
- path-traversal-like or absolute package member names, duplicate names, encrypted members, and unreadable or malformed XML;
- package main-part identity, parser status, counts of inspected XML parts/bytes, warnings, and truncation indicators.

An external `attachedTemplate` relationship is recorded separately because remote template references are a documented Office technique (MITRE ATT&CK [T1221](https://attack.mitre.org/techniques/T1221/)). CVEvident records the relationship metadata but never fetches the template. The presence of an indicator is contextual: a macro-enabled document, external relationship, connection, or query table is not automatically malicious, and no relationship is proof that a target was contacted or used.

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

The input-size cap can be changed with the `analyze` command's `--max-bytes` option. The other limits are parser configuration defaults rather than CLI flags. If the analyzer skips content, encounters ambiguity, or reaches a cap, it records warnings and may use a `partial` status rather than claiming complete inspection. If the primary OOXML parser reports `failed`, `analyze` returns exit code `1`; `analyze-batch` marks that file as an analysis failure and continues with other inputs. A report can still be preserved in either workflow. See [Analysis and reports](analysis-and-reports.md) for command exit semantics.

## Example

```bash
cvevident analyze ./document.docm \
  --format json \
  --output ./reports/document.json
```

To inspect the human-readable output, use `--format markdown` or `--format html`. For an explanation of report interpretation and evidence bases, see [Analysis and reports](analysis-and-reports.md). For package families outside OOXML, see [Legacy Office, OpenDocument, and RTF triage](legacy-and-open-document-triage.md).

## Open Packaging Conventions consistency

The OOXML package report also checks the `[Content_Types].xml` declarations against the package member inventory. It accounts for both `Default` extension mappings and `Override` part mappings, compares part names using ASCII case-insensitive equivalence, and reports duplicate mappings, parts without a declared content type, and overrides that refer to absent parts. This follows ECMA-376 Part 2: every package part must resolve to a content type, and duplicate mappings for a given extension or part name are not permitted. These are package-integrity observations only; they do not indicate malware. See [ECMA-376 Part 2](https://ecma-international.org/publications-and-standards/standards/ecma-376/).

## Custom UI callback references

When a package contains a Custom UI part, CVEvident records declared RibbonX callback attributes such as `onLoad`, `loadImage`, `onAction`, and supported `get*` callbacks, along with the XML part and element where each reference occurs. Microsoft documents these attributes as references to callback procedures used by custom Office UI controls. The report records the callback name only; it does not resolve it to VBA or add-in code, and it does not invoke the callback. Custom UI callbacks are informational because legitimate Office add-ins and documents can use them. See [MS-CUSTOMUI: customUI root](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-customui/8a27e852-3f8b-424a-ac67-32c58181e9d3), [MS-CUSTOMUI: elements](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-customui/d842006e-3187-4f66-a17d-0819a3cc94b5), and [MS-CUSTOMUI: repurposed commands](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-customui/21316865-fbce-4a3f-a9ff-a8277cce5f2d).
