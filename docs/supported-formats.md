# Supported formats

CVEvident performs bounded static inspection of selected document families. It is not a general-purpose document renderer or a semantic parser for every feature in those formats.

## Format families

| Family | Common extensions / container | What is inspected |
|---|---|---|
| PDF | `.pdf` or a recognized PDF header | SHA-256 and byte size, lexical PDF-name markers, byte-entropy metrics, and a bounded `pypdf` object-graph inspection for selected structural features and findings, including embedded-file navigation (`/GoToE`), associated-file entries (`/AF`), and file-attachment annotations |
| Office Open XML (OOXML) | Word: `.docx`, `.docm`, `.dotx`, `.dotm`; Excel: `.xlsx`, `.xlsm`, `.xltx`, `.xltm`, `.xlsb`, `.xlam`; PowerPoint: `.pptx`, `.pptm`, `.ppsx`, `.ppsm`, `.potx`, `.potm`, `.ppam`, `.sldx`, `.sldm` | ZIP package inventory, `[Content_Types].xml` format identification, selected XML parts and relationships, and structural indicators for macros, embedded objects, external attached templates, Excel external-data metadata, links, fields, and selected formulas, Custom UI callback references; `[Content_Types].xml` Default/Override consistency |
| Legacy binary Office | OLE/CFB containers commonly named `.doc`, `.xls`, `.ppt`, `.pps`, `.pot`, `.xlt`, or `.xla` | Bounded compound-file header, allocation-table and directory metadata; directory names are used for family and indicator classification |
| OpenDocument | `.odt`, `.ott`, `.ods`, `.ots`, `.odp`, `.otp` | ZIP package inventory, first-member `mimetype` identification, selected XML, manifest entries, script-event listeners and their declared macro bindings, macro-execution fields, external script references, embedded-object indicators, and external-reference schemes; manifest-to-package member consistency |
| Rich Text Format | `.rtf` or a recognized RTF signature | Bounded control-word and group scan, selected field-instruction and external-target strings, and indicators for embedded/binary content |

The format selected for analysis is based on content signatures first, with filename extensions used as a fallback in supported cases. A mismatch may be reported. A ZIP file without recognized Office or OpenDocument markers is not treated as a supported document just because it has a familiar extension. For an unrecognized suffix or non-document input, the current dispatch path falls back to the PDF analyzer; the report may show `structural_analysis.status` as `skipped_not_pdf` without treating the unknown format as a primary-parser failure. Do not interpret this fallback as support for the unknown format.

## Important scope boundaries

### PDF

PDF inspection includes lexical markers and bounded structural traversal; byte entropy describes byte distribution only. CVEvident does not render pages, perform OCR, establish that all streams can be decoded, or execute JavaScript, launch actions, links, form actions, or embedded files.

### Office Open XML

OOXML is inspected as a ZIP package. Selected XML and relationship information may reveal macro projects, ActiveX, embedded objects, external relationships, hyperlinks, formula indicators, or Word field instructions. CVEvident does not fully interpret document semantics or decompile VBA.

### Legacy binary Office

Legacy Office support is intentionally narrower: CVEvident inventories OLE/CFB structure and directory metadata. It does not parse the full contents of Word, Excel, or PowerPoint streams and does not extract VBA source.

### OpenDocument and RTF

OpenDocument inspection is package- and XML-focused. RTF inspection is lexical and structural. OpenDocument external-reference examples include their URI scheme for context. Neither format performs full document rendering or executes embedded scripts, field instructions, or object payloads.

## Unsupported or incomplete inputs

Depending on the format and failure point, a report may show `unsupported`, `failed`, `partial`, or another parser-specific status. A failed parser path may still preserve file identity and warnings. A partial report means that inspection was limited; it should not be read as a complete assessment of the file. A parser status of `failed` can still produce a persisted report. For the current command-level exit behavior, see [Analysis and reports](analysis-and-reports.md).

See the format-specific guides for detailed inspection boundaries:

- [Office Open XML triage](office-triage.md)
- [Legacy Office, OpenDocument, and RTF triage](legacy-and-open-document-triage.md)
- [Security and limitations](security-and-limitations.md)


## Research basis for structural indicators

The additional observations follow format specifications and documented techniques rather than generic malware assumptions:

- OOXML external attached-template relationships are tracked separately because [MITRE ATT&CK T1221](https://attack.mitre.org/techniques/T1221/) documents their abuse. Excel connection and query-table members are recorded as package metadata only.
- OOXML content-type consistency follows [ECMA-376 Part 2, Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/), which defines Default extension mappings, Override part mappings, and per-part content-type requirements.
- Custom Office UI callback references follow Microsoft's [MS-CUSTOMUI specification](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-customui/d842006e-3187-4f66-a17d-0819a3cc94b5). Callback names are recorded as metadata; callback code is not resolved or executed.
- ODF manifest consistency follows [OpenDocument 1.3 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.3/csprd01/part2-packages/OpenDocument-v1.3-csprd01-part2-packages.html). ODF event listeners, script references, and macro-execution fields follow the [OASIS OpenDocument 1.3 schema](https://docs.oasis-open.org/office/OpenDocument/v1.3/os/part3-schema/OpenDocument-v1.3-os-part3-schema.pdf).
- Legacy Office VBA component names follow Microsoft's [MS-OVBA specification](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/575462ba-bf67-4190-9fac-c275523c75fc).
- RTF field instructions and object groups follow the [RTF specification](https://latex2rtf.sourceforge.net/RTF-Spec-1.7.pdf); Microsoft documents the semantics of [DDEAUTO fields](https://learn.microsoft.com/en-us/openspecs/office_standards/ms-oe376/b9850510-7729-4f7d-9e7c-47131f64a5f5).
- PDF action and annotation observations follow Adobe's [PDF actions reference](https://opensource.adobe.com/dc-acrobat-sdk-docs/library/pdfmark/pdfmark_Actions.html), the [PDF 1.7 specification's GoToE action definition](https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf), and its [annotation types reference](https://opensource.adobe.com/dc-acrobat-sdk-docs/library/pdfmark/pdfmark_Basic.html). Associated-file (`/AF`) entries follow [ISO 32000-2's associated-file model](https://pdfa.org/files-inside-pdf/). Embedded-file inventory also accounts for the fact that [PDF embedded files are not necessarily all listed in the EmbeddedFiles name tree](https://pdfa.org/files-inside-pdf/).

These sources justify inspecting the named structures; they do not establish that a particular file is malicious. CVEvident keeps these observations informational and requires an explicitly reviewed, source-backed evidence rule before correlating a parser observation with a CVE.
