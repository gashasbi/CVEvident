# Supported formats

CVEvident performs bounded static inspection of selected document families. It is not a general-purpose document renderer or a semantic parser for every feature in those formats.

## Format families

| Family | Common extensions / container | What is inspected |
|---|---|---|
| PDF | `.pdf` or a recognized PDF header | SHA-256 and byte size, lexical PDF-name markers, byte-entropy metrics, and a bounded `pypdf` object-graph inspection for selected structural features and findings |
| Office Open XML (OOXML) | Word: `.docx`, `.docm`, `.dotx`, `.dotm`; Excel: `.xlsx`, `.xlsm`, `.xltx`, `.xltm`, `.xlsb`, `.xlam`; PowerPoint: `.pptx`, `.pptm`, `.ppsx`, `.ppsm`, `.potx`, `.potm`, `.ppam`, `.sldx`, `.sldm` | ZIP package inventory, `[Content_Types].xml` format identification, selected XML parts and relationships, and structural indicators for macros, embedded objects, links, fields, and selected formulas |
| Legacy binary Office | OLE/CFB containers commonly named `.doc`, `.xls`, `.ppt`, `.pps`, `.pot`, `.xlt`, or `.xla` | Bounded compound-file header, allocation-table and directory metadata; directory names are used for family and indicator classification |
| OpenDocument | `.odt`, `.ott`, `.ods`, `.ots`, `.odp`, `.otp` | ZIP package inventory, first-member `mimetype` identification, selected XML, manifest entries, and script/macro/embedded-object/external-reference indicators |
| Rich Text Format | `.rtf` or a recognized RTF signature | Bounded control-word and group scan, selected field-instruction and external-target strings, and indicators for embedded/binary content |

The format selected for analysis is based on content signatures first, with filename extensions used as a fallback in supported cases. A mismatch may be reported. A ZIP file without recognized Office or OpenDocument markers is not treated as a supported document just because it has a familiar extension.

## Important scope boundaries

### PDF

PDF inspection includes lexical markers and bounded structural traversal; byte entropy describes byte distribution only. CVEvident does not render pages, perform OCR, establish that all streams can be decoded, or execute JavaScript, launch actions, links, form actions, or embedded files.

### Office Open XML

OOXML is inspected as a ZIP package. Selected XML and relationship information may reveal macro projects, ActiveX, embedded objects, external relationships, hyperlinks, formula indicators, or Word field instructions. CVEvident does not fully interpret document semantics or decompile VBA.

### Legacy binary Office

Legacy Office support is intentionally narrower: CVEvident inventories OLE/CFB structure and directory metadata. It does not parse the full contents of Word, Excel, or PowerPoint streams and does not extract VBA source.

### OpenDocument and RTF

OpenDocument inspection is package- and XML-focused. RTF inspection is lexical and structural. Neither performs full document rendering or executes embedded scripts, field instructions, or object payloads.

## Unsupported or incomplete inputs

Depending on the format and failure point, a report may show `unsupported`, `failed`, `partial`, or another parser-specific status. A failed parser path may still preserve file identity and warnings. A partial report means that inspection was limited; it should not be read as a complete assessment of the file.

See the format-specific guides for detailed inspection boundaries:

- [Office Open XML triage](office-triage.md)
- [Legacy Office, OpenDocument, and RTF triage](legacy-and-open-document-triage.md)
- [Security and limitations](security-and-limitations.md)
