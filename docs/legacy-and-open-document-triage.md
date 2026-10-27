# Legacy Office, OpenDocument, and RTF triage

These parsers provide narrower, bounded views of document structures. They preserve useful observations without claiming complete semantic interpretation or executing embedded content.

## Legacy binary Office (OLE/CFB)

### Recognized family

Legacy binary Office inputs are commonly named `.doc`, `.xls`, `.ppt`, `.pps`, `.pot`, `.xlt`, or `.xla`. CVEvident first recognizes the OLE/CFB container signature and then validates a bounded subset of the compound-file header, allocation chains, and directory structure.

The analyzer inventories directory entry names, entry types, and declared sizes to classify Word/Excel/PowerPoint families and report indicators related to macros, embedded objects, or external links. Those names are indicators only.

### What is not inspected

CVEvident does not interpret document stream bodies, extract VBA source, decompile or execute macros, decrypt protected documents, or extract embedded objects. This is directory-level triage, not a full OLE/CFB parser or malware verdict.

### Resource limits

The implementation bounds the number of FAT/DIFAT sectors, directory stream bytes and entries, chain traversal, and displayed directory inventory. The current defaults include limits of 4,096 FAT sectors, 4,096 DIFAT sectors, 8 MiB of directory bytes, 65,536 directory entries, 200,000 chain sectors, and 300 displayed inventory entries. Invalid sector references, cycles, truncation, or incompatible headers can produce warnings and a `partial`, `failed`, or `unsupported` status.

## OpenDocument (ODF)

Supported extensions are `.odt`, `.ott`, `.ods`, `.ots`, `.odp`, and `.otp`, covering text, spreadsheet, presentation, and template packages. ODF packages are ZIP containers whose `mimetype` member identifies the family. CVEvident checks the package structure and inspects selected XML, including `content.xml` and manifest information where available.

Possible indicators include scripts/macros, embedded objects, external references, unsafe member names, duplicate names, encrypted members, missing package parts, and XML parsing or resource-limit issues. The parser does not execute scripts, macros, formulas, or links and does not extract embedded files. A package with an absent or unrecognized mimetype is not silently treated as a supported ODF file.

ODF shares the bounded ZIP/XML budgets used for OOXML: the default 100 MiB input cap, 10,000 archive members, 512 MiB declared uncompressed total, 4 MiB per XML part, 32 MiB total XML inspection bytes, 300 XML parts, and a 1,000:1 compression-ratio threshold for selected members. See [Office Open XML triage](office-triage.md) for the shared archive limits.

## Rich Text Format (RTF)

RTF inspection is a bounded lexical and structural scan. It counts selected control words, tracks group nesting and balance, looks for field instructions and external-target strings, and skips declared binary payloads rather than scanning those bytes as ordinary control text.

The scanner does not render the document, execute field instructions, fetch targets, or decode and interpret embedded OLE payloads. It is not a complete RTF grammar or a malware verdict.

Default scan limits include 16 MiB of RTF input scanned, group nesting depth of 4,096, and 1,000,000 control words. Reaching a cap, finding truncated binary payloads, or seeing unbalanced groups may result in warnings or a `partial` status.

## Example

```bash
cvevident analyze ./legacy.doc --format json --output ./reports/legacy.json
cvevident analyze ./document.odt --format markdown --output ./reports/document.md
cvevident analyze ./rich-text.rtf --format html --output ./reports/rich-text.html
```

Format dispatch prefers recognizable content signatures where available; file extensions are fallbacks, not proof of actual content. A wrong suffix may be reported. If the primary parser for legacy Office, OpenDocument, or RTF reports `failed`, `analyze` returns exit code `1`, while the report can still be persisted. In batch mode, that file is recorded as failed and later files continue to be processed. For general interpretation guidance, see [Analysis and reports](analysis-and-reports.md) and [Security and limitations](security-and-limitations.md).
