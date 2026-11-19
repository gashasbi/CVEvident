# Legacy Office, OpenDocument, and RTF triage

These parsers provide narrower, bounded views of document structures. They preserve useful observations without claiming complete semantic interpretation or executing embedded content.

## Legacy binary Office (OLE/CFB)

### Recognized family

Legacy binary Office inputs are commonly named `.doc`, `.xls`, `.ppt`, `.pps`, `.pot`, `.xlt`, or `.xla`. CVEvident first recognizes the OLE/CFB container signature and then validates a bounded subset of the compound-file header, allocation chains, and directory structure.

The analyzer inventories directory entry names, entry types, and declared sizes to classify Word/Excel/PowerPoint families and report indicators related to macros, embedded objects, or external links. For VBA, it now reports separate directory-name presence flags for the conventional `VBA` storage, `_VBA_PROJECT`, `dir`, `PROJECT`, `PROJECTwm`, and `PROJECTlk` entries. These are independent name observations, not proof that a complete or valid VBA project exists. Microsoft documents the VBA storage and its project/module streams in the [MS-OVBA specification](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/575462ba-bf67-4190-9fac-c275523c75fc).

### What is not inspected

CVEvident does not interpret document stream bodies, extract VBA source, decompile or execute macros, decrypt protected documents, or extract embedded objects. This is directory-level triage, not a full OLE/CFB parser or malware verdict.

### Resource limits

The implementation bounds the number of FAT/DIFAT sectors, directory stream bytes and entries, chain traversal, and displayed directory inventory. The current defaults include limits of 4,096 FAT sectors, 4,096 DIFAT sectors, 8 MiB of directory bytes, 65,536 directory entries, 200,000 chain sectors, and 300 displayed inventory entries. Invalid sector references, cycles, truncation, or incompatible headers can produce warnings and a `partial`, `failed`, or `unsupported` status.

## OpenDocument (ODF)

Supported extensions are `.odt`, `.ott`, `.ods`, `.ots`, `.odp`, and `.otp`, covering text, spreadsheet, presentation, and template packages. ODF packages are ZIP containers whose `mimetype` member identifies the family. CVEvident checks the package structure and inspects selected XML, including `content.xml` and manifest information where available.

Possible indicators include scripts/macros, event listeners, macro-execution fields, embedded objects, external script references, external-reference URI schemes, unsafe member names, duplicate names, encrypted members, missing package parts, and XML parsing or resource-limit issues. When the manifest is readable, CVEvident also compares its `manifest:file-entry` paths with package members (excluding `mimetype` and `META-INF` entries as specified for the package manifest). It reports duplicate manifest paths, package files absent from the manifest, and manifest paths absent from the package. These checks are package-consistency evidence, not malware indicators. For each readable `script:event-listener`, the report also preserves its declared event name, macro name, script language, and `xlink:href` when present. These attributes describe the event-to-macro binding in the ODF schema; CVEvident does not resolve the referenced source or execute it. The manifest's role in listing package files and describing encrypted entries is defined in [OpenDocument 1.3 Part 2](https://docs.oasis-open.org/office/OpenDocument/v1.3/csprd01/part2-packages/OpenDocument-v1.3-csprd01-part2-packages.html). ODF `script:event-listener` elements bind events to macros, and their `xlink:href` may identify macro code; `text:execute-macro` represents a macro field. These observations follow the [OASIS OpenDocument 1.3 schema](https://docs.oasis-open.org/office/OpenDocument/v1.3/os/part3-schema/OpenDocument-v1.3-os-part3-schema.pdf). Scheme and element metadata are reported as context only; targets are never fetched. The parser does not execute scripts, macros, formulas, or links and does not extract embedded files. A package with an absent or unrecognized mimetype is not silently treated as a supported ODF file.

ODF shares the bounded ZIP/XML budgets used for OOXML: the default 100 MiB input cap, 10,000 archive members, 512 MiB declared uncompressed total, 4 MiB per XML part, 32 MiB total XML inspection bytes, 300 XML parts, and a 1,000:1 compression-ratio threshold for selected members. See [Office Open XML triage](office-triage.md) for the shared archive limits.

## Rich Text Format (RTF)

RTF inspection is a bounded lexical and structural scan. It counts selected control words, including OLE object-type controls such as `objocx` and `objhtml`, tracks group nesting and balance, counts recognized field-instruction keywords separately (including `DDEAUTO`, `DDE`, `INCLUDETEXT`, and `INCLUDEPICTURE`), looks for external-target strings, and skips declared binary payloads rather than scanning those bytes as ordinary control text. RTF field instructions and object destinations are defined in Microsoft's [RTF 1.9.1 specification](https://latex2rtf.sourceforge.net/RTF-Spec-1.7.pdf) and later Office field documentation; the counters identify syntax only, not execution or maliciousness.

The scanner does not render the document, execute field instructions, fetch targets, or decode and interpret embedded OLE payloads. It is not a complete RTF grammar or a malware verdict.

Default scan limits include 16 MiB of RTF input scanned, group nesting depth of 4,096, and 1,000,000 control words. Reaching a cap, finding truncated binary payloads, or seeing unbalanced groups may result in warnings or a `partial` status.

## Example

```bash
cvevident analyze ./legacy.doc --format json --output ./reports/legacy.json
cvevident analyze ./document.odt --format markdown --output ./reports/document.md
cvevident analyze ./rich-text.rtf --format html --output ./reports/rich-text.html
```

Format dispatch prefers recognizable content signatures where available; file extensions are fallbacks, not proof of actual content. A wrong suffix may be reported. If the primary parser for legacy Office, OpenDocument, or RTF reports `failed`, `analyze` returns exit code `1`, while the report can still be persisted. In batch mode, that file is recorded as failed and later files continue to be processed. For general interpretation guidance, see [Analysis and reports](analysis-and-reports.md) and [Security and limitations](security-and-limitations.md).
