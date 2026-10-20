# Office Open XML static triage

CVEvident's `analyze` command supports bounded, static package inspection for modern Microsoft Office Open XML formats:

- Word: `.docx`, `.docm`, `.dotx`, `.dotm`
- Excel: `.xlsx`, `.xlsm`, `.xltx`, `.xltm`, `.xlsb`, `.xlam`
- PowerPoint: `.pptx`, `.pptm`, `.ppsx`, `.ppsm`, `.potx`, `.potm`, `.ppam`, `.sldx`, `.sldm`

The analyzer identifies the package type from `[Content_Types].xml` rather than trusting the filename alone. A filename/content mismatch is reported. It inventories bounded ZIP package members, inspects selected XML and relationship parts without extracting files to disk, and records contextual indicators such as:

- VBA project binaries, ActiveX parts, embedded-object parts and custom UI parts;
- external package relationships, with a bounded sample of their declared targets;
- Excel external-link parts, selected formula indicators, and Word field/`altChunk` indicators;
- duplicate, encrypted, path-traversal-like or resource-limit-truncated package members;
- XML parts inspected and package-parser status.

## Safety boundary

This is **static structural triage**, not complete semantic interpretation of Word, Excel or PowerPoint, not a VBA decompiler, not a malware verdict, and not proof that a file exploits a CVE. Macros, scripts, hyperlinks, external relationships and embedded objects are never executed, followed, opened or extracted. No network requests are made by the analyzer.

ZIP/OOXML inspection is bounded by the configured compressed input byte cap (100 MiB by default), 10,000 ZIP members, 512 MiB declared total uncompressed size, 4 MiB per XML part, 32 MiB total XML bytes and 300 XML parts. If a cap is reached, ambiguous members exist, or some XML cannot safely be parsed, the report records a `partial` status and warnings rather than claiming full coverage. XML containing DTD/entity declarations is not parsed. The analyzer does not recursively analyze embedded attachments in this stage.

Legacy binary Office formats (`.doc`, `.xls`, `.ppt` and related OLE/CFB formats) are **not supported by this OOXML analyzer** and require a separate parser/analyzer. Password-protected OOXML documents may be wrapped in an OLE/CFB container; these are identified as unsupported and are not decrypted. A ZIP archive without a recognized Office main content type is not treated as an Office document.

## Examples

```bash
# Inspect a Word document or macro-enabled Word document
cvevident --db ./.local-test/office.sqlite3 analyze ./sample.docx --format json --output ./reports/sample-docx.json
cvevident --db ./.local-test/office.sqlite3 analyze ./sample.docm --format markdown --output ./reports/sample-docm.md

# Inspect Excel and PowerPoint package families
cvevident --db ./.local-test/office.sqlite3 analyze ./book.xlsm --format json --output ./reports/book-xlsm.json
cvevident --db ./.local-test/office.sqlite3 analyze ./presentation.pptm --format html --output ./reports/presentation-pptm.html
```

Use a separate local database for testing. Office observations are saved in the same analysis/evidence tables as PDF observations and can be replayed with `show-analysis`.
