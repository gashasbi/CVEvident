# Security and limitations

CVEvident is intended for evidence-led static triage of suspicious documents. Static inspection reduces the need to open or execute a potentially hostile file, but it does not make parsing risk-free and cannot guarantee that a file is benign.

## Operating model

- **No content execution:** document macros, scripts, JavaScript, RTF field instructions, links, external relationships, and embedded objects are not run.
- **No external target following:** links and relationship targets are recorded as text where available; they are not fetched by the document analyzers.
- **Local database:** analysis results and imported CVE context are persisted in SQLite on the local machine.
- **Explicit synchronization:** network connections to NVD, CISA KEV, or FIRST EPSS occur when the corresponding synchronization command is run, not as part of ordinary file analysis.
- **Bounded work:** input size, parser traversal, archive entry counts, XML reads, object counts, and displayed examples are capped.

## Default resource boundaries

These are implementation defaults and can change between releases. The input-size cap for `analyze` and `analyze-batch` defaults to 100 MiB and can be set with `--max-bytes`.

| Parser | Examples of default limits |
|---|---|
| PDF | 20,000 object containers, graph depth 64, 500 reported structural findings, bounded parser/stream resource settings |
| OOXML / ODF | 10,000 ZIP entries, 512 MiB declared uncompressed bytes, 4 MiB per XML part, 32 MiB total XML bytes, 300 XML parts, selected-member compression-ratio cap of 1,000:1 |
| Legacy OLE/CFB Office | 4,096 FAT sectors, 4,096 DIFAT sectors, 8 MiB of directory bytes, 65,536 directory entries, 200,000 chain sectors, 300 displayed inventory entries |
| RTF | 16 MiB scanned, group depth 4,096, 1,000,000 control words |

An input over the configured input-byte limit is rejected instead of being read without bound. A parser may also report `partial` when a structural or resource limit is reached after reading the file. Consult the format-specific report section and warnings for the actual path taken.

## Interpret observations carefully

- **A finding is not a verdict.** Structural markers can be present in benign files and absent from files that deserve investigation.
- **No finding is not proof of safety.** The parser's declared scope is limited and some content is intentionally not decoded or interpreted.
- **Entropy is not maliciousness.** Entropy describes byte distribution and is not semantic similarity or a malware classifier.
- **A CVE candidate is not file attribution.** Product-context searches are lexical retrieval over local affected-product data; they do not prove the identity of the analyzed file or that it is affected.
- **A sample label depends on provenance.** An exact SHA-256 match identifies the same bytes as a registered sample. It does not independently validate the sample label or the provenance of linked CVEs.
- **Data freshness is local.** Search results reflect what has been imported into the local database; unimported or stale data can be missing.
- **Exit status is not severity.** A nonzero CLI exit code can mean that a parser or an output operation failed. A report may still be saved when a parser reports failure; interpret parser-specific status fields and warnings separately from the command exit code.

## Safer use with untrusted documents

Treat suspicious files as untrusted input even when using a static analyzer. For high-risk samples, run CVEvident in a disposable or isolated environment with least privilege, controlled access to sensitive files, and appropriate resource limits. Keep the tool and its Python dependencies maintained. Do not run it with elevated privileges merely to analyze a document.

Consider reports sensitive: they can contain source file names and paths, hashes, package-member names, URLs, and other data derived from the input. Review reports before sharing them outside the investigation team.

## Data handling and network activity

The document analyzers do not download referenced URLs or external relationships. Explicit synchronization commands fetch vulnerability feeds from their configured public providers and write downloaded feed/cache files locally. If network access is prohibited in the environment, use local import commands with feed files already obtained through an approved process.

CVEvident is a triage and research aid. Validate important findings with primary advisories, vendor information, and a reproducible investigation before making operational or incident-response decisions.
