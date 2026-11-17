# CVEvident correlation demo

This directory contains synthetic test data. It does not describe a real CVE, vendor advisory, product, or vulnerability.

The demo creates a temporary SQLite database, imports one synthetic NVD record, imports one synthetic parser-evidence rule, and analyzes a small RTF file.

## Requirements

Install CVEvident from the project root:

```bash
python -m pip install -e ".[test]"
```

## Run

From the project root:

```bash
bash examples/correlation-demo/run.sh
```

The script runs three checks:

1. A matching RTF observation and matching environment CPE should produce `MATCH`.
2. The same RTF observation with a different product version should not produce an applicable environment result.
3. The same RTF observation without an environment CPE should produce `PARTIAL` or `UNKNOWN`, never `MATCH`.

The database and reports are created in a temporary directory and removed when the script exits. Set `KEEP_DEMO_OUTPUT=1` to keep them; the script prints the output directory.

## Test files

- `nvd-demo.json`: synthetic NVD-shaped record for `CVE-2099-12345`.
- `evidence-rules.json`: synthetic rule matching the exact RTF header observation.
- `sample.rtf`: minimal valid RTF input.

The rule deliberately matches `rtf.header` to demonstrate the mechanism. It is not a security detection rule and must not be reused as a real-world CVE rule.
