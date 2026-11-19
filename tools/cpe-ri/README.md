# NIST CPE reference comparison

This small Java adapter runs the official NIST CPE 2.3 Reference Implementation
against the same source/target name pairs used by CVEvident's Python matcher.
It is test-only and is not a runtime dependency of CVEvident.

The adapter is pinned to
`gov.nist.secauto.cpe:cpe-reference-implementation:1.0.8`.

Run the differential test locally with Java 17, Maven, and the Python test
dependencies installed:

```bash
mvn --batch-mode --file tools/cpe-ri/pom.xml package dependency:build-classpath -Dmdep.outputFile=target/classpath.txt
export CPE_NIST_RI_CLASSPATH="$PWD/tools/cpe-ri/target/classes:$(cat tools/cpe-ri/target/classpath.txt)"
python -m pytest -q tests/test_cpe_nist_differential.py
```

The test compares the overall CPE name relation and all eleven attribute
relations. It covers representative exact, ANY/NA, source wildcard, escaped
character, and target-wildcard cases. It does not test NVD version-range
semantics, which are an NVD applicability layer above CPE name matching.

The Java library is maintained by NIST and implements the CPE Naming and Name
Matching algorithms. See
https://pages.nist.gov/cpe-reference-implementation/ and
https://doi.org/10.6028/NIST.IR.7696.
