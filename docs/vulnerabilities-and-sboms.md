# Vulnerability scans and SBOMs

`rv vuln` scans the dependencies in `rv.lock` against OSV. It writes a table by
default and also supports JSON and SARIF 2.1.0. Exit code 0 means the scan
completed without findings at or above the `--fail-on` threshold, 1 means it
completed with findings, and 2 means the scan did not complete. CI can
distinguish a finding from a network, API, or input failure.

`rv sbom` generates CycloneDX 1.5 or SPDX 2.3 from `rv.lock`. Documents include
the locked SHA-256 hashes, stable ordering, and content-derived identifiers.
CycloneDX output is byte-identical for the same lock; SPDX includes its required
creation timestamp. Set `SOURCE_DATE_EPOCH` to a Unix timestamp for
byte-identical SPDX output. `rv.lock` does not carry license evidence, so SPDX
license fields are `NOASSERTION` and CycloneDX omits licenses.

```bash
rv vuln
rv vuln --format sarif --fail-on high
rv sbom --format cyclonedx -o bom.cdx.json
rv sbom --format spdx -o bom.spdx.json
```
