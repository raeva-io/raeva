# Vendored JSON schemas

These schemas are test fixtures. Tests embed them with `include_str!` and
never resolve references over the network. The tables are the file list.

## CycloneDX 1.5

The files come from the CycloneDX specification tag `1.5` and are licensed
under Apache-2.0. Relative references in the BOM schema point to
`jsf-0.82.schema.json` and `spdx.schema.json`.

| File | Source |
| --- | --- |
| `cyclonedx/bom-1.5.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/bom-1.5.schema.json |
| `cyclonedx/jsf-0.82.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/jsf-0.82.schema.json |
| `cyclonedx/spdx.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/spdx.schema.json |

## SARIF 2.1.0

The file accompanies SARIF Version 2.1.0, an OASIS Standard. OASIS Open holds
the copyright (2020). Redistribution is covered by the OASIS notices and IPR policy:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317447

| File | Source |
| --- | --- |
| `sarif/sarif-2.1.0.schema.json` | https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json |
