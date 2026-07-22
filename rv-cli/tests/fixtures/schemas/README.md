# Vendored JSON schemas

These schemas are test fixtures. Tests load them from disk and never resolve
references over the network.

## CycloneDX 1.5

- `cyclonedx/bom-1.5.schema.json`
  - https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/bom-1.5.schema.json
- `cyclonedx/jsf-0.82.schema.json`
  - https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/jsf-0.82.schema.json
- `cyclonedx/spdx.schema.json`
  - https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/spdx.schema.json

The files come from the CycloneDX specification tag `1.5` and are licensed
under Apache-2.0. The companion schemas satisfy the BOM schema's relative
references.

## SPDX 2.3

- `spdx/spdx-2.3.schema.json`
  - https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json

The file comes from the SPDX specification tag `v2.3`. Copyright Linux
Foundation and its contributors, licensed under CC-BY-3.0:
https://github.com/spdx/spdx-spec/blob/v2.3/LICENSE

## SARIF 2.1.0

- `sarif/sarif-2.1.0.schema.json`
  - https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json

The file accompanies the OASIS SARIF Version 2.1.0 OASIS Standard. Copyright
OASIS Open 2020. Redistribution is covered by the OASIS notices and IPR policy:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317447
