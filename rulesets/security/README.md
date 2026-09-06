# Security rulesets

Semantic validation rules for security advisories, SBOMs, and vulnerability records.

| Ruleset | File | Source | What it checks |
|---------|------|--------|----------------|
| CSAF 2.0 | `csaf-2.0-mandatory.json` | [CSAF 2.0 sec 6.1](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html), [csaf-rs](https://github.com/csaf-rs/csaf) | 16 patterns: required fields, tracking format, CVE/PURL/language format, translator source_lang (6.1.15), remediation/flag product refs (6.1.29/6.1.32), version range checks (6.1.31), profile tests (6.1.27) |
| CycloneDX min | `cyclonedx-min.json` | [CycloneDX 1.4+](https://cyclonedx.org/specification/overview/) | bomFormat, specVersion, component type/name/version, PURL format, metadata |
| CycloneDX quality | `cyclonedx-quality.json` | [sbomqs](https://github.com/interlynk-io/sbomqs), [sbom-scorecard](https://github.com/eBay/sbom-scorecard), NTIA | NTIA minimum elements, supplier, licenses, checksums, primary component, PURL/CPE format, dual-ID coverage |
| SPDX min | `spdx-min.json` | [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) | spdxVersion, dataLicense (CC0-1.0), SPDXID, creation info, package fields, relationships |
| SPDX CISA 2026 | `spdx-cisa-2026.json` | [2026 Minimum Elements for a SBOM](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom) (CISA, 2026-07-29; replaces NTIA 2021) | 2026 minimum-element data fields mapped to SPDX 2.3: SBOM author/tool/timestamp/data format, component name/producer/version/license/identifiers, component hash algorithm+value, dependency relationships; `strict` adds NOASSERTION filtering, tool version, PURL/URI format |
| VEX | `vex-coherence.json` | [OpenVEX](https://openvex.dev/) / [CSAF VEX](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) | Status coherence: not_affected requires justification, affected expects action_statement, valid status values |
| OSV | `osv.json` | [OSV Schema](https://ossf.github.io/osv-schema/) | id prefix, modified timestamp, affected package/range fields, reference URLs, severity types |
| Red Hat VEX | `redhat-csaf-vex.json` | [RH Security Data Guidelines](https://github.com/RedHatProductSecurity/security-data-guidelines) | Publisher metadata, severity taxonomy, product tree structure, PURL namespace, remediation conventions, threat categories |
| Red Hat SPDX SBOM | `redhat-sbom-spdx.json` | [RH Security Data Guidelines](https://github.com/RedHatProductSecurity/security-data-guidelines) | Document namespace, creator conventions, supplier, PURL/CPE refs, checksums |
| Red Hat CDX SBOM | `redhat-sbom-cyclonedx.json` | [RH Security Data Guidelines](https://github.com/RedHatProductSecurity/security-data-guidelines) | CycloneDX 1.6, serial number format, supplier, root component, PURL namespace |

## Usage

```
$ scheck validate advisory.json --rules rulesets/security/csaf-2.0-mandatory.json --phase full
$ scheck validate sbom.json --rules rulesets/security/cyclonedx-min.json
$ scheck validate sbom.json --rules rulesets/security/cyclonedx-quality.json --phase quality
$ scheck validate sbom.json --rules rulesets/security/spdx-min.json
$ scheck validate sbom.json --rules rulesets/security/spdx-cisa-2026.json --phase strict
$ scheck validate vex.json --rules rulesets/security/vex-coherence.json --phase full
$ scheck validate vuln.json --rules rulesets/security/osv.json
$ scheck validate vex.json --rules rulesets/security/redhat-csaf-vex.json --phase full
$ scheck validate sbom.json --rules rulesets/security/redhat-sbom-spdx.json
$ scheck validate sbom.json --rules rulesets/security/redhat-sbom-cyclonedx.json
```

## Phases

| Ruleset | Phases |
|---------|--------|
| CSAF 2.0 | `structural` (required fields only), `full` (adds format, profile, csaf-rs-derived checks) |
| CycloneDX quality | `ntia` (NTIA minimum elements only), `quality` (adds sbomqs/scorecard criteria) |
| SPDX CISA 2026 | `minimum` (2026 required data fields only), `strict` (adds NOASSERTION filtering, tool version, PURL/URI format) |
| VEX | `structural` (statement structure), `full` (adds CSAF VEX and OpenVEX coherence) |
| Red Hat VEX | `structural` (document/publisher/tracking), `full` (adds severity, product tree, remediations, PURL) |

## Limitations

These rulesets cover structural and format checks. Some spec requirements
need dedicated tooling like [csaf-rs](https://github.com/csaf-rs/csaf):

- Cross-reference uniqueness (CSAF 6.1.1-6.1.5, 6.1.22-6.1.25)
- CVSS computation and consistency (CSAF 6.1.8-6.1.10)
- CWE database lookup (CSAF 6.1.11)
- Sorted revision history (CSAF 6.1.14)
- SPDX license list validation
- Dependency graph connectivity (ntia-conformance-checker reachability analysis)
- Three 2026 SBOM Minimum Elements have no native SPDX 2.3 field and are not
  checked by `spdx-cisa-2026.json`: SBOM Version, SBOM Author Signature (a
  detached signature, outside the document body), and SBOM Generation Context

## Test fixtures

Test data lives under `etc/testdata/security/` with valid and invalid
documents for each format.
