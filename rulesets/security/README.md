# Security rulesets

Semantic validation rules for security advisories, SBOMs, and vulnerability records.

| Ruleset | File | Spec | What it checks |
|---------|------|------|----------------|
| CSAF 2.0 | `csaf-2.0-mandatory.json` | [CSAF 2.0 sec 6.1](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) | Required document/tracking/publisher fields, tracking status values, CVE format, revision history entries |
| CycloneDX | `cyclonedx-min.json` | [CycloneDX 1.4+](https://cyclonedx.org/specification/overview/) | bomFormat, specVersion, component type/name/version, PURL format, metadata |
| SPDX | `spdx-min.json` | [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) | spdxVersion, dataLicense (CC0-1.0), SPDXID, creation info, package fields, relationships |
| VEX | `vex-coherence.json` | [OpenVEX](https://openvex.dev/) / [CSAF VEX](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) | Status coherence: not_affected requires justification, affected expects action_statement, valid status values |
| OSV | `osv.json` | [OSV Schema](https://ossf.github.io/osv-schema/) | id prefix, modified timestamp, affected package/range fields, reference URLs, severity types |

## Usage

```
$ scheck validate advisory.json --rules rulesets/security/csaf-2.0-mandatory.json --phase full
$ scheck validate sbom.json --rules rulesets/security/cyclonedx-min.json
$ scheck validate sbom.json --rules rulesets/security/spdx-min.json
$ scheck validate vex.json --rules rulesets/security/vex-coherence.json --phase full
$ scheck validate vuln.json --rules rulesets/security/osv.json
```

## Phases

Some rulesets support phases for incremental validation:

- **CSAF**: `structural` (required fields only) and `full` (adds format and category checks)
- **VEX**: `structural` (statement structure) and `full` (adds CSAF VEX and OpenVEX coherence)

## Limitations

These rulesets cover structural and format checks. Some spec requirements
need dedicated tooling:

- Cross-reference uniqueness (CSAF 6.1.1-6.1.5, 6.1.23-6.1.25)
- CVSS computation and consistency (CSAF 6.1.8-6.1.10)
- Sorted revision history (CSAF 6.1.14)
- Inter-document link validation

## Test fixtures

Test data lives under `etc/testdata/security/` with valid and invalid
documents for each format.
