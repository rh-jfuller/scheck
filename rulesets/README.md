# scheck rulesets

Ready-to-use rulesets for common document formats, organized by domain.

| Domain | Directory | Rulesets |
|--------|-----------|----------|
| [Security](security/) | `rulesets/security/` | CSAF 2.0, CycloneDX, SPDX, VEX, OSV |
| [API](api/) | `rulesets/api/` | REST response contracts, JSON:API |
| [Config](config/) | `rulesets/config/` | Kubernetes pod policy, GitHub Actions |
| [Data Quality](data-quality/) | `rulesets/data-quality/` | Contact records, dataset metadata |

## Usage

Point `--rules` at any ruleset file:

```
$ scheck validate doc.json --rules rulesets/security/csaf-2.0-mandatory.json
$ scheck validate response.json --rules rulesets/api/jsonapi.json
$ scheck validate pod.yaml --rules rulesets/config/kubernetes-pod.json
$ scheck validate contacts.json --rules rulesets/data-quality/contact-records.json
```

## Running all rulesets

```
$ make rulesets           # all domains
$ make rulesets-security  # security only
$ make rulesets-api       # api only
$ make rulesets-config    # config only
$ make rulesets-data-quality  # data quality only
```

## Adding rulesets

Create a new directory under `rulesets/` for your domain, add JSON rule files,
and put test fixtures under `etc/testdata/<domain>/`.

Rulesets are plain JSON -- any language can generate them, any tool can consume them.
