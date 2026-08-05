# Data quality rulesets

Data hygiene and metadata completeness checks for records and datasets.

| Ruleset | File | What it checks |
|---------|------|----------------|
| Contact records | `contact-records.json` | Required identity fields, email format, phone E.164 format, ISO country codes, contact method presence |
| Dataset metadata | `dataset-metadata.json` | Name/description/version, provenance, license, ISO 8601 dates, schema documentation |

## Usage

```
$ scheck validate contacts.json --rules rulesets/data-quality/contact-records.json
$ scheck validate dataset.json --rules rulesets/data-quality/dataset-metadata.json
```

## Test fixtures

Test data lives under `etc/testdata/data-quality/`.
