# API rulesets

Semantic validation rules for API response and request contracts.

| Ruleset | File | What it checks |
|---------|------|----------------|
| REST response | `openapi-response.json` | Error envelope structure (code + message), pagination metadata, resource identification |
| JSON:API | `jsonapi.json` | Top-level document structure, data/errors mutual exclusion, resource type/id, error objects |

## Usage

```
$ scheck validate response.json --rules rulesets/api/openapi-response.json
$ scheck validate response.json --rules rulesets/api/jsonapi.json
```

## Test fixtures

Test data lives under `etc/testdata/api/`.
