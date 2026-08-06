# scheck examples

Practical examples for semantic validation with scheck.
Each example includes a JSON rule file, input documents, and CLI invocations.
All files live under [`etc/examples/`](../etc/examples/).

DSL equivalents (`.scheck` files) are provided alongside each JSON rule file
for those who prefer a concise hand-written format.

## Required fields

Ensure a document contains mandatory fields.

**Rules:** [`required-fields.json`](../etc/examples/required-fields.json)
| [DSL](../etc/examples/required-fields.scheck)

```json
{
  "title": "required fields",
  "patterns": [
    {
      "name": "basics",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.name" },
              "message": "name is required"
            },
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.email" },
              "message": "email is required"
            }
          ]
        }
      ]
    }
  ]
}
```

```
$ scheck validate etc/examples/required-fields-pass.json --rules etc/examples/required-fields.json
OK: all checks passed

$ scheck validate etc/examples/required-fields-fail.json --rules etc/examples/required-fields.json
[error] basics at $: email is required

1 error(s), 0 warning(s), 0 info(s)
```

---

## Forbidden fields

Reject documents containing sensitive fields.

**Rules:** [`forbidden-fields.json`](../etc/examples/forbidden-fields.json)
| [DSL](../etc/examples/forbidden-fields.scheck)

```json
{
  "title": "no secrets",
  "patterns": [
    {
      "name": "security",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "not_exists", "path": "$.password" },
              "message": "must not contain password",
              "flag": "security"
            },
            {
              "kind": "assert",
              "test": { "type": "not_exists", "path": "$.secret" },
              "message": "must not contain secret",
              "flag": "security"
            }
          ]
        }
      ]
    }
  ]
}
```

```
$ scheck validate etc/examples/forbidden-fields-pass.json --rules etc/examples/forbidden-fields.json
OK: all checks passed

$ scheck validate etc/examples/forbidden-fields-fail.json --rules etc/examples/forbidden-fields.json
[error] security at $: must not contain password

1 error(s), 0 warning(s), 0 info(s)
```

---

## Regex matching

Validate string values match an expected format.

**Rules:** [`regex-matching.json`](../etc/examples/regex-matching.json)
| [DSL](../etc/examples/regex-matching.scheck)

```json
{
  "title": "format checks",
  "patterns": [
    {
      "name": "identifiers",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": {
                "type": "matches",
                "path": "$.cve",
                "pattern": "^CVE-\\d{4}-\\d{4,}$"
              },
              "message": "CVE ID must match standard format"
            }
          ]
        }
      ]
    }
  ]
}
```

```
$ scheck validate etc/examples/regex-matching-pass.json --rules etc/examples/regex-matching.json
OK: all checks passed

$ scheck validate etc/examples/regex-matching-fail.json --rules etc/examples/regex-matching.json
[error] identifiers at $: CVE ID must match standard format

1 error(s), 0 warning(s), 0 info(s)
```

---

## Exact value matching

Assert a field has a specific value.

```json
{
  "title": "status check",
  "patterns": [
    {
      "name": "state",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "equals", "path": "$.status", "value": "active" },
              "message": "status must be active"
            }
          ]
        }
      ]
    }
  ]
}
```

**Pass:** `{"status": "active"}`

**Fail:** `{"status": "draft"}` -- `[error] status must be active`

---

## Array cardinality

Require a minimum (or exact) number of elements.

```json
{
  "title": "array checks",
  "patterns": [
    {
      "name": "tags",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "count", "path": "$.tags[*]", "cmp": ">=", "expected": 1 },
              "message": "need at least one tag"
            },
            {
              "kind": "assert",
              "test": { "type": "count", "path": "$.authors[*]", "cmp": ">=", "expected": 1 },
              "message": "need at least one author",
              "severity": "warning"
            }
          ]
        }
      ]
    }
  ]
}
```

**Pass:** `{"tags": ["security"], "authors": ["Alice"]}`

**Fail:** `{"tags": []}` -- `[error] need at least one tag`

Supported comparison operators: `==`, `!=`, `<`, `<=`, `>`, `>=`.

---

## Logical combinators

Combine predicates with `and`, `or`, and `not`.

```json
{
  "title": "contact info",
  "patterns": [
    {
      "name": "contact",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": {
                "type": "or",
                "left": { "type": "exists", "path": "$.phone" },
                "right": { "type": "exists", "path": "$.email" }
              },
              "message": "need phone or email"
            },
            {
              "kind": "assert",
              "test": {
                "type": "and",
                "left": { "type": "exists", "path": "$.name" },
                "right": { "type": "exists", "path": "$.age" }
              },
              "message": "need both name and age"
            },
            {
              "kind": "assert",
              "test": {
                "type": "not",
                "inner": { "type": "exists", "path": "$.deprecated" }
              },
              "message": "document must not be deprecated"
            }
          ]
        }
      ]
    }
  ]
}
```

**Pass:** `{"name": "Alice", "age": 30, "email": "a@b.com"}`

**Fail:** `{"name": "Alice", "age": 30}` -- `[error] need phone or email`

---

## Recursive descent

Use `$..field` to find fields at any depth.

```json
{
  "title": "deep search",
  "patterns": [
    {
      "name": "nested",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$..email" },
              "message": "email must exist somewhere in document"
            }
          ]
        }
      ]
    }
  ]
}
```

**Pass:** `{"user": {"profile": {"email": "a@b.com"}}}`

**Fail:** `{"user": {"profile": {"name": "Alice"}}}` -- `[error] email must exist somewhere in document`

---

## Iterating over array elements

Use a context path to apply checks to each array element.

**Rules:** [`array-context.json`](../etc/examples/array-context.json)
| [DSL](../etc/examples/array-context.scheck)

```json
{
  "title": "item checks",
  "patterns": [
    {
      "name": "items",
      "rules": [
        {
          "context": "$.items[*]",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.name" },
              "message": "every item must have a name"
            },
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.price" },
              "message": "every item must have a price"
            }
          ]
        }
      ]
    }
  ]
}
```

```
$ scheck validate etc/examples/array-context-pass.json --rules etc/examples/array-context.json
OK: all checks passed

$ scheck validate etc/examples/array-context-fail.json --rules etc/examples/array-context.json
[error] items at $.items[*]: every item must have a price
[error] items at $.items[*]: every item must have a name

2 error(s), 0 warning(s), 0 info(s)
```

---

## Severity levels

Control how findings are classified: `fatal`, `error` (default), `warning`, `info`.

**Rules:** [`severity-levels.json`](../etc/examples/severity-levels.json)
| [DSL](../etc/examples/severity-levels.scheck)

```json
{
  "title": "severity demo",
  "patterns": [
    {
      "name": "checks",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.id" },
              "message": "id is required",
              "severity": "fatal"
            },
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.name" },
              "message": "name is required"
            },
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.description" },
              "message": "description is recommended",
              "severity": "warning"
            },
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.metadata" },
              "message": "metadata is optional",
              "severity": "info"
            }
          ]
        }
      ]
    }
  ]
}
```

`fatal` and `error` cause validation to fail. `warning` and `info` are
reported but do not fail validation.

```
$ scheck validate etc/examples/severity-levels-pass.json --rules etc/examples/severity-levels.json
OK: all checks passed

$ scheck validate etc/examples/severity-levels-fail.json --rules etc/examples/severity-levels.json
[fatal] checks at $: id is required
[warning] checks at $: description is recommended
[info] checks at $: metadata is optional

1 fatal(s), 0 error(s), 1 warning(s), 1 info(s)
```

---

## Assert vs report

`assert` fires on failure (test must be true). `report` fires on
success (surfaces a positive finding when test is true).

```json
{
  "title": "mixed checks",
  "patterns": [
    {
      "name": "audit",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.id" },
              "message": "id required"
            },
            {
              "kind": "report",
              "test": { "type": "exists", "path": "$.metadata" },
              "message": "document has metadata",
              "severity": "info"
            },
            {
              "kind": "report",
              "test": { "type": "exists", "path": "$.deprecated" },
              "message": "document is marked deprecated",
              "severity": "warning"
            }
          ]
        }
      ]
    }
  ]
}
```

Given `{"id": "1", "metadata": {}}`, validation passes and reports:
`[info] document has metadata`.

---

## Phases

Group patterns into named phases and run subsets selectively.

**Rules:** [`phases.json`](../etc/examples/phases.json)
| [DSL](../etc/examples/phases.scheck)

```json
{
  "title": "phased checks",
  "default_phase": "quick",
  "phases": [
    { "name": "quick", "active_patterns": ["required"] },
    { "name": "full", "active_patterns": ["required", "format"] }
  ],
  "patterns": [
    {
      "name": "required",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.id" },
              "message": "id required"
            }
          ]
        }
      ]
    },
    {
      "name": "format",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "matches", "path": "$.id", "pattern": "^[A-Z]" },
              "message": "id must start uppercase"
            }
          ]
        }
      ]
    }
  ]
}
```

```
$ scheck validate etc/examples/phases-pass.json --rules etc/examples/phases.json
OK: all checks passed

$ scheck validate etc/examples/phases-fail.json --rules etc/examples/phases.json
OK: all checks passed

$ scheck validate etc/examples/phases-fail.json --rules etc/examples/phases.json --phase full
[error] format at $: id must start uppercase

1 error(s), 0 warning(s), 0 info(s)

$ scheck validate etc/examples/phases-fail.json --rules etc/examples/phases.json --phase all
[error] format at $: id must start uppercase

1 error(s), 0 warning(s), 0 info(s)
```

---

## Diagnostics

Attach reusable explanations to checks.

**Rules:** [`diagnostics.json`](../etc/examples/diagnostics.json)
| [DSL](../etc/examples/diagnostics.scheck)

```json
{
  "title": "with diagnostics",
  "diagnostics": [
    { "id": "spec-4.2", "message": "See CSAF 2.0 spec, section 4.2" }
  ],
  "patterns": [
    {
      "name": "spec-compliance",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.document" },
              "message": "document root required",
              "diagnostics": ["spec-4.2"]
            }
          ]
        }
      ]
    }
  ]
}
```

```
$ scheck validate etc/examples/diagnostics-fail.json --rules etc/examples/diagnostics.json
[error] spec-compliance at $: document root required
       See CSAF 2.0 spec, section 4.2

1 error(s), 0 warning(s), 0 info(s)
```

---

## Flags

Categorize checks with flags for filtering and reporting.

```json
{
  "title": "flagged checks",
  "patterns": [
    {
      "name": "security",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "not_exists", "path": "$.password" },
              "message": "must not contain password",
              "flag": "security"
            },
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.auth_token" },
              "message": "auth token required",
              "flag": "security"
            }
          ]
        }
      ]
    }
  ]
}
```

Flags appear in JSON output:

```
$ scheck validate doc.json --rules flagged.json --format json
```

---

## YAML documents

scheck validates YAML documents identically to JSON. Format is auto-detected.

**Rules:** [`yaml-input.json`](../etc/examples/yaml-input.json)
| [DSL](../etc/examples/yaml-input.scheck)

```
$ scheck validate etc/examples/yaml-input-pass.yaml --rules etc/examples/yaml-input.json
OK: all checks passed

$ scheck validate etc/examples/yaml-input-fail.yaml --rules etc/examples/yaml-input.json
[error] required at $: version is required

1 error(s), 0 warning(s), 0 info(s)
```

---

## Validating rule syntax

Use `scheck check` to validate a rule file without running it against a document:

```
$ scheck check etc/examples/csaf-advisory.json
OK: schema "CSAF Advisory Checks" — 3 pattern(s), 2 phase(s) [json]
```

---

## JSON output

Get structured SVRL-inspired JSON output for programmatic consumption:

```
$ scheck validate etc/examples/required-fields-fail.json \
    --rules etc/examples/required-fields.json \
    --format json
```

---

## Rust builder API

Build rules programmatically with type safety.

```rust
use scheck::builder::*;
use scheck::{Comparison, Severity, validate_json};

let schema = schema("API validation")
    .pattern("request", |p| p
        .title("Request validation")
        .rule("$", |r| r
            .assert(exists("$.method"), "method is required")
            .assert(
                matches("$.method", "^(GET|POST|PUT|DELETE)$"),
                "method must be a valid HTTP verb",
            )
            .assert(exists("$.url"), "url is required")
            .assert_with(
                count("$.headers[*]", Comparison::Ge, 1),
                "should have at least one header",
                Severity::Warning,
            )
            .report(exists("$.body"), "request has a body")
        )
    )
    .build();

let doc = r#"{"method": "GET", "url": "/api/users"}"#;
let report = validate_json(&schema, doc)?;
assert!(report.is_ok());

// Export as JSON for other tools
let json = serde_json::to_string_pretty(&schema)?;
```

---

## Real-world: CSAF advisory validation

A complete example validating a CSAF security advisory.

**Rules:** [`csaf-advisory.json`](../etc/examples/csaf-advisory.json)
| [DSL](../etc/examples/csaf-advisory.scheck)

```
$ scheck validate etc/examples/csaf-advisory-pass.json \
    --rules etc/examples/csaf-advisory.json --phase full
OK: all checks passed

$ scheck validate etc/examples/csaf-advisory-fail.json \
    --rules etc/examples/csaf-advisory.json --phase full
[error] required-fields at $: tracking ID is required
[error] cve-format at $..vulnerabilities[*]: CVE ID must match standard format

2 error(s), 0 warning(s), 0 info(s)
```

With JSON output:

```
$ scheck validate etc/examples/csaf-advisory-fail.json \
    --rules etc/examples/csaf-advisory.json --phase full --format json
```

---

## Named test types

Built-in validators for common formats. Use `"type": "named"` instead of
writing regex patterns by hand.

```json
{
  "title": "named type checks",
  "patterns": [
    {
      "name": "formats",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "named", "name": "email", "path": "$.contact" },
              "message": "contact must be a valid email"
            },
            {
              "kind": "assert",
              "test": { "type": "named", "name": "url", "path": "$.homepage" },
              "message": "homepage must be a valid URL"
            },
            {
              "kind": "assert",
              "test": { "type": "named", "name": "semver", "path": "$.version" },
              "message": "version must be semver"
            },
            {
              "kind": "assert",
              "test": { "type": "named", "name": "cve_id", "path": "$.cve" },
              "message": "must be a valid CVE ID"
            },
            {
              "kind": "assert",
              "test": { "type": "named", "name": "uuid", "path": "$.id" },
              "message": "id must be a UUID"
            },
            {
              "kind": "assert",
              "test": { "type": "named", "name": "iso_date", "path": "$.date" },
              "message": "date must be YYYY-MM-DD"
            }
          ]
        }
      ]
    }
  ]
}
```

Supported types: `email`, `url`, `cve_id` (or `cve-id`), `purl`, `semver`,
`uuid`, `iso_date` (or `iso-date`), `iso_datetime` (or `iso-datetime`).

In the Rust builder API:

```rust
use scheck::builder::*;

let schema = schema("types")
    .pattern("p", |p| p
        .rule("$", |r| r
            .assert(is_email("$.contact"), "bad email")
            .assert(is_url("$.homepage"), "bad url")
            .assert(is_semver("$.version"), "bad version")
            .assert(is_cve_id("$.cve"), "bad CVE")
            .assert(is_purl("$.package"), "bad PURL")
            .assert(is_uuid("$.id"), "bad UUID")
            .assert(is_iso_date("$.date"), "bad date")
            .assert(is_iso_datetime("$.timestamp"), "bad datetime")
        )
    )
    .build();
```

---

## Partial validation

Validate only a subtree of a document with `--context`. Rules run against
each node matched by the context path instead of the full document root.

```
$ scheck validate users.json --rules user-rules.json --context '$.users[*]'
```

Given `users.json`:

```json
{
  "users": [
    {"name": "Alice", "email": "alice@example.com"},
    {"name": "Bob"},
    {"age": 30}
  ]
}
```

And rules that check for `$.name` and `$.email` at the root, partial
validation runs those checks against each user object individually.

In the Rust API:

```rust
let report = scheck::validate_context(&schema, &doc, "$.users[*]", "");
```

---

## Validated proof wrapper

The `Validated` wrapper guarantees at the type level that a document
passed all validation rules. It cannot be constructed directly -- only
through `try_validate()`.

```rust
use scheck::try_validate;

let doc = scheck::from_json(r#"{"name": "Alice"}"#)?;
match try_validate(&schema, doc) {
    Ok(validated) => {
        // proven valid -- safe to process
        let doc = validated.document();
        let report = validated.report();
    }
    Err(failed) => {
        // ValidationFailed implements Error + Display
        eprintln!("{}", failed.report().to_text());
    }
}
```

`try_validate_phase()` accepts a phase name for phased validation.
