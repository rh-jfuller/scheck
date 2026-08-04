# scheck examples

Practical examples showing how to use scheck for semantic validation.
Each example includes rule files, input documents, and CLI invocations.
All files live under [`etc/examples/`](../etc/examples/).

## Required fields

Ensure a document contains mandatory fields.

**Rules:** [`required-fields.scheck`](../etc/examples/required-fields.scheck)
| [`required-fields.json`](../etc/examples/required-fields.json) (JSON equivalent)

```
schema "required fields" {
  pattern "basics" {
    rule context="$" {
      assert exists("$.name")
        message="name is required";
      assert exists("$.email")
        message="email is required";
    }
  }
}
```

**Pass:** [`required-fields-pass.json`](../etc/examples/required-fields-pass.json)

```
$ scheck validate etc/examples/required-fields-pass.json --rules etc/examples/required-fields.scheck
OK: all checks passed
```

**Fail:** [`required-fields-fail.json`](../etc/examples/required-fields-fail.json)

```
$ scheck validate etc/examples/required-fields-fail.json --rules etc/examples/required-fields.scheck
[error] basics at $: email is required

1 error(s), 0 warning(s), 0 info(s)
```

JSON rules work identically:

```
$ scheck validate etc/examples/required-fields-fail.json --rules etc/examples/required-fields.json
```

---

## Forbidden fields

Reject documents containing sensitive fields.

**Rules:** [`forbidden-fields.scheck`](../etc/examples/forbidden-fields.scheck)

```
schema "no secrets" {
  pattern "security" {
    rule context="$" {
      assert not_exists("$.password")
        message="must not contain password"
        flag="security";
      assert not_exists("$.secret")
        message="must not contain secret"
        flag="security";
    }
  }
}
```

```
$ scheck validate etc/examples/forbidden-fields-pass.json --rules etc/examples/forbidden-fields.scheck
OK: all checks passed

$ scheck validate etc/examples/forbidden-fields-fail.json --rules etc/examples/forbidden-fields.scheck
[error] security at $: must not contain password

1 error(s), 0 warning(s), 0 info(s)
```

---

## Regex matching

Validate string values match an expected format.

**Rules:** [`regex-matching.scheck`](../etc/examples/regex-matching.scheck)

```
schema "format checks" {
  pattern "identifiers" {
    rule context="$" {
      assert matches("$.cve", "^CVE-\\d{4}-\\d{4,}$")
        message="CVE ID must match standard format";
    }
  }
}
```

```
$ scheck validate etc/examples/regex-matching-pass.json --rules etc/examples/regex-matching.scheck
OK: all checks passed

$ scheck validate etc/examples/regex-matching-fail.json --rules etc/examples/regex-matching.scheck
[error] identifiers at $: CVE ID must match standard format

1 error(s), 0 warning(s), 0 info(s)
```

---

## Exact value matching

Assert a field has a specific value.

```
schema "status check" {
  pattern "state" {
    rule context="$" {
      assert equals("$.status", "active")
        message="status must be active";
    }
  }
}
```

**Pass:** `{"status": "active"}`

**Fail:** `{"status": "draft"}` -- `[error] status must be active`

---

## Array cardinality

Require a minimum (or exact) number of elements.

```
schema "array checks" {
  pattern "tags" {
    rule context="$" {
      assert count("$.tags[*]", >=, 1)
        message="need at least one tag";
      assert count("$.authors[*]", >=, 1)
        message="need at least one author"
        severity=warning;
    }
  }
}
```

**Pass:** `{"tags": ["security"], "authors": ["Alice"]}`

**Fail:** `{"tags": []}` -- `[error] need at least one tag`

All comparison operators are supported: `==`, `!=`, `<`, `<=`, `>`, `>=`.

---

## Logical combinators

Combine predicates with `and`, `or`, and `not`.

```
schema "contact info" {
  pattern "contact" {
    rule context="$" {
      # Require at least one contact method
      assert exists("$.phone") or exists("$.email")
        message="need phone or email";

      # Require both name and age
      assert exists("$.name") and exists("$.age")
        message="need both name and age";

      # Reject deprecated documents
      assert not(exists("$.deprecated"))
        message="document must not be deprecated";
    }
  }
}
```

**Pass:** `{"name": "Alice", "age": 30, "email": "a@b.com"}`

**Fail:** `{"name": "Alice", "age": 30}` -- `[error] need phone or email`

---

## Recursive descent

Use `$..field` to find fields at any depth.

```
schema "deep search" {
  pattern "nested" {
    rule context="$" {
      assert exists("$..email")
        message="email must exist somewhere in document";
    }
  }
}
```

**Pass:** `{"user": {"profile": {"email": "a@b.com"}}}`

**Fail:** `{"user": {"profile": {"name": "Alice"}}}` -- `[error] email must exist somewhere in document`

---

## Iterating over array elements

Use a context path to apply checks to each array element.

**Rules:** [`array-context.scheck`](../etc/examples/array-context.scheck)

```
schema "item checks" {
  pattern "items" {
    rule context="$.items[*]" {
      assert exists("$.name")
        message="every item must have a name";
      assert exists("$.price")
        message="every item must have a price";
    }
  }
}
```

```
$ scheck validate etc/examples/array-context-pass.json --rules etc/examples/array-context.scheck
OK: all checks passed

$ scheck validate etc/examples/array-context-fail.json --rules etc/examples/array-context.scheck
[error] items at $.items[*]: every item must have a price
[error] items at $.items[*]: every item must have a name

2 error(s), 0 warning(s), 0 info(s)
```

---

## Severity levels

Control how findings are classified: `fatal`, `error` (default), `warning`, `info`.

**Rules:** [`severity-levels.scheck`](../etc/examples/severity-levels.scheck)

```
schema "severity demo" {
  pattern "checks" {
    rule context="$" {
      assert exists("$.id")
        message="id is required"
        severity=fatal;

      assert exists("$.name")
        message="name is required";

      assert exists("$.description")
        message="description is recommended"
        severity=warning;

      assert exists("$.metadata")
        message="metadata is optional"
        severity=info;
    }
  }
}
```

`fatal` and `error` cause validation to fail. `warning` and `info` are
reported but do not fail validation.

```
$ scheck validate etc/examples/severity-levels-pass.json --rules etc/examples/severity-levels.scheck
OK: all checks passed

$ scheck validate etc/examples/severity-levels-fail.json --rules etc/examples/severity-levels.scheck
[fatal] checks at $: id is required
[warning] checks at $: description is recommended
[info] checks at $: metadata is optional

1 fatal(s), 0 error(s), 1 warning(s), 1 info(s)
```

---

## Assert vs report

`assert` fires on failure (test must be true). `report` fires on
success (surfaces a positive finding when test is true).

```
schema "mixed checks" {
  pattern "audit" {
    rule context="$" {
      assert exists("$.id")
        message="id required";

      report exists("$.metadata")
        message="document has metadata"
        severity=info;

      report exists("$.deprecated")
        message="document is marked deprecated"
        severity=warning;
    }
  }
}
```

Given `{"id": "1", "metadata": {}}`, validation passes and reports:
`[info] document has metadata`.

---

## Phases

Group patterns into named phases and run subsets selectively.

**Rules:** [`phases.scheck`](../etc/examples/phases.scheck)

```
schema "phased checks" {
  default_phase "quick";

  phase "quick" {
    active "required";
  }

  phase "full" {
    active "required";
    active "format";
  }

  pattern "required" {
    rule context="$" {
      assert exists("$.id")
        message="id required";
    }
  }

  pattern "format" {
    rule context="$" {
      assert matches("$.id", "^[A-Z]")
        message="id must start uppercase";
    }
  }
}
```

```
$ scheck validate etc/examples/phases-pass.json --rules etc/examples/phases.scheck
OK: all checks passed

$ scheck validate etc/examples/phases-fail.json --rules etc/examples/phases.scheck
OK: all checks passed

$ scheck validate etc/examples/phases-fail.json --rules etc/examples/phases.scheck --phase full
[error] format at $: id must start uppercase

1 error(s), 0 warning(s), 0 info(s)

$ scheck validate etc/examples/phases-fail.json --rules etc/examples/phases.scheck --phase all
[error] format at $: id must start uppercase

1 error(s), 0 warning(s), 0 info(s)
```

---

## Diagnostics

Attach reusable explanations to checks.

**Rules:** [`diagnostics.scheck`](../etc/examples/diagnostics.scheck)

```
schema "with diagnostics" {
  diagnostics {
    diagnostic "spec-4.2" "See CSAF 2.0 spec, section 4.2";
  }

  pattern "spec-compliance" {
    rule context="$" {
      assert exists("$.document")
        message="document root required"
        diagnostic="spec-4.2";
    }
  }
}
```

```
$ scheck validate etc/examples/diagnostics-fail.json --rules etc/examples/diagnostics.scheck
[error] spec-compliance at $: document root required
       See CSAF 2.0 spec, section 4.2

1 error(s), 0 warning(s), 0 info(s)
```

---

## Flags

Categorize checks with flags for filtering and reporting.

```
schema "flagged checks" {
  pattern "security" {
    rule context="$" {
      assert not_exists("$.password")
        message="must not contain password"
        flag="security";
      assert exists("$.auth_token")
        message="auth token required"
        flag="security";
    }
  }
}
```

Flags appear in JSON output:

```
$ scheck validate doc.json --rules flagged.scheck --format json
```

---

## YAML documents

scheck validates YAML documents identically to JSON. Format is auto-detected.

**Rules:** [`yaml-input.scheck`](../etc/examples/yaml-input.scheck)

```
$ scheck validate etc/examples/yaml-input-pass.yaml --rules etc/examples/yaml-input.scheck
OK: all checks passed

$ scheck validate etc/examples/yaml-input-fail.yaml --rules etc/examples/yaml-input.scheck
[error] required at $: version is required

1 error(s), 0 warning(s), 0 info(s)
```

---

## Validating rule syntax

Use `scheck check` to validate a rule file without running it against a document:

```
$ scheck check etc/examples/csaf-advisory.scheck
OK: schema "CSAF Advisory Checks" — 3 pattern(s), 2 phase(s) [dsl]
```

---

## JSON output

Get structured SVRL-inspired JSON output for programmatic consumption:

```
$ scheck validate etc/examples/required-fields-fail.json \
    --rules etc/examples/required-fields.scheck \
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

**Rules:** [`csaf-advisory.scheck`](../etc/examples/csaf-advisory.scheck)

```
$ scheck validate etc/examples/csaf-advisory-pass.json \
    --rules etc/examples/csaf-advisory.scheck --phase full
OK: all checks passed

$ scheck validate etc/examples/csaf-advisory-fail.json \
    --rules etc/examples/csaf-advisory.scheck --phase full
[error] required-fields at $: tracking ID is required
[error] cve-format at $..vulnerabilities[*]: CVE ID must match standard format

2 error(s), 0 warning(s), 0 info(s)
```

With JSON output:

```
$ scheck validate etc/examples/csaf-advisory-fail.json \
    --rules etc/examples/csaf-advisory.scheck --phase full --format json
```
