# scheck

[![CI](https://github.com/rh-jfuller/scheck/actions/workflows/ci.yml/badge.svg)](https://github.com/rh-jfuller/scheck/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Semantic validation of structured data using assertion-based rules.

[Try it in your browser](https://rh-jfuller.github.io/scheck/) -- no install needed.

![scheck in the browser](docs/ss-wasm.png)

See the [examples](docs/examples.md) for a full walkthrough of every feature.

## The problem

Schema validation only brings you so far.

JSON Schema, XML Schema, YAML validators -- they tell you whether a document is
*structurally* correct. The right types in the right places. But they can't tell you
whether the data makes *sense*.

Real-world data has constraints that cut across structure:

- A vulnerability advisory **must** contain a CVE ID, and that ID **must** match `CVE-YYYY-NNNNN+`.
- If a remediation references a vulnerability, that vulnerability **must** exist in the document.
- Every product in a branch **must** have at least one version range.
- A `status` field set to `"final"` **must not** coexist with an empty `release_date`.
- An SBOM **must** contain at least one package with a valid PURL.

These are **semantic rules** -- co-occurrence constraints, cross-reference checks,
conditional requirements, cardinality bounds. No schema language can express them.
You end up writing bespoke validation code, scattered across your codebase, with
inconsistent error messages and no way to share rules across teams.

## The solution

scheck lets you define semantic assertions as rules -- in JSON, in Rust, or in a
lightweight DSL -- then run them against any JSON or YAML document. Rules are data.
Any language can generate them, any tool can read them.

Path expressions use [JSONPath (RFC 9535)](https://www.rfc-editor.org/rfc/rfc9535),
the standardized query language for JSON. No custom path syntax to learn.

scheck is inspired by [ISO Schematron](https://en.wikipedia.org/wiki/Schematron),
the rule-based validation language for XML that Rick Jelliffe described as
*"a feather duster to reach the parts other schema languages cannot reach."*

## Rules as JSON

The primary rule format is JSON. Every scheck schema serializes cleanly:

```json
{
  "title": "CSAF Advisory Checks",
  "patterns": [
    {
      "name": "required-fields",
      "title": "Core fields must be present",
      "rules": [
        {
          "context": "$",
          "checks": [
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.document" },
              "message": "Document root must contain a 'document' object"
            },
            {
              "kind": "assert",
              "test": { "type": "exists", "path": "$.vulnerabilities" },
              "message": "Advisory must contain at least one vulnerability",
              "severity": "warning"
            }
          ]
        }
      ]
    },
    {
      "name": "cve-format",
      "title": "CVE identifiers must be well-formed",
      "rules": [
        {
          "context": "$..vulnerabilities[*]",
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

Load and validate:

```
$ scheck validate advisory.json --rules csaf-checks.json
```

Or from any language -- generate the JSON, call scheck.

## Rules in Rust

For Rust projects, the builder API gives you type-checked rule construction
with no parsing at all:

```rust
use scheck::builder::*;
use scheck::{Severity, validate_json};

let schema = schema("CSAF Checks")
    .pattern("required-fields", |p| p
        .title("Core fields must be present")
        .rule("$", |r| r
            .assert(exists("$.document"), "must have document")
            .assert_with(
                exists("$.vulnerabilities"),
                "must have vulnerabilities",
                Severity::Warning,
            )
        )
    )
    .pattern("cve-format", |p| p
        .rule("$..vulnerabilities[*]", |r| r
            .assert(
                matches("$.cve", r"^CVE-\d{4}-\d{4,}$"),
                "CVE ID must match standard format",
            )
        )
    )
    .build();

// Validate directly
let report = validate_json(&schema, &json_string)?;
assert!(report.is_ok());

// Or serialize to JSON for sharing
let rules_json = serde_json::to_string_pretty(&schema)?;
```

The schema round-trips through JSON. Build in Rust, export as JSON for other
tools. Import JSON, validate in Rust.

## Rules as DSL

For hand-written rule files, scheck also supports a `.scheck` DSL:

```
schema "CSAF Advisory Checks" {
  pattern "required-fields" {
    title "Core fields must be present";

    rule context="$" {
      assert exists("$.document")
        message="must have document";

      assert exists("$.vulnerabilities")
        message="must have vulnerabilities"
        severity=warning;
    }
  }
}
```

## Key concepts

### Assert vs Report

Borrowed directly from Schematron. Two kinds of checks:

- **`assert`** -- the test *must* be true. If it fails, emit the message as a failure.
- **`report`** -- if the test *is* true, emit the message as a positive finding.

Assert catches problems. Report surfaces facts.

### Phases

Group patterns into named sets and run only what matters:

```json
{
  "title": "checks",
  "default_phase": "quick",
  "phases": [
    { "name": "quick", "active_patterns": ["required-fields"] },
    { "name": "full", "active_patterns": ["required-fields", "cve-format"] }
  ],
  "patterns": [ ]
}
```

```
$ scheck validate doc.json --rules checks.json --phase full
```

### Diagnostics

Reusable explanations referenced by ID:

```json
{
  "diagnostics": [
    { "id": "spec-4.2", "message": "See CSAF 2.0 spec, section 4.2" }
  ]
}
```

### Severity and flags

Every check carries a severity (`fatal`, `error`, `warning`, `info`) and an
optional `flag` for categorization.

## Path expressions (JSONPath)

scheck uses [JSONPath (RFC 9535)](https://www.rfc-editor.org/rfc/rfc9535):

| Syntax | Meaning |
|--------|---------|
| `$` | Root of the document |
| `$.child` | Direct child named "child" |
| `$..name` | Recursive descent -- any descendant named "name" |
| `$.items[*]` | All elements of an array |
| `$.items[0]` | First element of an array |
| `$..book[?@.price < 10]` | Filter expression |

## Predicates

| Predicate | Meaning |
|-----------|---------|
| `exists` | Node at path exists |
| `not_exists` | Node at path must not exist |
| `equals` | Scalar at path equals value |
| `matches` | Scalar at path matches regex |
| `count` | Count of nodes satisfies comparison |
| `and` | Both predicates must hold |
| `or` | At least one must hold |
| `not` | Predicate must not hold |

## Output

- **text** (default) -- human-readable, one line per finding
- **json** -- structured SVRL-inspired report with `fired-rules`, `failed-assert`, `successful-report`

## Install

### Pre-built binaries

Download from [GitHub Releases](https://github.com/rh-jfuller/scheck/releases):

```
# Linux x86_64 (static musl)
curl -LO https://github.com/rh-jfuller/scheck/releases/latest/download/scheck-<version>-x86_64-unknown-linux-musl.tar.gz
tar xzf scheck-*-x86_64-unknown-linux-musl.tar.gz
sudo install scheck /usr/local/bin/

# macOS (Apple Silicon)
curl -LO https://github.com/rh-jfuller/scheck/releases/latest/download/scheck-<version>-aarch64-apple-darwin.tar.gz
tar xzf scheck-*-aarch64-apple-darwin.tar.gz
sudo install scheck /usr/local/bin/
```

### RPM

```
sudo rpm -i https://github.com/rh-jfuller/scheck/releases/latest/download/scheck-<version>-1.x86_64.rpm
```

### From source

```
cargo install scheck
```

## CLI

```
scheck validate <document> --rules <rules> [--phase <name>] [--format text|json]
scheck check <rules>   # validate rule file syntax
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCHECK_MAX_FILE_SIZE` | `10485760` (10 MiB) | Maximum input file size in bytes for both rule files and documents |

## As a library

Three ways to use scheck from Rust:

```rust
// 1. Builder API (recommended for Rust projects)
use scheck::builder::*;
let schema = schema("example")
    .pattern("p", |p| p
        .rule("$", |r| r.assert(exists("$.name"), "name required"))
    )
    .build();
let report = scheck::validate_json(&schema, r#"{"name": "Alice"}"#)?;

// 2. JSON rules
let report = scheck::check_json(rules_json, doc_json)?;

// 3. DSL rules
let report = scheck::check(rules_dsl, doc_json)?;
```

## Rulesets

scheck ships with ready-to-use rulesets under [`rulesets/`](rulesets/),
organized by domain:

| Domain | Directory | Rulesets |
|--------|-----------|----------|
| [Security](rulesets/security/) | `rulesets/security/` | CSAF 2.0, CycloneDX, SPDX, VEX, OSV |
| [API](rulesets/api/) | `rulesets/api/` | REST response contracts, JSON:API |
| [Config](rulesets/config/) | `rulesets/config/` | Kubernetes pod policy, GitHub Actions |
| [Data Quality](rulesets/data-quality/) | `rulesets/data-quality/` | Contact records, dataset metadata |

```
$ scheck validate advisory.json --rules rulesets/security/csaf-2.0-mandatory.json --phase full
$ scheck validate response.json --rules rulesets/api/jsonapi.json
$ scheck validate pod.yaml --rules rulesets/config/kubernetes-pod.json
$ scheck validate contacts.json --rules rulesets/data-quality/contact-records.json
```

See [`rulesets/README.md`](rulesets/README.md) for the full catalog. Each
subdirectory has its own README with details, phases, and limitations.

## Why rules-as-data?

- **Portable** -- JSON rules work in any language. No Rust required.
- **Auditable** -- every rule has a human message. Non-developers can review them.
- **Composable** -- combine rule files, activate phases per environment.
- **Declarative** -- what to check, not how. The engine handles traversal.
- **Evolvable** -- add a rule, don't touch the validator code.
- **Round-trip** -- build in Rust, export as JSON, import elsewhere, and back.

This is the same insight behind Schematron, which has been validating XML in
healthcare (HL7), government (UBL/PEPPOL), and publishing (JATS) for 25 years.
scheck brings it to the formats the rest of us use.

## License

MIT
