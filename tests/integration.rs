#![expect(clippy::unwrap_used, clippy::panic)]

use scheck::{ResultKind, check, check_ok, check_phase, parse_schema, validate};

// -- Basic assert / report -------------------------------------------

#[test]
fn assert_passes_when_field_exists() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.name")
                        message="name required";
                }
            }
        }
    "#;
    let doc = r#"{"name": "Alice"}"#;
    assert!(check_ok(rules, doc).unwrap());
}

#[test]
fn assert_fails_when_field_missing() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.email")
                        message="email required";
                }
            }
        }
    "#;
    let doc = r#"{"name": "Alice"}"#;
    assert!(!check_ok(rules, doc).unwrap());
}

#[test]
fn report_fires_on_presence() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    report exists("$.deprecated")
                        message="deprecated field found"
                        severity=warning;
                }
            }
        }
    "#;
    let doc = r#"{"deprecated": true}"#;
    let report = check(rules, doc).unwrap();
    let findings = report.findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, ResultKind::SuccessfulReport);
    assert_eq!(findings[0].message, "deprecated field found");
}

#[test]
fn report_silent_when_field_absent() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    report exists("$.deprecated")
                        message="deprecated field found";
                }
            }
        }
    "#;
    let doc = r#"{"name": "ok"}"#;
    let report = check(rules, doc).unwrap();
    assert!(report.findings().is_empty());
}

// -- Predicates ------------------------------------------------------

#[test]
fn equals_string_value() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert equals("$.status", "active")
                        message="must be active";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"status": "active"}"#).unwrap());
    assert!(!check_ok(rules, r#"{"status": "draft"}"#).unwrap());
}

#[test]
fn matches_regex_pattern() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert matches("$.id", "^CVE-\\d{4}-\\d{4,}$")
                        message="bad CVE format";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"id": "CVE-2024-12345"}"#).unwrap());
    assert!(!check_ok(rules, r#"{"id": "not-a-cve"}"#).unwrap());
}

#[test]
fn not_exists_predicate() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert not_exists("$.password")
                        message="must not contain password";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"name": "ok"}"#).unwrap());
    assert!(!check_ok(rules, r#"{"password": "secret"}"#).unwrap());
}

#[test]
fn count_array_items() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert count("$.tags[*]", >=, 1)
                        message="need at least one tag";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"tags": ["a", "b"]}"#).unwrap());
}

#[test]
fn logical_and() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.name") and exists("$.email")
                        message="need both name and email";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"name": "A", "email": "a@b"}"#).unwrap());
    assert!(!check_ok(rules, r#"{"name": "A"}"#).unwrap());
}

#[test]
fn logical_or() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.phone") or exists("$.email")
                        message="need phone or email";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"phone": "555"}"#).unwrap());
    assert!(check_ok(rules, r#"{"email": "a@b"}"#).unwrap());
    assert!(!check_ok(rules, r#"{"name": "A"}"#).unwrap());
}

#[test]
fn logical_not() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert not(exists("$.secret"))
                        message="must not have secret";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"name": "ok"}"#).unwrap());
    assert!(!check_ok(rules, r#"{"secret": "x"}"#).unwrap());
}

// -- Phases ----------------------------------------------------------

#[test]
fn phase_selects_patterns() {
    let rules = r#"
        schema "t" {
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
    "#;
    let doc = r#"{"id": "abc"}"#;

    let quick = check_phase(rules, doc, "quick").unwrap();
    assert!(quick.is_ok());

    let full = check_phase(rules, doc, "full").unwrap();
    assert!(!full.is_ok());
    assert_eq!(full.error_count(), 1);
}

#[test]
fn default_phase_used_when_none_specified() {
    let rules = r#"
        schema "t" {
            default_phase "minimal";

            phase "minimal" {
                active "basic";
            }

            pattern "basic" {
                rule context="$" {
                    assert exists("$.x")
                        message="need x";
                }
            }

            pattern "extra" {
                rule context="$" {
                    assert exists("$.y")
                        message="need y";
                }
            }
        }
    "#;
    let doc = r#"{"x": 1}"#;

    let report = check(rules, doc).unwrap();
    assert!(report.is_ok());
}

#[test]
fn all_phase_runs_everything() {
    let rules = r#"
        schema "t" {
            default_phase "minimal";

            phase "minimal" {
                active "basic";
            }

            pattern "basic" {
                rule context="$" {
                    assert exists("$.x")
                        message="need x";
                }
            }

            pattern "extra" {
                rule context="$" {
                    assert exists("$.y")
                        message="need y";
                }
            }
        }
    "#;
    let doc = r#"{"x": 1}"#;
    let report = check_phase(rules, doc, "all").unwrap();
    assert!(!report.is_ok());
}

// -- Severity --------------------------------------------------------

#[test]
fn severity_fatal() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.critical")
                        message="critical missing"
                        severity=fatal;
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    assert_eq!(report.fatal_count(), 1);
    assert!(!report.is_ok());
}

#[test]
fn severity_info_does_not_fail() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.optional")
                        message="optional missing"
                        severity=info;
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    assert!(report.is_ok());
    assert_eq!(report.info_count(), 1);
}

// -- Diagnostics -----------------------------------------------------

#[test]
fn diagnostics_included_in_report() {
    let rules = r#"
        schema "t" {
            diagnostics {
                diagnostic "d1" "See specification section 4.2";
            }

            pattern "p" {
                rule context="$" {
                    assert exists("$.required")
                        message="field missing"
                        diagnostic="d1";
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    let findings = report.findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].diagnostic, "See specification section 4.2");
}

// -- Let bindings ----------------------------------------------------

#[test]
fn let_binding_in_rule() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    let items = "$..item";
                    assert count("$..item", >=, 1)
                        message="need items";
                }
            }
        }
    "#;
    let doc = r#"{"item": "x"}"#;
    assert!(check_ok(rules, doc).unwrap());
}

// -- Flags -----------------------------------------------------------

#[test]
fn flag_on_check() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.auth")
                        message="auth missing"
                        flag="security";
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    let findings = report.findings();
    assert_eq!(findings[0].flag, "security");
}

// -- Pattern title and schema description ----------------------------

#[test]
fn schema_metadata() {
    let rules = r#"
        schema "My Checks" {
            description "Validates my data format";

            pattern "basics" {
                title "Basic field checks";
                rule context="$" {
                    assert exists("$.x")
                        message="x";
                }
            }
        }
    "#;
    let schema = parse_schema(rules).unwrap();
    assert_eq!(schema.title, "My Checks");
    assert_eq!(schema.description, "Validates my data format");
    assert_eq!(schema.patterns[0].title, "Basic field checks");
}

// -- Fired rules tracking (SVRL) -------------------------------------

#[test]
fn fired_rules_reported() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule "r1" context="$" {
                    assert exists("$.x")
                        message="need x";
                }
            }
        }
    "#;
    let doc = r#"{"x": 1}"#;
    let schema = parse_schema(rules).unwrap();
    let document = scheck::from_json(doc).unwrap();
    let report = validate(&schema, &document);
    assert_eq!(report.fired_rules.len(), 1);
    assert_eq!(report.fired_rules[0].rule_id, "r1");
}

// -- Output format ---------------------------------------------------

#[test]
fn text_output_ok() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.x")
                        message="x";
                }
            }
        }
    "#;
    let report = check(rules, r#"{"x": 1}"#).unwrap();
    assert!(report.to_text().contains("OK"));
}

#[test]
fn text_output_failure() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.x")
                        message="missing x";
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    let text = report.to_text();
    assert!(text.contains("[error]"));
    assert!(text.contains("missing x"));
}

#[test]
fn json_output_structure() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.x")
                        message="missing x";
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    let json = report.to_json();
    assert!(json.contains("\"ok\": false"));
    assert!(json.contains("\"fired-rules\""));
    assert!(json.contains("\"findings\""));
    assert!(json.contains("\"summary\""));
    assert!(json.contains("\"failed-assert\""));
}

// -- YAML input ------------------------------------------------------

#[test]
fn yaml_document_validation() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.name")
                        message="name required";
                }
            }
        }
    "#;
    let yaml = "name: Alice\nage: 30\n";
    assert!(check_ok(rules, yaml).unwrap());
}

// -- Recursive descent paths -----------------------------------------

#[test]
fn descendant_path_finds_nested() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$..email")
                        message="email somewhere";
                }
            }
        }
    "#;
    let doc = r#"{"user": {"profile": {"email": "a@b"}}}"#;
    assert!(check_ok(rules, doc).unwrap());
}

// -- Multiple patterns -----------------------------------------------

#[test]
fn multiple_patterns_all_evaluated() {
    let rules = r#"
        schema "t" {
            pattern "a" {
                rule context="$" {
                    assert exists("$.x")
                        message="need x";
                }
            }
            pattern "b" {
                rule context="$" {
                    assert exists("$.y")
                        message="need y";
                }
            }
        }
    "#;
    let report = check(rules, r#"{"x": 1}"#).unwrap();
    assert_eq!(report.error_count(), 1);
    let findings = report.findings();
    assert!(findings.iter().any(|f| f.message == "need y"));
}

// -- Comments in rule files ------------------------------------------

#[test]
fn comments_ignored() {
    let rules = r#"
        # Top comment
        schema "t" {
            # Phase comment
            pattern "p" {
                # Rule comment
                rule context="$" {
                    # Assert comment
                    assert exists("$.x")
                        message="x";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"x": 1}"#).unwrap());
}

// -- Error handling --------------------------------------------------

#[test]
fn bad_rules_return_error() {
    let result = check("not a schema", r"{}");
    assert!(result.is_err());
}

#[test]
fn bad_document_returns_error() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.x") message="x";
                }
            }
        }
    "#;
    let result = check(rules, ":\n\t- :\n\t\t{{{\n\t\t: [");
    assert!(result.is_err());
}

// -- Mixed assert and report -----------------------------------------

#[test]
fn mixed_assert_and_report() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.id")
                        message="id required";
                    report exists("$.metadata")
                        message="has metadata"
                        severity=info;
                }
            }
        }
    "#;
    let doc = r#"{"id": "1", "metadata": {}}"#;
    let report = check(rules, doc).unwrap();
    assert!(report.is_ok());

    let findings = report.findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, ResultKind::SuccessfulReport);
    assert_eq!(findings[0].message, "has metadata");
}

// -- Empty and minimal inputs ----------------------------------------

#[test]
fn empty_json_object() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.x")
                        message="x required";
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    assert!(!report.is_ok());
    assert_eq!(report.error_count(), 1);
}

#[test]
fn empty_json_array_as_root() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert count("$[*]", >=, 1)
                        message="array must not be empty";
                }
            }
        }
    "#;
    assert!(!check_ok(rules, "[]").unwrap());
    assert!(check_ok(rules, r"[1]").unwrap());
}

#[test]
fn null_values() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.name")
                        message="name required";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"name": null}"#).unwrap());
}

#[test]
fn boolean_value_equals() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert equals("$.active", "true")
                        message="must be active";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"active": true}"#).unwrap());
    assert!(!check_ok(rules, r#"{"active": false}"#).unwrap());
}

#[test]
fn numeric_value_equals() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert equals("$.count", "42")
                        message="must be 42";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"count": 42}"#).unwrap());
    assert!(!check_ok(rules, r#"{"count": 0}"#).unwrap());
}

// -- Count operator coverage -----------------------------------------

#[test]
fn count_eq() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert count("$.items[*]", ==, 2)
                        message="need exactly 2";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"items": [1, 2]}"#).unwrap());
    assert!(!check_ok(rules, r#"{"items": [1]}"#).unwrap());
    assert!(!check_ok(rules, r#"{"items": [1, 2, 3]}"#).unwrap());
}

#[test]
fn count_ne() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert count("$.items[*]", !=, 0)
                        message="must not be empty";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"items": [1]}"#).unwrap());
    assert!(!check_ok(rules, r#"{"items": []}"#).unwrap());
}

#[test]
fn count_lt() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert count("$.items[*]", <, 3)
                        message="must have fewer than 3";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"items": [1, 2]}"#).unwrap());
    assert!(!check_ok(rules, r#"{"items": [1, 2, 3]}"#).unwrap());
}

#[test]
fn count_le() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert count("$.items[*]", <=, 2)
                        message="must have at most 2";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"items": [1, 2]}"#).unwrap());
    assert!(!check_ok(rules, r#"{"items": [1, 2, 3]}"#).unwrap());
}

#[test]
fn count_gt() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert count("$.items[*]", >, 0)
                        message="must have more than 0";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"items": [1]}"#).unwrap());
    assert!(!check_ok(rules, r#"{"items": []}"#).unwrap());
}

// -- Context matching ------------------------------------------------

#[test]
fn context_no_match_skips_rule() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$.nonexistent[*]" {
                    assert exists("$.x")
                        message="x required";
                }
            }
        }
    "#;
    let report = check(rules, r#"{"y": 1}"#).unwrap();
    assert!(report.is_ok());
    assert!(report.findings().is_empty());
}

#[test]
fn multiple_context_matches() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$.users[*]" {
                    assert exists("$.email")
                        message="user needs email";
                }
            }
        }
    "#;
    let doc = r#"{"users": [{"email": "a@b"}, {"name": "no email"}]}"#;
    let report = check(rules, doc).unwrap();
    assert_eq!(report.error_count(), 1);
}

// -- Nested logical combinators --------------------------------------

#[test]
fn nested_and_or() {
    // DSL precedence: `and` binds tighter than `or` in the grammar,
    // but the parser produces `a and (b or c)` for chained expressions.
    // Use explicit grouping for clarity.
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.a") or exists("$.b") and exists("$.c")
                        message="need a, or (b and c)";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"a": 1}"#).unwrap());
    assert!(check_ok(rules, r#"{"b": 1, "c": 2}"#).unwrap());
    assert!(!check_ok(rules, r#"{"b": 1}"#).unwrap());
}

// -- Report output ---------------------------------------------------

#[test]
fn text_output_with_diagnostics() {
    let rules = r#"
        schema "t" {
            diagnostics {
                diagnostic "d1" "See specification";
            }
            pattern "p" {
                rule context="$" {
                    assert exists("$.x")
                        message="x missing"
                        diagnostic="d1";
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    let text = report.to_text();
    assert!(text.contains("x missing"));
    assert!(text.contains("See specification"));
}

#[test]
fn json_output_with_flag() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.x")
                        message="x missing"
                        flag="critical";
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    let json = report.to_json();
    assert!(json.contains("\"flag\": \"critical\""));
}

#[test]
fn json_output_escaping() {
    let rules = r#"
        schema "test \"escapes\"" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.x")
                        message="needs \"x\" field";
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    let json = report.to_json();
    assert!(json.contains("\\\""));
}

// -- Security: regex limits ------------------------------------------

#[test]
fn invalid_regex_fails_gracefully() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert matches("$.x", "[invalid")
                        message="bad regex";
                }
            }
        }
    "#;
    let report = check(rules, r#"{"x": "test"}"#).unwrap();
    assert!(!report.is_ok());
}

#[test]
fn oversized_regex_returns_false() {
    let long_pattern = format!("^{}$", "a".repeat(2000));
    let rules = format!(
        r#"schema "t" {{
            pattern "p" {{
                rule context="$" {{
                    assert matches("$.x", "{long_pattern}")
                        message="oversized regex";
                }}
            }}
        }}"#
    );
    let report = check(&rules, r#"{"x": "a"}"#).unwrap();
    assert!(!report.is_ok());
}

// -- JSON rules roundtrip --------------------------------------------

#[test]
fn json_rules_validation() {
    let rules_json = r#"{
        "title": "json test",
        "patterns": [{
            "name": "p",
            "rules": [{
                "context": "$",
                "checks": [{
                    "kind": "assert",
                    "test": {"type": "exists", "path": "$.name"},
                    "message": "name required"
                }]
            }]
        }]
    }"#;
    let report = scheck::check_json(rules_json, r#"{"name": "ok"}"#).unwrap();
    assert!(report.is_ok());

    let report = scheck::check_json(rules_json, r"{}").unwrap();
    assert!(!report.is_ok());
}

#[test]
fn json_rules_with_all_predicates() {
    let rules_json = r#"{
        "title": "predicates",
        "patterns": [{
            "name": "p",
            "rules": [{
                "context": "$",
                "checks": [
                    {
                        "kind": "assert",
                        "test": {"type": "not_exists", "path": "$.bad"},
                        "message": "no bad field"
                    },
                    {
                        "kind": "assert",
                        "test": {"type": "equals", "path": "$.status", "value": "ok"},
                        "message": "status ok"
                    },
                    {
                        "kind": "assert",
                        "test": {"type": "matches", "path": "$.id", "pattern": "^[A-Z]+$"},
                        "message": "id uppercase"
                    },
                    {
                        "kind": "assert",
                        "test": {"type": "count", "path": "$.items[*]", "cmp": ">=", "expected": 1},
                        "message": "has items"
                    }
                ]
            }]
        }]
    }"#;
    let doc = r#"{"status": "ok", "id": "ABC", "items": [1]}"#;
    let report = scheck::check_json(rules_json, doc).unwrap();
    assert!(report.is_ok());
}

// -- Schematron XML rules --------------------------------------------

#[test]
fn schematron_xml_end_to_end() {
    let xml = r#"
<schema xmlns="http://purl.oclc.org/dsdl/schematron">
  <title>XML test</title>
  <pattern id="p">
    <rule context="$">
      <assert test="exists('$.name')">name required</assert>
    </rule>
  </pattern>
</schema>
"#;
    let report = scheck::check_schematron(xml, r#"{"name": "ok"}"#).unwrap();
    assert!(report.is_ok());

    let report = scheck::check_schematron(xml, r"{}").unwrap();
    assert!(!report.is_ok());
}

// -- Free-text rules -------------------------------------------------

#[test]
fn freetext_end_to_end() {
    let rules = r#"Every document must have a "name" field.
The "status" field must equal "active"."#;
    let report = scheck::check_freetext(rules, r#"{"name": "x", "status": "active"}"#).unwrap();
    assert!(report.is_ok());

    let report = scheck::check_freetext(rules, r"{}").unwrap();
    assert!(!report.is_ok());
}

// -- Builder API integration -----------------------------------------

#[test]
fn builder_api_end_to_end() {
    use scheck::Severity;
    use scheck::builder::*;

    let schema = schema("builder test")
        .pattern("p", |p| {
            p.rule("$", |r| {
                r.assert(exists("$.name"), "name required")
                    .assert_with(
                        matches("$.id", "^[A-Z]"),
                        "id must start uppercase",
                        Severity::Warning,
                    )
                    .report(exists("$.metadata"), "has metadata")
            })
        })
        .build();

    let report = scheck::validate_json(&schema, r#"{"name": "A", "id": "XYZ"}"#).unwrap();
    assert!(report.is_ok());

    let report = scheck::validate_json(&schema, r#"{"id": "abc"}"#).unwrap();
    assert!(!report.is_ok());
}

#[test]
fn builder_schema_round_trips_through_json() {
    use scheck::builder::*;

    let schema = schema("roundtrip")
        .pattern("p", |p| {
            p.rule("$", |r| {
                r.assert(exists("$.x"), "need x")
                    .assert(equals("$.y", "ok"), "y must be ok")
            })
        })
        .build();

    let json = serde_json::to_string(&schema).unwrap();
    let report = scheck::check_json(&json, r#"{"x": 1, "y": "ok"}"#).unwrap();
    assert!(report.is_ok());
}

// -- Edge cases: special characters ----------------------------------

#[test]
fn message_with_special_chars() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.x")
                        message="field \"x\" is required (see docs)";
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    let text = report.to_text();
    assert!(text.contains("field \"x\" is required"));
}

#[test]
fn unicode_field_names() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.nombre")
                        message="nombre required";
                }
            }
        }
    "#;
    assert!(check_ok(rules, r#"{"nombre": "Juan"}"#).unwrap());
    assert!(!check_ok(rules, r#"{"name": "John"}"#).unwrap());
}

// -- Report counts ---------------------------------------------------

#[test]
fn report_counts_are_accurate() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.a")
                        message="a" severity=fatal;
                    assert exists("$.b")
                        message="b" severity=error;
                    assert exists("$.c")
                        message="c" severity=warning;
                    assert exists("$.d")
                        message="d" severity=info;
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    assert_eq!(report.fatal_count(), 1);
    assert_eq!(report.error_count(), 1);
    assert_eq!(report.warning_count(), 1);
    assert_eq!(report.info_count(), 1);
    assert!(!report.is_ok());
    assert_eq!(report.findings().len(), 4);
    assert_eq!(report.failures().len(), 4);
    assert!(report.reports().is_empty());
}

#[test]
fn info_only_failures_still_pass() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.optional")
                        message="optional missing"
                        severity=info;
                }
            }
        }
    "#;
    let report = check(rules, r"{}").unwrap();
    assert!(report.is_ok());
    assert_eq!(report.info_count(), 1);
}

// -- Multiple rules in same pattern ----------------------------------

#[test]
fn multiple_rules_different_contexts() {
    let rules = r#"
        schema "t" {
            pattern "p" {
                rule context="$" {
                    assert exists("$.items")
                        message="items required";
                }
                rule context="$.items[*]" {
                    assert exists("$.id")
                        message="item id required";
                }
            }
        }
    "#;
    let doc = r#"{"items": [{"id": 1}, {"name": "no id"}]}"#;
    let report = check(rules, doc).unwrap();
    assert_eq!(report.error_count(), 1);
}

// -- Default rulesets ------------------------------------------------

fn load_ruleset_from(domain: &str, name: &str) -> scheck::Schema {
    let path = format!("rulesets/{domain}/{name}.json");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    serde_json::from_str(&src).unwrap_or_else(|e| panic!("cannot parse {path}: {e}"))
}

fn load_ruleset(name: &str) -> scheck::Schema {
    load_ruleset_from("security", name)
}

fn load_testdata_from(domain: &str, name: &str) -> String {
    let path = format!("etc/testdata/{domain}/{name}.json");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

fn load_testdata(name: &str) -> String {
    load_testdata_from("security", name)
}

#[test]
fn csaf_ruleset_valid_document() {
    let schema = load_ruleset("csaf-2.0-mandatory");
    let doc = scheck::load(&load_testdata("csaf-valid")).unwrap();
    let report = scheck::validate_phase(&schema, &doc, "full");
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn csaf_ruleset_invalid_document() {
    let schema = load_ruleset("csaf-2.0-mandatory");
    let doc = scheck::load(&load_testdata("csaf-invalid")).unwrap();
    let report = scheck::validate_phase(&schema, &doc, "structural");
    assert!(!report.is_ok());
    assert!(
        report.fatal_count() >= 3,
        "expected at least 3 fatal errors"
    );
}

#[test]
fn cyclonedx_ruleset_valid_document() {
    let schema = load_ruleset("cyclonedx-min");
    let doc = scheck::load(&load_testdata("cyclonedx-valid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn cyclonedx_ruleset_invalid_document() {
    let schema = load_ruleset("cyclonedx-min");
    let doc = scheck::load(&load_testdata("cyclonedx-invalid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(!report.is_ok());
    assert!(report.fatal_count() >= 1);
}

#[test]
fn spdx_ruleset_valid_document() {
    let schema = load_ruleset("spdx-min");
    let doc = scheck::load(&load_testdata("spdx-valid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn spdx_ruleset_invalid_document() {
    let schema = load_ruleset("spdx-min");
    let doc = scheck::load(&load_testdata("spdx-invalid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(!report.is_ok());
    assert!(report.fatal_count() >= 3);
}

#[test]
fn vex_ruleset_valid_document() {
    let schema = load_ruleset("vex-coherence");
    let doc = scheck::load(&load_testdata("vex-valid")).unwrap();
    let report = scheck::validate_phase(&schema, &doc, "full");
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn vex_ruleset_invalid_document() {
    let schema = load_ruleset("vex-coherence");
    let doc = scheck::load(&load_testdata("vex-invalid")).unwrap();
    let report = scheck::validate_phase(&schema, &doc, "full");
    assert!(!report.is_ok());
}

#[test]
fn osv_ruleset_valid_document() {
    let schema = load_ruleset("osv");
    let doc = scheck::load(&load_testdata("osv-valid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn osv_ruleset_invalid_document() {
    let schema = load_ruleset("osv");
    let doc = scheck::load(&load_testdata("osv-invalid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(!report.is_ok());
}

#[test]
fn cyclonedx_quality_valid() {
    let schema = load_ruleset("cyclonedx-quality");
    let doc = scheck::load(&load_testdata("cyclonedx-quality-valid")).unwrap();
    let report = scheck::validate_phase(&schema, &doc, "quality");
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn cyclonedx_quality_invalid() {
    let schema = load_ruleset("cyclonedx-quality");
    let doc = scheck::load(&load_testdata("cyclonedx-quality-invalid")).unwrap();
    let report = scheck::validate_phase(&schema, &doc, "quality");
    assert!(!report.is_ok());
}

#[test]
fn spdx_ntia_valid() {
    let schema = load_ruleset("spdx-ntia");
    let doc = scheck::load(&load_testdata("spdx-ntia-valid")).unwrap();
    let report = scheck::validate_phase(&schema, &doc, "quality");
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn spdx_ntia_invalid() {
    let schema = load_ruleset("spdx-ntia");
    let doc = scheck::load(&load_testdata("spdx-ntia-invalid")).unwrap();
    let report = scheck::validate_phase(&schema, &doc, "quality");
    assert!(!report.is_ok());
}

// -- API rulesets ----------------------------------------------------

#[test]
fn openapi_response_valid() {
    let schema = load_ruleset_from("api", "openapi-response");
    let doc = scheck::load(&load_testdata_from("api", "openapi-response-valid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn openapi_response_invalid() {
    let schema = load_ruleset_from("api", "openapi-response");
    let doc = scheck::load(&load_testdata_from("api", "openapi-response-invalid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(!report.is_ok());
}

#[test]
fn jsonapi_valid() {
    let schema = load_ruleset_from("api", "jsonapi");
    let doc = scheck::load(&load_testdata_from("api", "jsonapi-valid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn jsonapi_invalid() {
    let schema = load_ruleset_from("api", "jsonapi");
    let doc = scheck::load(&load_testdata_from("api", "jsonapi-invalid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(!report.is_ok());
}

// -- Config rulesets --------------------------------------------------

#[test]
fn kubernetes_pod_valid() {
    let schema = load_ruleset_from("config", "kubernetes-pod");
    let doc = scheck::load(&load_testdata_from("config", "kubernetes-pod-valid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn kubernetes_pod_invalid() {
    let schema = load_ruleset_from("config", "kubernetes-pod");
    let doc = scheck::load(&load_testdata_from("config", "kubernetes-pod-invalid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(!report.is_ok());
}

#[test]
fn github_actions_valid() {
    let schema = load_ruleset_from("config", "github-actions");
    let doc = scheck::load(&load_testdata_from("config", "github-actions-valid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn github_actions_invalid() {
    let schema = load_ruleset_from("config", "github-actions");
    let doc = scheck::load(&load_testdata_from("config", "github-actions-invalid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(!report.is_ok());
}

// -- Data quality rulesets --------------------------------------------

#[test]
fn contact_records_valid() {
    let schema = load_ruleset_from("data-quality", "contact-records");
    let doc = scheck::load(&load_testdata_from("data-quality", "contacts-valid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn contact_records_invalid() {
    let schema = load_ruleset_from("data-quality", "contact-records");
    let doc = scheck::load(&load_testdata_from("data-quality", "contacts-invalid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(!report.is_ok());
}

#[test]
fn dataset_metadata_valid() {
    let schema = load_ruleset_from("data-quality", "dataset-metadata");
    let doc = scheck::load(&load_testdata_from("data-quality", "dataset-valid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

#[test]
fn dataset_metadata_invalid() {
    let schema = load_ruleset_from("data-quality", "dataset-metadata");
    let doc = scheck::load(&load_testdata_from("data-quality", "dataset-invalid")).unwrap();
    let report = scheck::validate(&schema, &doc);
    assert!(!report.is_ok());
}

// -- Named test types ------------------------------------------------

#[test]
fn named_email_valid() {
    let rules = r#"{
        "title": "t",
        "patterns": [{"name": "p", "rules": [{"context": "$", "checks": [
            {"kind": "assert", "test": {"type": "named", "name": "email", "path": "$.email"}, "message": "bad email"}
        ]}]}]
    }"#;
    assert!(
        scheck::check_json(rules, r#"{"email": "alice@example.com"}"#)
            .unwrap()
            .is_ok()
    );
    assert!(
        !scheck::check_json(rules, r#"{"email": "not-an-email"}"#)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn named_url_valid() {
    let rules = r#"{
        "title": "t",
        "patterns": [{"name": "p", "rules": [{"context": "$", "checks": [
            {"kind": "assert", "test": {"type": "named", "name": "url", "path": "$.link"}, "message": "bad url"}
        ]}]}]
    }"#;
    assert!(
        scheck::check_json(rules, r#"{"link": "https://example.com"}"#)
            .unwrap()
            .is_ok()
    );
    assert!(
        !scheck::check_json(rules, r#"{"link": "not a url"}"#)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn named_cve_id() {
    let rules = r#"{
        "title": "t",
        "patterns": [{"name": "p", "rules": [{"context": "$", "checks": [
            {"kind": "assert", "test": {"type": "named", "name": "cve_id", "path": "$.cve"}, "message": "bad cve"}
        ]}]}]
    }"#;
    assert!(
        scheck::check_json(rules, r#"{"cve": "CVE-2024-12345"}"#)
            .unwrap()
            .is_ok()
    );
    assert!(
        !scheck::check_json(rules, r#"{"cve": "not-a-cve"}"#)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn named_cve_id_hyphenated() {
    let rules = r#"{
        "title": "t",
        "patterns": [{"name": "p", "rules": [{"context": "$", "checks": [
            {"kind": "assert", "test": {"type": "named", "name": "cve-id", "path": "$.cve"}, "message": "bad cve"}
        ]}]}]
    }"#;
    assert!(
        scheck::check_json(rules, r#"{"cve": "CVE-2024-12345"}"#)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn named_purl() {
    let rules = r#"{
        "title": "t",
        "patterns": [{"name": "p", "rules": [{"context": "$", "checks": [
            {"kind": "assert", "test": {"type": "named", "name": "purl", "path": "$.purl"}, "message": "bad purl"}
        ]}]}]
    }"#;
    assert!(
        scheck::check_json(rules, r#"{"purl": "pkg:cargo/serde@1.0"}"#)
            .unwrap()
            .is_ok()
    );
    assert!(
        !scheck::check_json(rules, r#"{"purl": "serde@1.0"}"#)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn named_semver() {
    let rules = r#"{
        "title": "t",
        "patterns": [{"name": "p", "rules": [{"context": "$", "checks": [
            {"kind": "assert", "test": {"type": "named", "name": "semver", "path": "$.version"}, "message": "bad version"}
        ]}]}]
    }"#;
    assert!(
        scheck::check_json(rules, r#"{"version": "1.2.3"}"#)
            .unwrap()
            .is_ok()
    );
    assert!(
        scheck::check_json(rules, r#"{"version": "0.1.0-beta.1"}"#)
            .unwrap()
            .is_ok()
    );
    assert!(
        !scheck::check_json(rules, r#"{"version": "v1.2"}"#)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn named_uuid() {
    let rules = r#"{
        "title": "t",
        "patterns": [{"name": "p", "rules": [{"context": "$", "checks": [
            {"kind": "assert", "test": {"type": "named", "name": "uuid", "path": "$.id"}, "message": "bad uuid"}
        ]}]}]
    }"#;
    assert!(
        scheck::check_json(rules, r#"{"id": "550e8400-e29b-41d4-a716-446655440000"}"#)
            .unwrap()
            .is_ok()
    );
    assert!(
        !scheck::check_json(rules, r#"{"id": "not-a-uuid"}"#)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn named_iso_date() {
    let rules = r#"{
        "title": "t",
        "patterns": [{"name": "p", "rules": [{"context": "$", "checks": [
            {"kind": "assert", "test": {"type": "named", "name": "iso_date", "path": "$.date"}, "message": "bad date"}
        ]}]}]
    }"#;
    assert!(
        scheck::check_json(rules, r#"{"date": "2024-01-15"}"#)
            .unwrap()
            .is_ok()
    );
    assert!(
        !scheck::check_json(rules, r#"{"date": "Jan 15 2024"}"#)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn named_iso_datetime() {
    let rules = r#"{
        "title": "t",
        "patterns": [{"name": "p", "rules": [{"context": "$", "checks": [
            {"kind": "assert", "test": {"type": "named", "name": "iso_datetime", "path": "$.ts"}, "message": "bad ts"}
        ]}]}]
    }"#;
    assert!(
        scheck::check_json(rules, r#"{"ts": "2024-01-15T10:00:00Z"}"#)
            .unwrap()
            .is_ok()
    );
    assert!(
        !scheck::check_json(rules, r#"{"ts": "yesterday"}"#)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn named_unknown_returns_false() {
    let rules = r#"{
        "title": "t",
        "patterns": [{"name": "p", "rules": [{"context": "$", "checks": [
            {"kind": "assert", "test": {"type": "named", "name": "bogus", "path": "$.x"}, "message": "unknown type"}
        ]}]}]
    }"#;
    assert!(
        !scheck::check_json(rules, r#"{"x": "anything"}"#)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn named_type_builder_api() {
    use scheck::builder::*;

    let schema = schema("named types")
        .pattern("p", |p| {
            p.rule("$", |r| {
                r.assert(is_email("$.email"), "bad email")
                    .assert(is_url("$.website"), "bad url")
                    .assert(is_semver("$.version"), "bad version")
            })
        })
        .build();

    let doc = r#"{"email": "a@b.com", "website": "https://x.com", "version": "1.0.0"}"#;
    let report = scheck::validate_json(&schema, doc).unwrap();
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

// -- Validated proof wrapper -----------------------------------------

#[test]
fn validated_wrapper_success() {
    use scheck::builder::*;

    let s = schema("t")
        .pattern("p", |p| {
            p.rule("$", |r| r.assert(exists("$.name"), "need name"))
        })
        .build();
    let doc = scheck::from_json(r#"{"name": "Alice"}"#).unwrap();
    let validated = scheck::try_validate(&s, doc).unwrap();
    assert!(validated.report().is_ok());
    assert_eq!(
        validated
            .document()
            .root
            .get("name")
            .unwrap()
            .as_str()
            .unwrap(),
        "Alice"
    );
}

#[test]
fn validated_wrapper_failure() {
    use scheck::builder::*;

    let s = schema("t")
        .pattern("p", |p| {
            p.rule("$", |r| r.assert(exists("$.name"), "need name"))
        })
        .build();
    let doc = scheck::from_json(r"{}").unwrap();
    let err = scheck::try_validate(&s, doc).unwrap_err();
    assert!(!err.report().is_ok());
    assert!(err.to_string().contains("need name"));
}

#[test]
fn validated_into_document() {
    use scheck::builder::*;

    let s = schema("t")
        .pattern("p", |p| p.rule("$", |r| r.assert(exists("$.x"), "need x")))
        .build();
    let doc = scheck::from_json(r#"{"x": 1}"#).unwrap();
    let validated = scheck::try_validate(&s, doc).unwrap();
    let doc = validated.into_document();
    assert_eq!(doc.root.get("x").unwrap().as_i64().unwrap(), 1);
}

// -- Partial validation (--context) ----------------------------------

#[test]
fn partial_validation_subtree() {
    use scheck::builder::*;

    let s = schema("t")
        .pattern("p", |p| {
            p.rule("$", |r| r.assert(exists("$.name"), "need name"))
        })
        .build();

    let doc = scheck::from_json(r#"{"users": [{"name": "Alice"}, {"age": 30}]}"#).unwrap();

    // Validate each user individually
    let report = scheck::validate_context(&s, &doc, "$.users[*]", "");
    // One user has name, one does not
    assert_eq!(report.error_count(), 1);
}

#[test]
fn partial_validation_no_match() {
    use scheck::builder::*;

    let s = schema("t")
        .pattern("p", |p| {
            p.rule("$", |r| r.assert(exists("$.name"), "need name"))
        })
        .build();

    let doc = scheck::from_json(r#"{"x": 1}"#).unwrap();
    let report = scheck::validate_context(&s, &doc, "$.nonexistent", "");
    assert!(report.is_ok());
    assert!(report.findings().is_empty());
}

#[test]
fn partial_validation_single_object() {
    use scheck::builder::*;

    let s = schema("t")
        .pattern("p", |p| {
            p.rule("$", |r| {
                r.assert(exists("$.title"), "need title")
                    .assert(is_url("$.url"), "bad url")
            })
        })
        .build();

    let doc = scheck::from_json(
        r#"{"metadata": {"title": "test", "url": "https://example.com"}, "data": []}"#,
    )
    .unwrap();

    let report = scheck::validate_context(&s, &doc, "$.metadata", "");
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());
}

// -- Spectral conversion ---------------------------------------------

#[test]
fn spectral_convert_and_validate() {
    let spectral_src = load_testdata_from("api", "spectral-sample");
    let result = scheck::spectral::convert_spectral(&spectral_src).unwrap();

    // 5 convertible rules, 1 skipped custom function
    assert_eq!(result.schema.patterns.len(), 5);
    assert_eq!(result.skipped.len(), 1);
    assert_eq!(result.skipped[0].0, "custom-function-rule");

    // Converted schema round-trips through JSON
    let json = serde_json::to_string(&result.schema).unwrap();
    let schema: scheck::Schema = serde_json::from_str(&json).unwrap();

    // Validate a passing document
    let doc = r#"{
        "info": {
            "contact": { "name": "Alice" },
            "description": "An API"
        }
    }"#;
    let report = scheck::check_json(&json, doc).unwrap();
    assert!(report.is_ok(), "expected OK, got:\n{}", report.to_text());

    // Validate a failing document
    let report = scheck::check_json(&json, r"{}").unwrap();
    assert!(!report.is_ok());
    assert!(report.error_count() >= 1);
    assert_eq!(schema.patterns.len(), 5);
}
