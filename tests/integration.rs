#![expect(clippy::unwrap_used)]

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
