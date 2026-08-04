//! Evaluation engine: runs rules against a document tree.
//!
//! Follows the Schematron evaluation model:
//! 1. Resolve active phase to determine which patterns run.
//! 2. For each active pattern, evaluate each rule.
//! 3. For each rule, select context nodes via `JSONPath`.
//! 4. For each matched node, resolve let bindings, then
//!    evaluate each assert/report check.
//! 5. Collect results into an SVRL-inspired report.

use std::collections::HashMap;

use regex::Regex;
use serde_json::Value;
use serde_json_path::JsonPath;

use crate::document::Document;
use crate::report::{CheckResult, FiredRule, Report, ResultKind};
use crate::rule::{Check, CheckKind, Predicate, Schema};

/// Validate a document against a schema using the default phase.
#[must_use]
pub fn validate(schema: &Schema, doc: &Document) -> Report {
    validate_phase(schema, doc, "")
}

/// Validate a document against a schema using a named phase.
///
/// Pass `""` or `"all"` to run all patterns.
#[must_use]
pub fn validate_phase(schema: &Schema, doc: &Document, phase: &str) -> Report {
    let phase_name = if phase.is_empty() {
        &schema.default_phase
    } else {
        phase
    };

    let active = schema.active_patterns(phase_name);
    let mut fired_rules = Vec::new();
    let mut results = Vec::new();

    for pattern in &active {
        for rule in &pattern.rules {
            let context_nodes = query_path(&rule.context, &doc.root);

            if context_nodes.is_empty() {
                continue;
            }

            for ctx_node in &context_nodes {
                let bindings = resolve_lets(&rule.lets, ctx_node);

                fired_rules.push(FiredRule {
                    rule_id: rule.id.clone(),
                    pattern: pattern.name.clone(),
                    context_path: rule.context.clone(),
                });

                for check in &rule.checks {
                    let result = eval_check(
                        check,
                        ctx_node,
                        &bindings,
                        &rule.id,
                        &pattern.name,
                        schema,
                        &rule.context,
                    );
                    results.push(result);
                }
            }
        }
    }

    Report::new(
        schema.title.clone(),
        phase_name.to_owned(),
        fired_rules,
        results,
    )
}

/// Query a `JSONPath` expression against a value, returning
/// cloned matches. Each context node is treated as a root
/// for predicate evaluation, so we clone them.
fn query_path(path_str: &str, value: &Value) -> Vec<Value> {
    if path_str == "$" {
        return vec![value.clone()];
    }
    let Ok(path) = JsonPath::parse(path_str) else {
        return vec![];
    };
    let node_list = path.query(value);
    node_list.all().into_iter().cloned().collect()
}

/// Query a `JSONPath` against a value, returning references.
fn query_path_ref<'a>(path_str: &str, value: &'a Value) -> Vec<&'a Value> {
    if path_str == "$" {
        return vec![value];
    }
    let Ok(path) = JsonPath::parse(path_str) else {
        return vec![];
    };
    path.query(value).all()
}

/// Resolve let bindings for a rule against a context node.
fn resolve_lets(lets: &[crate::rule::LetBinding], node: &Value) -> HashMap<String, bool> {
    let mut bindings = HashMap::new();
    for binding in lets {
        let selected = query_path_ref(&binding.path, node);
        bindings.insert(binding.name.clone(), !selected.is_empty());
    }
    bindings
}

fn eval_check(
    check: &Check,
    context_node: &Value,
    bindings: &HashMap<String, bool>,
    rule_id: &str,
    pattern_name: &str,
    schema: &Schema,
    context_path: &str,
) -> CheckResult {
    let test_result = eval_predicate(&check.test, context_node, bindings);

    // Schematron semantics:
    // - assert: fires (= failure) when test is FALSE
    // - report: fires (= finding) when test is TRUE
    let (fired, kind) = match check.kind {
        CheckKind::Assert => (!test_result, ResultKind::FailedAssert),
        CheckKind::Report => (test_result, ResultKind::SuccessfulReport),
    };

    let diagnostic_text = check
        .diagnostics
        .iter()
        .filter_map(|id| schema.diagnostic(id))
        .collect::<Vec<_>>()
        .join("; ");

    CheckResult {
        kind,
        fired,
        rule_id: rule_id.to_owned(),
        pattern: pattern_name.to_owned(),
        path: context_path.to_owned(),
        severity: check.severity,
        message: check.message.clone(),
        diagnostic: diagnostic_text,
        flag: check.flag.clone(),
    }
}

fn eval_predicate(pred: &Predicate, node: &Value, bindings: &HashMap<String, bool>) -> bool {
    match pred {
        Predicate::Exists { path } => !query_path_ref(path, node).is_empty(),
        Predicate::NotExists { path } => query_path_ref(path, node).is_empty(),
        Predicate::Equals { path, value } => {
            let nodes = query_path_ref(path, node);
            nodes.iter().any(|n| value_as_string(n) == *value)
        }
        Predicate::Matches { path, pattern } => match Regex::new(pattern) {
            Ok(re) => {
                let nodes = query_path_ref(path, node);
                nodes.iter().any(|n| re.is_match(&value_as_string(n)))
            }
            Err(_) => false,
        },
        Predicate::Count {
            path,
            cmp,
            expected,
        } => {
            let count = query_path_ref(path, node).len();
            cmp.eval(count, *expected)
        }
        Predicate::Var { name } => bindings.get(name.as_str()).copied().unwrap_or(false),
        Predicate::And { left, right } => {
            eval_predicate(left, node, bindings) && eval_predicate(right, node, bindings)
        }
        Predicate::Or { left, right } => {
            eval_predicate(left, node, bindings) || eval_predicate(right, node, bindings)
        }
        Predicate::Not { inner } => !eval_predicate(inner, node, bindings),
    }
}

/// Extract a string representation from a `serde_json::Value`.
fn value_as_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_owned(),
        other => other.to_string(),
    }
}

// -- Convenience API -------------------------------------------------

/// Parse `.scheck` rules + document, validate, return report.
///
/// # Errors
///
/// Returns an error if rules or document can't be parsed.
pub fn check(rules_src: &str, doc_src: &str) -> Result<Report, String> {
    check_phase(rules_src, doc_src, "")
}

/// Parse `.scheck` rules + document, validate with a phase.
///
/// # Errors
///
/// Returns an error if rules or document can't be parsed.
pub fn check_phase(rules_src: &str, doc_src: &str, phase: &str) -> Result<Report, String> {
    let schema = crate::parser::parse_schema(rules_src).map_err(|e| format!("Rule error: {e}"))?;
    let doc = crate::document::load(doc_src).map_err(|e| format!("Document error: {e}"))?;
    Ok(validate_phase(&schema, &doc, phase))
}

/// Parse `.scheck` rules + document, return true if no errors or warnings.
///
/// # Errors
///
/// Returns an error if rules or document can't be parsed.
pub fn check_ok(rules_src: &str, doc_src: &str) -> Result<bool, String> {
    let report = check(rules_src, doc_src)?;
    Ok(report.is_ok())
}

/// Validate a JSON string against a pre-built schema.
///
/// # Errors
///
/// Returns an error if the JSON can't be parsed.
pub fn validate_json(schema: &Schema, json: &str) -> Result<Report, String> {
    let doc = crate::document::from_json(json).map_err(|e| format!("Document error: {e}"))?;
    Ok(validate(schema, &doc))
}

/// Load a schema from a JSON string, then validate a document.
///
/// # Errors
///
/// Returns an error if the schema JSON or document can't be parsed.
pub fn check_json(rules_json: &str, doc_src: &str) -> Result<Report, String> {
    let schema: Schema =
        serde_json::from_str(rules_json).map_err(|e| format!("Schema JSON error: {e}"))?;
    let doc = crate::document::load(doc_src).map_err(|e| format!("Document error: {e}"))?;
    Ok(validate(&schema, &doc))
}

/// Parse Schematron XML rules + document, validate.
///
/// # Errors
///
/// Returns an error if the Schematron XML or document can't be parsed.
pub fn check_schematron(rules_xml: &str, doc_src: &str) -> Result<Report, String> {
    let schema = crate::schematron::parse_schematron(rules_xml)
        .map_err(|e| format!("Schematron error: {e}"))?;
    let doc = crate::document::load(doc_src).map_err(|e| format!("Document error: {e}"))?;
    Ok(validate(&schema, &doc))
}

/// Parse free-text rules + document, validate.
///
/// # Errors
///
/// Returns an error if the free-text rules or document can't be parsed.
pub fn check_freetext(rules_text: &str, doc_src: &str) -> Result<Report, String> {
    let schema =
        crate::freetext::parse_freetext(rules_text).map_err(|e| format!("Freetext error: {e}"))?;
    let doc = crate::document::load(doc_src).map_err(|e| format!("Document error: {e}"))?;
    Ok(validate(&schema, &doc))
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::document;

    fn make_doc(json: &str) -> Document {
        document::from_json(json).unwrap()
    }

    #[test]
    fn assert_exists_passes() {
        let rules = r#"
            schema "t" {
                pattern "p" {
                    rule context="$" {
                        assert exists("$.name")
                            message="need name";
                    }
                }
            }
        "#;
        let doc = make_doc(r#"{"name": "Alice"}"#);
        let schema = crate::parser::parse_schema(rules).unwrap();
        let report = validate(&schema, &doc);
        assert!(report.is_ok());
    }

    #[test]
    fn assert_exists_fails() {
        let rules = r#"
            schema "t" {
                pattern "p" {
                    rule context="$" {
                        assert exists("$.email")
                            message="need email";
                    }
                }
            }
        "#;
        let doc = make_doc(r#"{"name": "Alice"}"#);
        let schema = crate::parser::parse_schema(rules).unwrap();
        let report = validate(&schema, &doc);
        assert!(!report.is_ok());
        assert_eq!(report.error_count(), 1);
    }

    #[test]
    fn report_fires_on_success() {
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
        let doc = make_doc(r#"{"deprecated": true}"#);
        let schema = crate::parser::parse_schema(rules).unwrap();
        let report = validate(&schema, &doc);
        let findings = report.findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ResultKind::SuccessfulReport);
    }

    #[test]
    fn report_silent_when_absent() {
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
        let doc = make_doc(r#"{"name": "ok"}"#);
        let schema = crate::parser::parse_schema(rules).unwrap();
        let report = validate(&schema, &doc);
        assert!(report.findings().is_empty());
    }

    #[test]
    fn equals_passes() {
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
        let doc = make_doc(r#"{"status": "active"}"#);
        let schema = crate::parser::parse_schema(rules).unwrap();
        let report = validate(&schema, &doc);
        assert!(report.is_ok());
    }

    #[test]
    fn matches_regex() {
        let rules = r#"
            schema "t" {
                pattern "p" {
                    rule context="$" {
                        assert matches("$.id", "^CVE-\\d{4}-\\d+$")
                            message="bad CVE format";
                    }
                }
            }
        "#;
        let doc = make_doc(r#"{"id": "CVE-2024-12345"}"#);
        let schema = crate::parser::parse_schema(rules).unwrap();
        let report = validate(&schema, &doc);
        assert!(report.is_ok());
    }

    #[test]
    fn count_check() {
        let rules = r#"
            schema "t" {
                pattern "p" {
                    rule context="$" {
                        assert count("$.items[*]", >=, 2)
                            message="need >= 2 items";
                    }
                }
            }
        "#;
        let doc = make_doc(r#"{"items": [1, 2, 3]}"#);
        let schema = crate::parser::parse_schema(rules).unwrap();
        let report = validate(&schema, &doc);
        assert!(report.is_ok());
    }

    #[test]
    fn phase_filtering() {
        let rules = r#"
            schema "t" {
                default_phase "quick";

                phase "quick" {
                    active "basic";
                }

                phase "full" {
                    active "basic";
                    active "strict";
                }

                pattern "basic" {
                    rule context="$" {
                        assert exists("$.id")
                            message="need id";
                    }
                }

                pattern "strict" {
                    rule context="$" {
                        assert matches("$.id", "^[A-Z]")
                            message="id must start uppercase";
                    }
                }
            }
        "#;
        let doc = make_doc(r#"{"id": "abc"}"#);
        let schema = crate::parser::parse_schema(rules).unwrap();

        let quick = validate_phase(&schema, &doc, "quick");
        assert!(quick.is_ok());

        let full = validate_phase(&schema, &doc, "full");
        assert!(!full.is_ok());
        assert_eq!(full.error_count(), 1);
    }

    #[test]
    fn diagnostics_resolved() {
        let rules = r#"
            schema "t" {
                diagnostics {
                    diagnostic "d1" "See spec section 4.2";
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
        let doc = make_doc(r"{}");
        let schema = crate::parser::parse_schema(rules).unwrap();
        let report = validate(&schema, &doc);
        let findings = report.findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].diagnostic, "See spec section 4.2");
    }

    #[test]
    fn severity_levels() {
        let rules = r#"
            schema "t" {
                pattern "p" {
                    rule context="$" {
                        assert exists("$.a")
                            message="missing a"
                            severity=fatal;
                        assert exists("$.b")
                            message="missing b"
                            severity=error;
                        assert exists("$.c")
                            message="missing c"
                            severity=warning;
                        assert exists("$.d")
                            message="missing d"
                            severity=info;
                    }
                }
            }
        "#;
        let doc = make_doc(r"{}");
        let schema = crate::parser::parse_schema(rules).unwrap();
        let report = validate(&schema, &doc);
        assert_eq!(report.fatal_count(), 1);
        assert_eq!(report.error_count(), 1);
        assert_eq!(report.warning_count(), 1);
        assert_eq!(report.info_count(), 1);
    }

    #[test]
    fn fired_rules_tracked() {
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
        let doc = make_doc(r#"{"x": 1}"#);
        let schema = crate::parser::parse_schema(rules).unwrap();
        let report = validate(&schema, &doc);
        assert_eq!(report.fired_rules.len(), 1);
        assert_eq!(report.fired_rules[0].rule_id, "r1");
    }
}
