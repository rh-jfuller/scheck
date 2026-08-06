//! One-shot converter from Spectral rulesets to scheck schemas.
//!
//! Converts the subset of Spectral rules that use built-in functions:
//! - `truthy` (+ optional `field`) → `exists`
//! - `falsy` / `undefined` (+ optional `field`) → `not_exists`
//! - `pattern` (`match`/`notMatch`) → `matches` / `not(matches)`
//! - `length` (`min`/`max`) → `count`
//!
//! Rules using custom JS functions are skipped with a warning
//! in the returned `ConvertResult`.

use serde_json::Value;

use crate::rule::{Check, CheckKind, Pattern, Predicate, Rule, Schema, Severity};

/// Result of converting a Spectral ruleset.
#[derive(Debug)]
pub struct ConvertResult {
    /// Converted scheck schema.
    pub schema: Schema,
    /// Rules that could not be converted (name + reason).
    pub skipped: Vec<(String, String)>,
}

/// Convert a Spectral ruleset (JSON or YAML string) to scheck schema.
///
/// # Errors
///
/// Returns an error if the input cannot be parsed as JSON or YAML.
pub fn convert_spectral(input: &str) -> Result<ConvertResult, String> {
    let root: Value = parse_input(input)?;
    let rules_obj = root
        .get("rules")
        .and_then(Value::as_object)
        .ok_or("spectral ruleset must have a 'rules' object")?;

    let mut patterns = Vec::new();
    let mut skipped = Vec::new();

    for (name, rule_val) in rules_obj {
        match convert_rule(name, rule_val) {
            Ok(pattern) => patterns.push(pattern),
            Err(reason) => skipped.push((name.clone(), reason)),
        }
    }

    let title = root
        .get("description")
        .or_else(|| root.get("title"))
        .and_then(Value::as_str)
        .unwrap_or("Converted Spectral ruleset")
        .to_owned();

    Ok(ConvertResult {
        schema: Schema {
            title,
            description: String::new(),
            default_phase: String::new(),
            phases: Vec::new(),
            diagnostics: Vec::new(),
            patterns,
        },
        skipped,
    })
}

fn parse_input(input: &str) -> Result<Value, String> {
    let trimmed = input.trim_start();
    if trimmed.starts_with('{') {
        serde_json::from_str(input).map_err(|e| format!("JSON parse error: {e}"))
    } else {
        serde_yml::from_str(input).map_err(|e| format!("YAML parse error: {e}"))
    }
}

fn convert_rule(name: &str, val: &Value) -> Result<Pattern, String> {
    let given = extract_given(val)?;
    let description = val
        .get("description")
        .and_then(Value::as_str)
        .or_else(|| val.get("message").and_then(Value::as_str))
        .unwrap_or("")
        .to_owned();
    let severity = extract_severity(val);

    let then_val = val.get("then").ok_or("rule missing 'then'")?;

    let then_items: Vec<&Value> = if let Some(arr) = then_val.as_array() {
        arr.iter().collect()
    } else {
        vec![then_val]
    };

    let mut checks = Vec::new();
    for item in &then_items {
        let check = convert_then(&given, item, &description, severity)?;
        checks.push(check);
    }

    Ok(Pattern {
        name: name.to_owned(),
        title: description,
        rules: vec![Rule {
            id: String::new(),
            context: given,
            lets: Vec::new(),
            checks,
        }],
    })
}

fn extract_given(val: &Value) -> Result<String, String> {
    match val.get("given") {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Array(arr)) => arr
            .first()
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| "empty 'given' array".to_owned()),
        _ => Err("rule missing 'given' path".to_owned()),
    }
}

fn extract_severity(val: &Value) -> Severity {
    match val.get("severity") {
        Some(Value::String(s)) => match s.as_str() {
            "warn" | "warning" => Severity::Warning,
            "info" | "hint" | "off" => Severity::Info,
            _ => Severity::Error,
        },
        Some(Value::Number(n)) => match n.as_u64().unwrap_or(1) {
            0 => Severity::Fatal,
            1 => Severity::Error,
            2 => Severity::Warning,
            _ => Severity::Info,
        },
        _ => Severity::Error,
    }
}

fn convert_then(
    context: &str,
    then_val: &Value,
    message: &str,
    severity: Severity,
) -> Result<Check, String> {
    let function = then_val
        .get("function")
        .and_then(Value::as_str)
        .ok_or("'then' missing 'function'")?;

    let field = then_val.get("field").and_then(Value::as_str);
    let opts = then_val.get("functionOptions");

    let path = match field {
        Some("@key") => context.to_owned(),
        Some(f) => format!("$.{f}"),
        None => "$".to_owned(),
    };

    let test = match function {
        "truthy" => Predicate::Exists { path },
        "falsy" | "undefined" => Predicate::NotExists { path },
        "pattern" => convert_pattern_function(&path, opts)?,
        "length" => convert_length_function(&path, opts)?,
        other => {
            return Err(format!("custom function '{other}' cannot be converted"));
        }
    };

    Ok(Check {
        kind: CheckKind::Assert,
        test,
        message: message.to_owned(),
        severity,
        flag: String::new(),
        diagnostics: Vec::new(),
    })
}

fn convert_pattern_function(path: &str, opts: Option<&Value>) -> Result<Predicate, String> {
    let opts = opts.ok_or("pattern function requires functionOptions")?;

    if let Some(m) = opts.get("match").and_then(Value::as_str) {
        return Ok(Predicate::Matches {
            path: path.to_owned(),
            pattern: m.to_owned(),
        });
    }
    if let Some(nm) = opts.get("notMatch").and_then(Value::as_str) {
        return Ok(Predicate::Not {
            inner: Box::new(Predicate::Matches {
                path: path.to_owned(),
                pattern: nm.to_owned(),
            }),
        });
    }

    Err("pattern function requires 'match' or 'notMatch'".to_owned())
}

fn convert_length_function(path: &str, opts: Option<&Value>) -> Result<Predicate, String> {
    let opts = opts.ok_or("length function requires functionOptions")?;
    let items_path = format!("{path}[*]");

    if let Some(min) = opts.get("min").and_then(Value::as_u64) {
        let expected = usize::try_from(min).map_err(|_| "min value too large".to_owned())?;
        return Ok(Predicate::Count {
            path: items_path,
            cmp: crate::rule::Comparison::Ge,
            expected,
        });
    }
    if let Some(max) = opts.get("max").and_then(Value::as_u64) {
        let expected = usize::try_from(max).map_err(|_| "max value too large".to_owned())?;
        return Ok(Predicate::Count {
            path: items_path,
            cmp: crate::rule::Comparison::Le,
            expected,
        });
    }

    Err("length function requires 'min' or 'max'".to_owned())
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn convert_truthy_rule() {
        let input = r#"{
            "rules": {
                "info-contact": {
                    "description": "Info must have contact",
                    "given": "$",
                    "severity": "warn",
                    "then": { "field": "info.contact", "function": "truthy" }
                }
            }
        }"#;
        let result = convert_spectral(input).unwrap();
        assert_eq!(result.schema.patterns.len(), 1);
        assert!(result.skipped.is_empty());
        let check = &result.schema.patterns[0].rules[0].checks[0];
        assert!(matches!(&check.test, Predicate::Exists { path } if path == "$.info.contact"));
        assert_eq!(check.severity, Severity::Warning);
    }

    #[test]
    fn convert_pattern_match() {
        let input = r#"{
            "rules": {
                "valid-id": {
                    "description": "ID must be alphanumeric",
                    "given": "$.paths[*]",
                    "then": {
                        "field": "operationId",
                        "function": "pattern",
                        "functionOptions": { "match": "^[a-zA-Z0-9]+$" }
                    }
                }
            }
        }"#;
        let result = convert_spectral(input).unwrap();
        let check = &result.schema.patterns[0].rules[0].checks[0];
        assert!(
            matches!(&check.test, Predicate::Matches { pattern, .. } if pattern == "^[a-zA-Z0-9]+$")
        );
    }

    #[test]
    fn convert_pattern_not_match() {
        let input = r#"{
            "rules": {
                "no-eval": {
                    "description": "No eval in markdown",
                    "given": "$..[description,title]",
                    "then": {
                        "function": "pattern",
                        "functionOptions": { "notMatch": "eval\\(" }
                    }
                }
            }
        }"#;
        let result = convert_spectral(input).unwrap();
        let check = &result.schema.patterns[0].rules[0].checks[0];
        assert!(matches!(&check.test, Predicate::Not { .. }));
    }

    #[test]
    fn convert_undefined() {
        let input = r#"{
            "rules": {
                "no-anyof": {
                    "description": "anyOf not allowed",
                    "given": "$..anyOf",
                    "then": { "function": "undefined" }
                }
            }
        }"#;
        let result = convert_spectral(input).unwrap();
        let check = &result.schema.patterns[0].rules[0].checks[0];
        assert!(matches!(&check.test, Predicate::NotExists { .. }));
    }

    #[test]
    fn convert_length_min() {
        let input = r#"{
            "rules": {
                "has-tags": {
                    "description": "Must have tags",
                    "given": "$",
                    "then": {
                        "field": "tags",
                        "function": "length",
                        "functionOptions": { "min": 1 }
                    }
                }
            }
        }"#;
        let result = convert_spectral(input).unwrap();
        let check = &result.schema.patterns[0].rules[0].checks[0];
        assert!(matches!(&check.test, Predicate::Count { expected: 1, .. }));
    }

    #[test]
    fn skip_custom_function() {
        let input = r#"{
            "rules": {
                "custom-check": {
                    "description": "Uses custom JS",
                    "given": "$",
                    "then": { "function": "oasPathParam" }
                }
            }
        }"#;
        let result = convert_spectral(input).unwrap();
        assert!(result.schema.patterns.is_empty());
        assert_eq!(result.skipped.len(), 1);
        assert!(result.skipped[0].1.contains("oasPathParam"));
    }

    #[test]
    fn convert_multiple_then() {
        let input = r#"{
            "rules": {
                "contact-props": {
                    "description": "Contact must have name and url",
                    "given": "$.info.contact",
                    "then": [
                        { "field": "name", "function": "truthy" },
                        { "field": "url", "function": "truthy" }
                    ]
                }
            }
        }"#;
        let result = convert_spectral(input).unwrap();
        assert_eq!(result.schema.patterns[0].rules[0].checks.len(), 2);
    }

    #[test]
    fn convert_severity_numeric() {
        let input = r#"{
            "rules": {
                "fatal-check": {
                    "description": "Fatal severity 0",
                    "given": "$",
                    "severity": 0,
                    "then": { "field": "x", "function": "truthy" }
                }
            }
        }"#;
        let result = convert_spectral(input).unwrap();
        assert_eq!(
            result.schema.patterns[0].rules[0].checks[0].severity,
            Severity::Fatal
        );
    }

    #[test]
    fn round_trip_converted_schema() {
        let input = r#"{
            "rules": {
                "has-info": {
                    "description": "Must have info",
                    "given": "$",
                    "then": { "field": "info", "function": "truthy" }
                }
            }
        }"#;
        let result = convert_spectral(input).unwrap();
        let json = serde_json::to_string(&result.schema).unwrap();
        let schema: Schema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema.patterns.len(), 1);
    }
}
