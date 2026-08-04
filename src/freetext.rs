//! Parser for free-text (natural-language) rules into scheck's
//! `Schema` model.
//!
//! Supported sentence patterns:
//!
//! - `Every <context> must have a "<field>" field.`
//! - `The "<field>" field must match "<pattern>".`
//! - `The "<field>" field must equal "<value>".`
//! - `The "<field>" field must not exist.`
//! - `Every <context> must have at least <n> "<field>".`
//!
//! Uses `txt2data` with an ixml grammar to parse each line into
//! a native parse tree, then converts to scheck `Schema` types.

use txt2data::{Mark, TreeNode};

use crate::rule::{Check, CheckKind, Comparison, Pattern, Predicate, Rule, Schema, Severity};

/// Errors from parsing free-text rules.
#[derive(Debug, thiserror::Error)]
pub enum FreetextError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("conversion error: {0}")]
    Conversion(String),
}

/// ixml grammar for free-text rules.
///
/// Each line is one rule sentence. Uses `+` for the top-level
/// repetition to avoid txt2data's nested-star ambiguity.
/// Each rule consumes its own trailing whitespace.
const GRAMMAR: &str = r#"
rules: rule+.

rule: every_must_have, -ws; must_match, -ws; must_equal, -ws; must_not_exist, -ws; must_have_count, -ws.

every_must_have: -"Every ", @context, -" must have a ", -'"', @field, -'"', -" field", -".".
must_match: -"The ", -'"', @field, -'"', -" field must match ", -'"', @pattern, -'"', -".".
must_equal: -"The ", -'"', @field, -'"', -" field must equal ", -'"', @value, -'"', -".".
must_not_exist: -"The ", -'"', @field, -'"', -" field must not exist", -".".
must_have_count: -"Every ", @context, -" must have at least ", @count, -" ", -'"', @field, -'"', -".".

@context: ~[" "]+.
@field: ~['"']+.
@pattern: ~['"']+.
@value: ~['"']+.
@count: ["0"-"9"]+.
-ws: [" "; #0A; #0D; #09]*.
"#;

/// Parse free-text rules into an scheck `Schema`.
///
/// # Errors
///
/// Returns `FreetextError` on parse failures or conversion issues.
pub fn parse_freetext(input: &str) -> Result<Schema, FreetextError> {
    let grammar = txt2data::parse_grammar(GRAMMAR)
        .map_err(|e| FreetextError::Parse(format!("internal: bad grammar: {e}")))?;
    let parser = txt2data::Parser::new(&grammar);
    let tree = parser
        .parse(input)
        .map_err(|e| FreetextError::Parse(e.to_string()))?;
    convert_rules(&tree.root)
}

// -- conversion -----------------------------------------------------

fn convert_rules(root: &TreeNode) -> Result<Schema, FreetextError> {
    let rule_nodes = find_children(root, "rule");
    if rule_nodes.is_empty() {
        return Err(FreetextError::Conversion("no rules found".into()));
    }

    let mut checks = Vec::new();
    for node in &rule_nodes {
        checks.push(convert_rule_node(node)?);
    }

    Ok(Schema {
        title: "Free-text rules".into(),
        description: String::new(),
        default_phase: String::new(),
        phases: Vec::new(),
        diagnostics: Vec::new(),
        patterns: vec![Pattern {
            name: "rules".into(),
            title: String::new(),
            rules: vec![Rule {
                id: String::new(),
                context: "$".into(),
                lets: Vec::new(),
                checks,
            }],
        }],
    })
}

fn convert_rule_node(node: &TreeNode) -> Result<Check, FreetextError> {
    if let Some(emh) = find_child(node, "every_must_have") {
        let field = get_attr(emh, "field");
        return Ok(make_assert(
            Predicate::Exists {
                path: format!("$.{field}"),
            },
            format!("Every document must have a \"{field}\" field"),
        ));
    }
    if let Some(mm) = find_child(node, "must_match") {
        let field = get_attr(mm, "field");
        let pattern = get_attr(mm, "pattern");
        return Ok(make_assert(
            Predicate::Matches {
                path: format!("$.{field}"),
                pattern: pattern.clone(),
            },
            format!("The \"{field}\" field must match \"{pattern}\""),
        ));
    }
    if let Some(me) = find_child(node, "must_equal") {
        let field = get_attr(me, "field");
        let value = get_attr(me, "value");
        return Ok(make_assert(
            Predicate::Equals {
                path: format!("$.{field}"),
                value: value.clone(),
            },
            format!("The \"{field}\" field must equal \"{value}\""),
        ));
    }
    if let Some(mne) = find_child(node, "must_not_exist") {
        let field = get_attr(mne, "field");
        return Ok(make_assert(
            Predicate::NotExists {
                path: format!("$.{field}"),
            },
            format!("The \"{field}\" field must not exist"),
        ));
    }
    if let Some(mhc) = find_child(node, "must_have_count") {
        let field = get_attr(mhc, "field");
        let count_str = get_attr(mhc, "count");
        let expected: usize = count_str
            .parse()
            .map_err(|_| FreetextError::Conversion(format!("invalid count: {count_str}")))?;
        let context = get_attr(mhc, "context");
        return Ok(make_assert(
            Predicate::Count {
                path: format!("$.{field}[*]"),
                cmp: Comparison::Ge,
                expected,
            },
            format!(
                "Every {context} must have at least \
                 {expected} \"{field}\""
            ),
        ));
    }

    Err(FreetextError::Conversion(
        "unrecognised rule pattern".into(),
    ))
}

fn make_assert(test: Predicate, message: String) -> Check {
    Check {
        kind: CheckKind::Assert,
        test,
        message,
        severity: Severity::Error,
        flag: String::new(),
        diagnostics: Vec::new(),
    }
}

// -- TreeNode helpers -----------------------------------------------

/// Find all visible child elements with a given name,
/// descending through hidden (transparent) nodes.
fn find_children<'a>(node: &'a TreeNode, target: &str) -> Vec<&'a TreeNode> {
    let mut results = Vec::new();
    if let TreeNode::Element { children, .. } = node {
        find_children_recursive(children, target, &mut results);
    }
    results
}

fn find_children_recursive<'a>(
    children: &'a [TreeNode],
    target: &str,
    results: &mut Vec<&'a TreeNode>,
) {
    for child in children {
        match child {
            TreeNode::Element {
                mark: Mark::Hidden,
                children: inner,
                ..
            } => {
                find_children_recursive(inner, target, results);
            }
            TreeNode::Element { name, .. } if name == target => {
                results.push(child);
            }
            _ => {}
        }
    }
}

/// Find the first visible child element with a given name.
fn find_child<'a>(node: &'a TreeNode, target: &str) -> Option<&'a TreeNode> {
    find_children(node, target).into_iter().next()
}

/// Get the text value of an attribute child by name,
/// searching through hidden nodes.
fn get_attr(node: &TreeNode, attr_name: &str) -> String {
    match node {
        TreeNode::Element { children, .. } => {
            if let Some(val) = get_attr_recursive(children, attr_name) {
                return val;
            }
            String::new()
        }
        _ => String::new(),
    }
}

fn get_attr_recursive(children: &[TreeNode], attr_name: &str) -> Option<String> {
    for child in children {
        match child {
            TreeNode::Element {
                mark: Mark::Attribute,
                name,
                children: attr_children,
            } if name == attr_name => {
                return Some(collect_text(attr_children));
            }
            TreeNode::Element {
                mark: Mark::Hidden,
                children: inner,
                ..
            } => {
                if let Some(val) = get_attr_recursive(inner, attr_name) {
                    return Some(val);
                }
            }
            _ => {}
        }
    }
    None
}

/// Collect all text content from a slice of tree nodes.
fn collect_text(nodes: &[TreeNode]) -> String {
    let mut buf = String::new();
    for node in nodes {
        collect_text_recursive(node, &mut buf);
    }
    buf
}

fn collect_text_recursive(node: &TreeNode, buf: &mut String) {
    match node {
        TreeNode::Text { mark, value } => {
            if *mark != Mark::Hidden {
                buf.push_str(value);
            }
        }
        TreeNode::Element { children, .. } => {
            for child in children {
                collect_text_recursive(child, buf);
            }
        }
        TreeNode::Insertion { value } => {
            buf.push_str(value);
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::rule::{Comparison, Predicate};

    #[test]
    fn parse_every_must_have() {
        let input = r#"Every document must have a "name" field."#;
        let schema = parse_freetext(input).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        assert_eq!(check.kind, CheckKind::Assert);
        match &check.test {
            Predicate::Exists { path } => {
                assert_eq!(path, "$.name");
            }
            other => panic!("expected Exists, got: {other:?}"),
        }
    }

    #[test]
    fn parse_must_match() {
        let input = r#"The "email" field must match "^.+@.+$"."#;
        let schema = parse_freetext(input).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        match &check.test {
            Predicate::Matches { path, pattern } => {
                assert_eq!(path, "$.email");
                assert_eq!(pattern, "^.+@.+$");
            }
            other => {
                panic!("expected Matches, got: {other:?}")
            }
        }
    }

    #[test]
    fn parse_must_equal() {
        let input = r#"The "status" field must equal "active"."#;
        let schema = parse_freetext(input).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        match &check.test {
            Predicate::Equals { path, value } => {
                assert_eq!(path, "$.status");
                assert_eq!(value, "active");
            }
            other => {
                panic!("expected Equals, got: {other:?}")
            }
        }
    }

    #[test]
    fn parse_must_not_exist() {
        let input = r#"The "password" field must not exist."#;
        let schema = parse_freetext(input).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        match &check.test {
            Predicate::NotExists { path } => {
                assert_eq!(path, "$.password");
            }
            other => {
                panic!("expected NotExists, got: {other:?}")
            }
        }
    }

    #[test]
    fn parse_must_have_count() {
        let input = r#"Every item must have at least 2 "tags"."#;
        let schema = parse_freetext(input).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        match &check.test {
            Predicate::Count {
                path,
                cmp,
                expected,
            } => {
                assert_eq!(path, "$.tags[*]");
                assert_eq!(*cmp, Comparison::Ge);
                assert_eq!(*expected, 2);
            }
            other => {
                panic!("expected Count, got: {other:?}")
            }
        }
    }

    #[test]
    fn parse_multiple_rules() {
        let input = "\
Every document must have a \"name\" field.\n\
The \"email\" field must match \"^.+@.+$\".\n\
The \"password\" field must not exist.";
        let schema = parse_freetext(input).unwrap();
        let checks = &schema.patterns[0].rules[0].checks;
        assert_eq!(checks.len(), 3);

        assert!(matches!(&checks[0].test, Predicate::Exists { .. }));
        assert!(matches!(&checks[1].test, Predicate::Matches { .. }));
        assert!(matches!(&checks[2].test, Predicate::NotExists { .. }));
    }

    #[test]
    fn end_to_end_freetext_validation() {
        let rules = r#"Every document must have a "name" field.
The "status" field must equal "active"."#;
        let schema = parse_freetext(rules).unwrap();

        let json = r#"{"name": "test", "status": "active"}"#;
        let doc = crate::document::from_json(json).unwrap();
        let report = crate::eval::validate(&schema, &doc);
        assert!(report.is_ok(), "expected OK report, got: {report:?}");

        // Now test with missing field
        let json_bad = r#"{"status": "inactive"}"#;
        let doc_bad = crate::document::from_json(json_bad).unwrap();
        let report_bad = crate::eval::validate(&schema, &doc_bad);
        assert!(!report_bad.is_ok(), "expected failures, got OK");
        assert!(report_bad.error_count() >= 1);
    }
}
