//! Parser for ISO Schematron XML into scheck's `Schema` model.
//!
//! Parses standard Schematron XML elements (`<schema>`, `<pattern>`,
//! `<rule>`, `<assert>`, `<report>`, `<phase>`, `<diagnostics>`,
//! `<let>`) and maps them to the internal rule types.
//!
//! Uses `roxmltree` for XML parsing. Predicate expressions in `test`
//! attributes use the same syntax as the DSL parser (e.g.
//! `exists("$.path")`, `matches("$.path", "regex")`).

use roxmltree::{Document, Node};

use crate::rule::{
    Check, CheckKind, Comparison, DiagnosticDef, LetBinding, Pattern, Phase, Predicate, Rule,
    Schema, Severity,
};

/// Errors from parsing Schematron XML.
#[derive(Debug, thiserror::Error)]
pub enum SchematronError {
    #[error("XML parse error: {0}")]
    Xml(String),
    #[error("missing required element: {0}")]
    MissingElement(String),
    #[error("invalid predicate in test attribute: {0}")]
    Predicate(String),
    #[error("invalid attribute value: {0}")]
    InvalidValue(String),
}

const SCHEMATRON_NS: &str = "http://purl.oclc.org/dsdl/schematron";

/// Parse ISO Schematron XML into an scheck `Schema`.
///
/// # Errors
///
/// Returns `SchematronError` on malformed XML, missing required
/// elements, or invalid predicate expressions.
pub fn parse_schematron(xml: &str) -> Result<Schema, SchematronError> {
    let doc = Document::parse(xml).map_err(|e| SchematronError::Xml(e.to_string()))?;
    let root = doc.root_element();
    if root.tag_name().name() != "schema" {
        return Err(SchematronError::MissingElement(
            "root <schema> element".into(),
        ));
    }
    convert_schema(&root)
}

// -- helpers --------------------------------------------------------

/// Check if an element matches a local name (with or without the
/// Schematron namespace).
fn is_elem(node: &Node<'_, '_>, name: &str) -> bool {
    if !node.is_element() {
        return false;
    }
    let tag = node.tag_name();
    tag.name() == name && (tag.namespace().is_none() || tag.namespace() == Some(SCHEMATRON_NS))
}

/// Iterator over direct child elements matching `name`.
fn children_named<'a, 'b>(
    parent: &'a Node<'b, 'b>,
    name: &'a str,
) -> impl Iterator<Item = Node<'b, 'b>> + 'a {
    parent.children().filter(move |c| is_elem(c, name))
}

/// Get text content of an element (concatenated text children).
fn text_content(node: &Node<'_, '_>) -> String {
    node.descendants()
        .filter(Node::is_text)
        .map(|t| t.text().unwrap_or(""))
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Extract the `<title>` child text, falling back to `@title` attr.
fn title_of(node: &Node<'_, '_>) -> String {
    for child in children_named(node, "title") {
        let t = text_content(&child);
        if !t.is_empty() {
            return t;
        }
    }
    node.attribute("title").unwrap_or("").to_owned()
}

// -- conversion -----------------------------------------------------

fn convert_schema(root: &Node<'_, '_>) -> Result<Schema, SchematronError> {
    let title = title_of(root);

    let mut phases = Vec::new();
    let mut diagnostics = Vec::new();
    let mut patterns = Vec::new();

    for child in children_named(root, "phase") {
        phases.push(convert_phase(&child));
    }

    for diag_block in children_named(root, "diagnostics") {
        for diag in children_named(&diag_block, "diagnostic") {
            diagnostics.push(DiagnosticDef {
                id: diag.attribute("id").unwrap_or("").to_owned(),
                message: text_content(&diag),
            });
        }
    }

    for pat in children_named(root, "pattern") {
        patterns.push(convert_pattern(&pat)?);
    }

    Ok(Schema {
        title,
        description: String::new(),
        default_phase: String::new(),
        phases,
        diagnostics,
        patterns,
    })
}

fn convert_phase(node: &Node<'_, '_>) -> Phase {
    let name = node.attribute("id").unwrap_or("").to_owned();
    let mut active_patterns = Vec::new();

    for active in children_named(node, "active") {
        if let Some(pat) = active.attribute("pattern") {
            active_patterns.push(pat.to_owned());
        }
    }

    Phase {
        name,
        description: String::new(),
        active_patterns,
    }
}

fn convert_pattern(node: &Node<'_, '_>) -> Result<Pattern, SchematronError> {
    let name = node.attribute("id").unwrap_or("").to_owned();
    let title = title_of(node);

    let mut rules = Vec::new();
    for rule_node in children_named(node, "rule") {
        rules.push(convert_rule(&rule_node)?);
    }

    Ok(Pattern { name, title, rules })
}

fn convert_rule(node: &Node<'_, '_>) -> Result<Rule, SchematronError> {
    let id = node.attribute("id").unwrap_or("").to_owned();
    let context = node.attribute("context").unwrap_or("$").to_owned();

    let mut lets = Vec::new();
    let mut checks = Vec::new();

    for let_node in children_named(node, "let") {
        lets.push(LetBinding {
            name: let_node.attribute("name").unwrap_or("").to_owned(),
            path: let_node.attribute("value").unwrap_or("").to_owned(),
        });
    }

    for assert_node in children_named(node, "assert") {
        checks.push(convert_check(&assert_node, CheckKind::Assert)?);
    }
    for report_node in children_named(node, "report") {
        checks.push(convert_check(&report_node, CheckKind::Report)?);
    }

    Ok(Rule {
        id,
        context,
        lets,
        checks,
    })
}

fn convert_check(node: &Node<'_, '_>, kind: CheckKind) -> Result<Check, SchematronError> {
    let test_str = node.attribute("test").unwrap_or("");
    let test = parse_predicate(test_str)?;
    let message = text_content(node);

    let severity = match node.attribute("severity") {
        Some("fatal") => Severity::Fatal,
        Some("error") => Severity::Error,
        Some("warning") => Severity::Warning,
        Some("info") => Severity::Info,
        None => match kind {
            CheckKind::Assert => Severity::Error,
            CheckKind::Report => Severity::Info,
        },
        Some(other) => {
            return Err(SchematronError::InvalidValue(format!(
                "unknown severity '{other}'"
            )));
        }
    };

    let flag = node.attribute("flag").unwrap_or("").to_owned();

    let diagnostics: Vec<String> = node
        .attribute("diagnostics")
        .unwrap_or("")
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    Ok(Check {
        kind,
        test,
        message,
        severity,
        flag,
        diagnostics,
    })
}

// -- predicate mini-parser ------------------------------------------
//
// Parses the same predicate syntax as the DSL:
//   exists("path")
//   not_exists("path")
//   equals("path", "value")
//   matches("path", "pattern")
//   count("path", >=, n)
//   not(pred)
//   pred and pred
//   pred or pred

fn parse_predicate(input: &str) -> Result<Predicate, SchematronError> {
    let input = input.trim();
    parse_or_expr(input).map(|(pred, _)| pred)
}

/// Parse an `or` expression (lowest precedence).
fn parse_or_expr(input: &str) -> Result<(Predicate, &str), SchematronError> {
    let (left, rest) = parse_and_expr(input)?;
    let rest = rest.trim_start();
    if let Some(after) = rest.strip_prefix("or ") {
        let (right, rest2) = parse_or_expr(after.trim_start())?;
        Ok((
            Predicate::Or {
                left: Box::new(left),
                right: Box::new(right),
            },
            rest2,
        ))
    } else {
        Ok((left, rest))
    }
}

/// Parse an `and` expression.
fn parse_and_expr(input: &str) -> Result<(Predicate, &str), SchematronError> {
    let (left, rest) = parse_atom(input)?;
    let rest = rest.trim_start();
    if let Some(after) = rest.strip_prefix("and ") {
        let (right, rest2) = parse_and_expr(after.trim_start())?;
        Ok((
            Predicate::And {
                left: Box::new(left),
                right: Box::new(right),
            },
            rest2,
        ))
    } else {
        Ok((left, rest))
    }
}

/// Parse an atomic predicate.
fn parse_atom(input: &str) -> Result<(Predicate, &str), SchematronError> {
    let input = input.trim_start();

    if let Some(rest) = input.strip_prefix("exists") {
        return parse_single_arg(rest.trim_start())
            .map(|(path, r)| (Predicate::Exists { path }, r));
    }
    if let Some(rest) = input.strip_prefix("not_exists") {
        return parse_single_arg(rest.trim_start())
            .map(|(path, r)| (Predicate::NotExists { path }, r));
    }
    if let Some(rest) = input.strip_prefix("equals") {
        return parse_two_args(rest.trim_start())
            .map(|((path, value), r)| (Predicate::Equals { path, value }, r));
    }
    if let Some(rest) = input.strip_prefix("matches") {
        return parse_two_args(rest.trim_start())
            .map(|((path, pattern), r)| (Predicate::Matches { path, pattern }, r));
    }
    if let Some(rest) = input.strip_prefix("count") {
        return parse_count_args(rest.trim_start());
    }
    // not(pred) — must check after not_exists
    if let Some(rest) = input.strip_prefix("not") {
        let rest = rest.trim_start();
        if let Some(inside_parens) = rest.strip_prefix('(') {
            let trimmed = inside_parens.trim_start();
            let (pred, after) = parse_or_expr(trimmed)?;
            let after = after.trim_start();
            if let Some(after_close) = after.strip_prefix(')') {
                return Ok((
                    Predicate::Not {
                        inner: Box::new(pred),
                    },
                    after_close,
                ));
            }
            return Err(SchematronError::Predicate("expected ')' after not".into()));
        }
    }

    Err(SchematronError::Predicate(format!(
        "unrecognised predicate: {input}"
    )))
}

/// Parse `("string")` -> string, rest
fn parse_single_arg(input: &str) -> Result<(String, &str), SchematronError> {
    let input = input.trim_start();
    if !input.starts_with('(') {
        return Err(SchematronError::Predicate("expected '('".into()));
    }
    let inner = &input[1..].trim_start();
    let (val, rest) = parse_quoted_string(inner)?;
    let rest = rest.trim_start();
    if !rest.starts_with(')') {
        return Err(SchematronError::Predicate("expected ')'".into()));
    }
    Ok((val, &rest[1..]))
}

/// Parse `("s1", "s2")` -> (s1, s2), rest
fn parse_two_args(input: &str) -> Result<((String, String), &str), SchematronError> {
    let input = input.trim_start();
    if !input.starts_with('(') {
        return Err(SchematronError::Predicate("expected '('".into()));
    }
    let inner = &input[1..].trim_start();
    let (a, rest) = parse_quoted_string(inner)?;
    let rest = rest.trim_start();
    if !rest.starts_with(',') {
        return Err(SchematronError::Predicate("expected ','".into()));
    }
    let rest = &rest[1..].trim_start();
    let (b, rest) = parse_quoted_string(rest)?;
    let rest = rest.trim_start();
    if !rest.starts_with(')') {
        return Err(SchematronError::Predicate("expected ')'".into()));
    }
    Ok(((a, b), &rest[1..]))
}

/// Parse `("path", >=, n)` -> Count predicate
fn parse_count_args(input: &str) -> Result<(Predicate, &str), SchematronError> {
    let input = input.trim_start();
    if !input.starts_with('(') {
        return Err(SchematronError::Predicate("expected '('".into()));
    }
    let inner = &input[1..].trim_start();
    let (path, rest) = parse_quoted_string(inner)?;

    let rest = rest.trim_start();
    if !rest.starts_with(',') {
        return Err(SchematronError::Predicate("expected ','".into()));
    }
    let rest = &rest[1..].trim_start();

    // Parse comparison operator
    let (cmp, rest) = parse_cmp_op(rest)?;

    let rest = rest.trim_start();
    if !rest.starts_with(',') {
        return Err(SchematronError::Predicate("expected ','".into()));
    }
    let rest = &rest[1..].trim_start();

    // Parse number
    let num_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if num_end == 0 {
        return Err(SchematronError::Predicate("expected number".into()));
    }
    let expected: usize = rest[..num_end]
        .parse()
        .map_err(|_| SchematronError::Predicate("invalid number".into()))?;
    let rest = rest[num_end..].trim_start();

    if !rest.starts_with(')') {
        return Err(SchematronError::Predicate("expected ')'".into()));
    }

    Ok((
        Predicate::Count {
            path,
            cmp,
            expected,
        },
        &rest[1..],
    ))
}

fn parse_cmp_op(input: &str) -> Result<(Comparison, &str), SchematronError> {
    if let Some(rest) = input.strip_prefix(">=") {
        return Ok((Comparison::Ge, rest));
    }
    if let Some(rest) = input.strip_prefix("<=") {
        return Ok((Comparison::Le, rest));
    }
    if let Some(rest) = input.strip_prefix("!=") {
        return Ok((Comparison::Ne, rest));
    }
    if let Some(rest) = input.strip_prefix("==") {
        return Ok((Comparison::Eq, rest));
    }
    if let Some(rest) = input.strip_prefix('>') {
        return Ok((Comparison::Gt, rest));
    }
    if let Some(rest) = input.strip_prefix('<') {
        return Ok((Comparison::Lt, rest));
    }
    Err(SchematronError::Predicate(
        "expected comparison operator".into(),
    ))
}

/// Parse a `"quoted string"`, returning contents and remaining input.
fn parse_quoted_string(input: &str) -> Result<(String, &str), SchematronError> {
    let input = input.trim_start();

    let quote = if input.starts_with('"') {
        '"'
    } else if input.starts_with('\'') {
        '\''
    } else {
        return Err(SchematronError::Predicate("expected quoted string".into()));
    };

    let inner = &input[1..];
    let mut result = String::new();
    let mut chars = inner.char_indices();
    loop {
        match chars.next() {
            None => {
                return Err(SchematronError::Predicate("unterminated string".into()));
            }
            Some((_, '\\')) => match chars.next() {
                Some((_, c)) => result.push(c),
                None => {
                    return Err(SchematronError::Predicate("unterminated escape".into()));
                }
            },
            Some((i, c)) if c == quote => {
                return Ok((result, &inner[i + 1..]));
            }
            Some((_, c)) => result.push(c),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::rule::{CheckKind, Comparison, Severity};

    #[test]
    fn parse_complete_schematron() {
        let xml = r#"
<schema xmlns="http://purl.oclc.org/dsdl/schematron">
  <title>CSAF Checks</title>
  <phase id="quick">
    <active pattern="required"/>
  </phase>
  <diagnostics>
    <diagnostic id="d1">See spec section 4.2</diagnostic>
    <diagnostic id="d2">Contact admin</diagnostic>
  </diagnostics>
  <pattern id="required-fields">
    <title>Required fields</title>
    <rule context="$">
      <let name="items" value="$..item"/>
      <assert test="exists('$.document')" severity="error" flag="security" diagnostics="d1">
        Document root must contain a 'document' object
      </assert>
      <report test="exists('$.metadata')" severity="info">
        Has metadata
      </report>
    </rule>
  </pattern>
  <pattern id="format-checks">
    <rule context="$.document">
      <assert test="matches('$.title', '^[A-Z]')" severity="warning">
        Title should start with uppercase
      </assert>
    </rule>
  </pattern>
</schema>
"#;
        let schema = parse_schematron(xml).unwrap();

        assert_eq!(schema.title, "CSAF Checks");

        // Phases
        assert_eq!(schema.phases.len(), 1);
        assert_eq!(schema.phases[0].name, "quick");
        assert_eq!(schema.phases[0].active_patterns, vec!["required"]);

        // Diagnostics
        assert_eq!(schema.diagnostics.len(), 2);
        assert_eq!(schema.diagnostics[0].id, "d1");
        assert_eq!(schema.diagnostics[0].message, "See spec section 4.2");

        // Patterns
        assert_eq!(schema.patterns.len(), 2);
        assert_eq!(schema.patterns[0].name, "required-fields");
        assert_eq!(schema.patterns[0].title, "Required fields");

        // Rules
        let rule = &schema.patterns[0].rules[0];
        assert_eq!(rule.context, "$");
        assert_eq!(rule.lets.len(), 1);
        assert_eq!(rule.lets[0].name, "items");
        assert_eq!(rule.lets[0].path, "$..item");

        // Checks
        assert_eq!(rule.checks.len(), 2);
        let assert_check = &rule.checks[0];
        assert_eq!(assert_check.kind, CheckKind::Assert);
        assert_eq!(assert_check.severity, Severity::Error);
        assert_eq!(assert_check.flag, "security");
        assert_eq!(assert_check.diagnostics, vec!["d1"]);
        assert!(assert_check.message.contains("document"));

        let report_check = &rule.checks[1];
        assert_eq!(report_check.kind, CheckKind::Report);
        assert_eq!(report_check.severity, Severity::Info);
    }

    #[test]
    fn parse_minimal_schema() {
        let xml = r#"
<schema xmlns="http://purl.oclc.org/dsdl/schematron">
  <title>Minimal</title>
  <pattern id="p">
    <rule context="$">
      <assert test="exists('$.name')">must have name</assert>
    </rule>
  </pattern>
</schema>
"#;
        let schema = parse_schematron(xml).unwrap();
        assert_eq!(schema.title, "Minimal");
        assert_eq!(schema.patterns.len(), 1);
        assert_eq!(schema.patterns[0].rules[0].checks.len(), 1);
    }

    #[test]
    fn parse_with_let_bindings() {
        let xml = r#"
<schema xmlns="http://purl.oclc.org/dsdl/schematron">
  <title>Lets</title>
  <pattern id="p">
    <rule context="$">
      <let name="items" value="$..item"/>
      <let name="tags" value="$..tag"/>
      <assert test="exists('$.name')">must have name</assert>
    </rule>
  </pattern>
</schema>
"#;
        let schema = parse_schematron(xml).unwrap();
        let rule = &schema.patterns[0].rules[0];
        assert_eq!(rule.lets.len(), 2);
        assert_eq!(rule.lets[0].name, "items");
        assert_eq!(rule.lets[0].path, "$..item");
        assert_eq!(rule.lets[1].name, "tags");
        assert_eq!(rule.lets[1].path, "$..tag");
    }

    #[test]
    fn error_on_invalid_xml() {
        let xml = "<schema><not closed";
        let result = parse_schematron(xml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SchematronError::Xml(_)),
            "expected Xml error, got: {err}"
        );
    }

    #[test]
    fn parse_count_predicate() {
        let xml = r#"
<schema xmlns="http://purl.oclc.org/dsdl/schematron">
  <title>Count</title>
  <pattern id="p">
    <rule context="$">
      <assert test="count('$.items[*]', >=, 2)">
        Need at least 2 items
      </assert>
    </rule>
  </pattern>
</schema>
"#;
        let schema = parse_schematron(xml).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        match &check.test {
            Predicate::Count {
                path,
                cmp,
                expected,
            } => {
                assert_eq!(path, "$.items[*]");
                assert_eq!(*cmp, Comparison::Ge);
                assert_eq!(*expected, 2);
            }
            other => panic!("expected Count, got: {other:?}"),
        }
    }

    #[test]
    fn parse_logical_predicates() {
        let xml = r#"
<schema xmlns="http://purl.oclc.org/dsdl/schematron">
  <title>Logic</title>
  <pattern id="p">
    <rule context="$">
      <assert test="exists('$.a') and exists('$.b')">
        Need both
      </assert>
    </rule>
  </pattern>
</schema>
"#;
        let schema = parse_schematron(xml).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        assert!(
            matches!(&check.test, Predicate::And { .. }),
            "expected And, got: {:?}",
            check.test
        );
    }

    #[test]
    fn parse_schema_without_namespace() {
        let xml = r#"
<schema>
  <title>No NS</title>
  <pattern id="p">
    <rule context="$">
      <assert test="exists('$.x')">need x</assert>
    </rule>
  </pattern>
</schema>
"#;
        let schema = parse_schematron(xml).unwrap();
        assert_eq!(schema.title, "No NS");
    }

    #[test]
    fn parse_title_from_attr() {
        let xml = r#"
<schema title="Attr Title" xmlns="http://purl.oclc.org/dsdl/schematron">
  <pattern id="p">
    <rule context="$">
      <assert test="exists('$.x')">need x</assert>
    </rule>
  </pattern>
</schema>
"#;
        let schema = parse_schematron(xml).unwrap();
        assert_eq!(schema.title, "Attr Title");
    }

    #[test]
    fn parse_not_predicate() {
        let xml = r#"
<schema xmlns="http://purl.oclc.org/dsdl/schematron">
  <title>Not</title>
  <pattern id="p">
    <rule context="$">
      <assert test="not(exists('$.bad'))">bad must not exist</assert>
    </rule>
  </pattern>
</schema>
"#;
        let schema = parse_schematron(xml).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        assert!(
            matches!(&check.test, Predicate::Not { .. }),
            "expected Not, got: {:?}",
            check.test
        );
    }

    #[test]
    fn parse_equals_predicate() {
        let xml = r#"
<schema xmlns="http://purl.oclc.org/dsdl/schematron">
  <title>Eq</title>
  <pattern id="p">
    <rule context="$">
      <assert test="equals('$.status', 'active')">must be active</assert>
    </rule>
  </pattern>
</schema>
"#;
        let schema = parse_schematron(xml).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        match &check.test {
            Predicate::Equals { path, value } => {
                assert_eq!(path, "$.status");
                assert_eq!(value, "active");
            }
            other => panic!("expected Equals, got: {other:?}"),
        }
    }
}
