//! Parser for `.scheck` rule files.
//!
//! Uses an ixml grammar (via `txt2data`) to parse the DSL into a
//! native parse tree, then converts the tree into `Schema` structs.
//!
//! Full grammar (inspired by ISO Schematron):
//!
//! ```text
//! schema <title> {
//!   description <string>;
//!   default_phase <name>;
//!
//!   phase <name> {
//!     description <string>;
//!     active <pattern-name>;
//!     active <pattern-name>;
//!   }
//!
//!   diagnostics {
//!     diagnostic <id> <message>;
//!   }
//!
//!   pattern <name> {
//!     title <string>;
//!
//!     rule context=<path> {
//!       let <name> = <path>;
//!
//!       assert <predicate>
//!         message=<string>
//!         severity=<error|warning|info|fatal>
//!         flag=<string>
//!         diagnostic=<id>;
//!
//!       report <predicate>
//!         message=<string>
//!         severity=<info>;
//!     }
//!   }
//! }
//! ```
//!
//! Predicates:
//!   `exists(<path>)`
//!   `not_exists(<path>)`
//!   `equals(<path>, <string>)`
//!   `matches(<path>, <regex>)`
//!   `count(<path>, <cmp>, <n>)`
//!   `not(<pred>)`
//!   `<pred> and <pred>`
//!   `<pred> or <pred>`

use txt2data::{Mark, TreeNode};

use crate::rule::{
    Check, CheckKind, Comparison, DiagnosticDef, LetBinding, Pattern, Phase, Predicate, Rule,
    Schema, Severity,
};

/// ixml grammar for the `.scheck` DSL.
///
/// Key design decisions for `txt2data`'s Earley parser:
/// - Use `+` (not `*`) for content nested inside other repeated
///   blocks to avoid ambiguous nested-star failures.
/// - Use `-s` (required whitespace) between keywords and `-ss`
///   (optional whitespace) around operators/delimiters.
/// - Every repeated item ends with trailing `-ss` so the `+`
///   repetition can consume inter-item whitespace.
/// - String chars use `-sc` (hidden rule with alternation) to
///   handle plain chars and escape sequences.
/// - Comments are `#` followed by at least one non-newline char,
///   then a newline.
const GRAMMAR: &str = r##"
schema: -ss, -"schema", -s, @title, -ss, -"{", -ss, schema_item+, -ss, -"}", -ss.
@title: -'"', -sc+, -'"'.

-schema_item: description_decl; default_phase_decl; phase_decl; diagnostics_block; pat.

description_decl: -"description", -s, @desc_val, -ss, -";", -ss.
@desc_val: -'"', -sc+, -'"'.

default_phase_decl: -"default_phase", -s, @dp_val, -ss, -";", -ss.
@dp_val: -'"', -sc+, -'"'.

phase_decl: -"phase", -s, @phase_name, -ss, -"{", -ss, phase_item+, -ss, -"}", -ss.
@phase_name: -'"', -sc+, -'"'.
-phase_item: phase_desc; phase_active.
phase_desc: -"description", -s, @pdesc_val, -ss, -";", -ss.
@pdesc_val: -'"', -sc+, -'"'.
phase_active: -"active", -s, @pactive_val, -ss, -";", -ss.
@pactive_val: -'"', -sc+, -'"'.

diagnostics_block: -"diagnostics", -ss, -"{", -ss, diagnostic_def+, -ss, -"}", -ss.
diagnostic_def: -"diagnostic", -s, @diag_id, -s, @diag_msg, -ss, -";", -ss.
@diag_id: -'"', -sc+, -'"'.
@diag_msg: -'"', -sc+, -'"'.

pat: -"pattern", -s, @name, -ss, -"{", -ss, pat_item+, -ss, -"}", -ss.
@name: -'"', -sc+, -'"'.
-pat_item: title_decl; rul.

title_decl: -"title", -s, @title_val, -ss, -";", -ss.
@title_val: -'"', -sc+, -'"'.

rul: -"rule", -s, rul_id, -"context", -ss, -"=", -ss, @ctx, -ss, -"{", -ss, rul_item+, -ss, -"}", -ss.
rul_id: @rid, -s; .
@rid: -'"', -sc+, -'"'.
@ctx: -'"', -sc+, -'"'.

-rul_item: let_bind; assert_chk; report_chk.

let_bind: -"let", -s, @let_name, -ss, -"=", -ss, @let_path, -ss, -";", -ss.
@let_name: ["a"-"z"; "A"-"Z"; "_"; "0"-"9"; "-"]+.
@let_path: -'"', -sc+, -'"'.

assert_chk: -"assert", -s, pred, -ss, -"message", -ss, -"=", -ss, @msg, chk_opts, -ss, -";", -ss.
report_chk: -"report", -s, pred, -ss, -"message", -ss, -"=", -ss, @msg, chk_opts, -ss, -";", -ss.
@msg: -'"', -sc+, -'"'.

chk_opts: -ss, chk_opt, chk_opts; .
-chk_opt: severity_opt; flag_opt; diagnostic_opt.
severity_opt: -"severity", -ss, -"=", -ss, @sev_val.
@sev_val: "fatal"; "error"; "warning"; "info".
flag_opt: -"flag", -ss, -"=", -ss, @flag_val.
@flag_val: -'"', -sc+, -'"'.
diagnostic_opt: -"diagnostic", -ss, -"=", -ss, @diagref_val.
@diagref_val: -'"', -sc+, -'"'.

pred: and_pred; or_pred; pred_atom.
and_pred: pred_atom, -s, -"and", -s, pred.
or_pred: pred_atom, -s, -"or", -s, pred.
-pred_atom: exists_p; not_exists_p; equals_p; matches_p; count_p; not_p.

exists_p: -"exists", -ss, -"(", -ss, @ppath, -ss, -")".
not_exists_p: -"not_exists", -ss, -"(", -ss, @ppath, -ss, -")".
equals_p: -"equals", -ss, -"(", -ss, @epath, -ss, -",", -ss, @eval, -ss, -")".
@epath: -'"', -sc+, -'"'.
@eval: -'"', -sc+, -'"'.
matches_p: -"matches", -ss, -"(", -ss, @mpath, -ss, -",", -ss, @mpat, -ss, -")".
@mpath: -'"', -sc+, -'"'.
@mpat: -'"', -sc+, -'"'.
count_p: -"count", -ss, -"(", -ss, @cpath, -ss, -",", -ss, @cmp_op, -ss, -",", -ss, @cmp_n, -ss, -")".
@cpath: -'"', -sc+, -'"'.
@cmp_op: ">="; "<="; "!="; "=="; ">"; "<".
@cmp_n: ["0"-"9"]+.
not_p: -"not", -ss, -"(", -ss, pred, -ss, -")".

@ppath: -'"', -sc+, -'"'.

-sc: ~['"'; #5C]; #5C, [#5C; '"'; "n"; "t"].
-s: -wsc+.
-ss: -wsc*.
-wsc: [" "; #0A; #0D; #09]; -"#", -cmtc+, -#0A.
-cmtc: ~[#0A].
"##;

/// Parse a `.scheck` rule file into a Schema.
///
/// # Errors
///
/// Returns an error if the rule file has syntax errors.
pub fn parse_schema(input: &str) -> Result<Schema, ParseError> {
    let grammar = txt2data::parse_grammar(GRAMMAR).map_err(|e| ParseError {
        message: format!("internal: bad grammar: {e}"),
        line: 1,
        col: 1,
    })?;
    let parser = txt2data::Parser::new(&grammar);
    let tree = parser
        .parse(input)
        .map_err(|e| make_parse_error(input, &e.to_string()))?;
    convert_schema(&tree.root)
}

// -- Error helpers -----------------------------------------------

fn make_parse_error(input: &str, msg: &str) -> ParseError {
    let pos = extract_position(msg);
    let (line, col) = offset_to_line_col(input, pos);
    ParseError {
        message: simplify_error(msg),
        line,
        col,
    }
}

fn extract_position(msg: &str) -> usize {
    // txt2data errors: "parse failed at position N: ..."
    msg.find("position ")
        .and_then(|i| {
            let rest = &msg[i + 9..];
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            rest[..end].parse().ok()
        })
        .unwrap_or(0)
}

fn simplify_error(msg: &str) -> String {
    if let Some(idx) = msg.find("position ") {
        let after = &msg[idx..];
        if let Some(colon) = after.find(": ") {
            let expected = &after[colon + 2..];
            return format!("syntax error: expected {expected}");
        }
    }
    msg.to_owned()
}

fn offset_to_line_col(input: &str, offset: usize) -> (usize, usize) {
    let clamped = offset.min(input.len());
    let line = input[..clamped].chars().filter(|&c| c == '\n').count() + 1;
    let col = clamped - input[..clamped].rfind('\n').map_or(0, |p| p + 1) + 1;
    (line, col)
}

// -- TreeNode helpers --------------------------------------------

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
                return Some(unescape(&collect_text(attr_children)));
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

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') | None => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn err(msg: impl Into<String>) -> ParseError {
    ParseError {
        message: msg.into(),
        line: 0,
        col: 0,
    }
}

// -- Schema conversion -------------------------------------------

fn convert_schema(root: &TreeNode) -> Result<Schema, ParseError> {
    let title = get_attr(root, "title");
    if title.is_empty() {
        return Err(err("missing schema title"));
    }

    let mut description = String::new();
    let mut default_phase = String::new();
    let mut phases = Vec::new();
    let mut diagnostics = Vec::new();
    let mut patterns = Vec::new();

    for dd in find_children(root, "description_decl") {
        description = get_attr(dd, "desc_val");
    }
    for dp in find_children(root, "default_phase_decl") {
        default_phase = get_attr(dp, "dp_val");
    }
    for ph in find_children(root, "phase_decl") {
        phases.push(convert_phase(ph));
    }
    for db in find_children(root, "diagnostics_block") {
        for dd in find_children(db, "diagnostic_def") {
            diagnostics.push(DiagnosticDef {
                id: get_attr(dd, "diag_id"),
                message: get_attr(dd, "diag_msg"),
            });
        }
    }
    for p in find_children(root, "pat") {
        patterns.push(convert_pattern(p)?);
    }

    Ok(Schema {
        title,
        description,
        default_phase,
        phases,
        diagnostics,
        patterns,
    })
}

fn convert_phase(node: &TreeNode) -> Phase {
    let name = get_attr(node, "phase_name");
    let mut description = String::new();
    let mut active_patterns = Vec::new();

    for pd in find_children(node, "phase_desc") {
        description = get_attr(pd, "pdesc_val");
    }
    for pa in find_children(node, "phase_active") {
        active_patterns.push(get_attr(pa, "pactive_val"));
    }

    Phase {
        name,
        description,
        active_patterns,
    }
}

fn convert_pattern(node: &TreeNode) -> Result<Pattern, ParseError> {
    let name = get_attr(node, "name");
    let mut title = String::new();
    let mut rules = Vec::new();

    for td in find_children(node, "title_decl") {
        title = get_attr(td, "title_val");
    }
    for r in find_children(node, "rul") {
        rules.push(convert_rule(r)?);
    }

    Ok(Pattern { name, title, rules })
}

fn convert_rule(node: &TreeNode) -> Result<Rule, ParseError> {
    let id = find_child(node, "rul_id")
        .map(|ri| get_attr(ri, "rid"))
        .unwrap_or_default();
    let context = get_attr(node, "ctx");

    let mut lets = Vec::new();
    let mut checks = Vec::new();

    for lb in find_children(node, "let_bind") {
        lets.push(LetBinding {
            name: get_attr(lb, "let_name"),
            path: get_attr(lb, "let_path"),
        });
    }
    for ac in find_children(node, "assert_chk") {
        checks.push(convert_check(ac, CheckKind::Assert)?);
    }
    for rc in find_children(node, "report_chk") {
        checks.push(convert_check(rc, CheckKind::Report)?);
    }

    Ok(Rule {
        id,
        context,
        lets,
        checks,
    })
}

fn convert_check(node: &TreeNode, kind: CheckKind) -> Result<Check, ParseError> {
    let pred_node = find_child(node, "pred").ok_or_else(|| err("check missing predicate"))?;
    let test = convert_predicate(pred_node)?;
    let message = get_attr(node, "msg");

    let default_sev = match kind {
        CheckKind::Assert => Severity::Error,
        CheckKind::Report => Severity::Info,
    };
    let mut severity = default_sev;
    let mut flag = String::new();
    let mut diagnostics_refs = Vec::new();

    collect_check_opts(
        find_child(node, "chk_opts"),
        &mut severity,
        &mut flag,
        &mut diagnostics_refs,
    );

    Ok(Check {
        kind,
        test,
        message,
        severity,
        flag,
        diagnostics: diagnostics_refs,
    })
}

fn collect_check_opts(
    node: Option<&TreeNode>,
    severity: &mut Severity,
    flag: &mut String,
    diagnostics: &mut Vec<String>,
) {
    let Some(opts) = node else { return };

    if let Some(so) = find_child(opts, "severity_opt") {
        let val = get_attr(so, "sev_val");
        *severity = match val.as_str() {
            "fatal" => Severity::Fatal,
            "warning" => Severity::Warning,
            "info" => Severity::Info,
            _ => Severity::Error,
        };
    }
    if let Some(fo) = find_child(opts, "flag_opt") {
        *flag = get_attr(fo, "flag_val");
    }
    if let Some(d) = find_child(opts, "diagnostic_opt") {
        diagnostics.push(get_attr(d, "diagref_val"));
    }

    // chk_opts is recursive: chk_opts -> chk_opt, chk_opts
    collect_check_opts(find_child(opts, "chk_opts"), severity, flag, diagnostics);
}

fn convert_predicate(node: &TreeNode) -> Result<Predicate, ParseError> {
    if let Some(ep) = find_child(node, "exists_p") {
        return Ok(Predicate::Exists {
            path: get_attr(ep, "ppath"),
        });
    }
    if let Some(nep) = find_child(node, "not_exists_p") {
        return Ok(Predicate::NotExists {
            path: get_attr(nep, "ppath"),
        });
    }
    if let Some(eq) = find_child(node, "equals_p") {
        return Ok(Predicate::Equals {
            path: get_attr(eq, "epath"),
            value: get_attr(eq, "eval"),
        });
    }
    if let Some(mp) = find_child(node, "matches_p") {
        return Ok(Predicate::Matches {
            path: get_attr(mp, "mpath"),
            pattern: get_attr(mp, "mpat"),
        });
    }
    if let Some(cp) = find_child(node, "count_p") {
        let cmp = match get_attr(cp, "cmp_op").as_str() {
            "==" => Comparison::Eq,
            "!=" => Comparison::Ne,
            "<" => Comparison::Lt,
            "<=" => Comparison::Le,
            ">" => Comparison::Gt,
            ">=" => Comparison::Ge,
            other => {
                return Err(err(format!("unknown comparison '{other}'")));
            }
        };
        let expected: usize = get_attr(cp, "cmp_n")
            .parse()
            .map_err(|_| err("invalid count number"))?;
        return Ok(Predicate::Count {
            path: get_attr(cp, "cpath"),
            cmp,
            expected,
        });
    }
    if let Some(np) = find_child(node, "not_p") {
        let inner_pred = find_child(np, "pred").ok_or_else(|| err("not() missing predicate"))?;
        return Ok(Predicate::Not {
            inner: Box::new(convert_predicate(inner_pred)?),
        });
    }
    if let Some(ap) = find_child(node, "and_pred") {
        let left = convert_pred_atom(ap)?;
        let right_node = find_child(ap, "pred").ok_or_else(|| err("and missing right operand"))?;
        let right = convert_predicate(right_node)?;
        return Ok(Predicate::And {
            left: Box::new(left),
            right: Box::new(right),
        });
    }
    if let Some(op) = find_child(node, "or_pred") {
        let left = convert_pred_atom(op)?;
        let right_node = find_child(op, "pred").ok_or_else(|| err("or missing right operand"))?;
        let right = convert_predicate(right_node)?;
        return Ok(Predicate::Or {
            left: Box::new(left),
            right: Box::new(right),
        });
    }

    Err(err("unrecognised predicate"))
}

/// Extract the atomic predicate from an and/or node.
///
/// An `and_pred` or `or_pred` node contains the left-hand atom
/// directly (as `exists_p`, `not_exists_p`, etc.) alongside the
/// `pred` child which holds the right-hand operand.
fn convert_pred_atom(node: &TreeNode) -> Result<Predicate, ParseError> {
    if let Some(ep) = find_child(node, "exists_p") {
        return Ok(Predicate::Exists {
            path: get_attr(ep, "ppath"),
        });
    }
    if let Some(nep) = find_child(node, "not_exists_p") {
        return Ok(Predicate::NotExists {
            path: get_attr(nep, "ppath"),
        });
    }
    if let Some(eq) = find_child(node, "equals_p") {
        return Ok(Predicate::Equals {
            path: get_attr(eq, "epath"),
            value: get_attr(eq, "eval"),
        });
    }
    if let Some(mp) = find_child(node, "matches_p") {
        return Ok(Predicate::Matches {
            path: get_attr(mp, "mpath"),
            pattern: get_attr(mp, "mpat"),
        });
    }
    if let Some(cp) = find_child(node, "count_p") {
        let cmp = match get_attr(cp, "cmp_op").as_str() {
            "==" => Comparison::Eq,
            "!=" => Comparison::Ne,
            "<" => Comparison::Lt,
            "<=" => Comparison::Le,
            ">" => Comparison::Gt,
            ">=" => Comparison::Ge,
            other => {
                return Err(err(format!("unknown comparison '{other}'")));
            }
        };
        let expected: usize = get_attr(cp, "cmp_n")
            .parse()
            .map_err(|_| err("invalid count number"))?;
        return Ok(Predicate::Count {
            path: get_attr(cp, "cpath"),
            cmp,
            expected,
        });
    }
    if let Some(np) = find_child(node, "not_p") {
        let inner_pred = find_child(np, "pred").ok_or_else(|| err("not() missing predicate"))?;
        return Ok(Predicate::Not {
            inner: Box::new(convert_predicate(inner_pred)?),
        });
    }
    Err(err("unrecognised predicate atom"))
}

/// Error from parsing a `.scheck` rule file.
#[derive(Debug, thiserror::Error)]
#[error("line {line}:{col}: {message}")]
pub struct ParseError {
    pub message: String,
    pub line: usize,
    pub col: usize,
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_schema() {
        let input = r#"
            schema "test" {
                pattern "basics" {
                    rule context="$.root" {
                        assert exists("$.name")
                            message="must have name"
                            severity=error;
                    }
                }
            }
        "#;
        let schema = parse_schema(input).unwrap();
        assert_eq!(schema.title, "test");
        assert_eq!(schema.patterns.len(), 1);
        assert_eq!(schema.patterns[0].rules.len(), 1);
        assert_eq!(schema.patterns[0].rules[0].checks.len(), 1);
    }

    #[test]
    fn parse_assert_and_report() {
        let input = r#"
            schema "mixed" {
                pattern "p" {
                    rule context="$" {
                        assert exists("$.required")
                            message="required field missing";
                        report exists("$.deprecated")
                            message="deprecated field present"
                            severity=warning;
                    }
                }
            }
        "#;
        let schema = parse_schema(input).unwrap();
        let checks = &schema.patterns[0].rules[0].checks;
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].kind, CheckKind::Assert);
        assert_eq!(checks[0].severity, Severity::Error);
        assert_eq!(checks[1].kind, CheckKind::Report);
        assert_eq!(checks[1].severity, Severity::Warning);
    }

    #[test]
    fn parse_phases() {
        let input = r#"
            schema "phased" {
                default_phase "quick";

                phase "quick" {
                    description "fast checks only";
                    active "required-fields";
                }

                phase "full" {
                    description "all checks";
                    active "required-fields";
                    active "format-checks";
                }

                pattern "required-fields" {
                    rule context="$" {
                        assert exists("$.id")
                            message="missing id";
                    }
                }

                pattern "format-checks" {
                    rule context="$" {
                        assert matches("$.id", "^[A-Z]")
                            message="id must start uppercase";
                    }
                }
            }
        "#;
        let schema = parse_schema(input).unwrap();
        assert_eq!(schema.default_phase, "quick");
        assert_eq!(schema.phases.len(), 2);
        assert_eq!(schema.phases[0].active_patterns.len(), 1);
        assert_eq!(schema.phases[1].active_patterns.len(), 2);

        let quick = schema.active_patterns("quick");
        assert_eq!(quick.len(), 1);
        assert_eq!(quick[0].name, "required-fields");

        let full = schema.active_patterns("full");
        assert_eq!(full.len(), 2);
    }

    #[test]
    fn parse_let_bindings() {
        let input = r#"
            schema "lets" {
                pattern "p" {
                    rule context="$" {
                        let items = "$..item";
                        assert count("$..item", >=, 1)
                            message="need items";
                    }
                }
            }
        "#;
        let schema = parse_schema(input).unwrap();
        let rule = &schema.patterns[0].rules[0];
        assert_eq!(rule.lets.len(), 1);
        assert_eq!(rule.lets[0].name, "items");
    }

    #[test]
    fn parse_diagnostics() {
        let input = r#"
            schema "diags" {
                diagnostics {
                    diagnostic "d1" "See section 4.2 of the spec";
                    diagnostic "d2" "Contact admin for help";
                }

                pattern "p" {
                    rule context="$" {
                        assert exists("$.name")
                            message="name required"
                            diagnostic="d1";
                    }
                }
            }
        "#;
        let schema = parse_schema(input).unwrap();
        assert_eq!(schema.diagnostics.len(), 2);
        assert_eq!(schema.diagnostic("d1"), Some("See section 4.2 of the spec"));
        let check = &schema.patterns[0].rules[0].checks[0];
        assert_eq!(check.diagnostics, vec!["d1"]);
    }

    #[test]
    fn parse_flags() {
        let input = r#"
            schema "flagged" {
                pattern "p" {
                    rule context="$" {
                        assert exists("$.critical")
                            message="missing"
                            severity=fatal
                            flag="security";
                    }
                }
            }
        "#;
        let schema = parse_schema(input).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        assert_eq!(check.severity, Severity::Fatal);
        assert_eq!(check.flag, "security");
    }

    #[test]
    fn parse_pattern_title() {
        let input = r#"
            schema "titled" {
                description "A test schema";

                pattern "p" {
                    title "Required fields must exist";
                    rule context="$" {
                        assert exists("$.x")
                            message="need x";
                    }
                }
            }
        "#;
        let schema = parse_schema(input).unwrap();
        assert_eq!(schema.description, "A test schema");
        assert_eq!(schema.patterns[0].title, "Required fields must exist");
    }

    #[test]
    fn parse_comments() {
        let input = r#"
            # Top-level comment
            schema "commented" {
                # Phase comment
                pattern "p" {
                    # Rule comment
                    rule context="$" {
                        # Assert comment
                        assert exists("$.name")
                            message="need name";
                    }
                }
            }
        "#;
        let schema = parse_schema(input).unwrap();
        assert_eq!(schema.title, "commented");
    }

    #[test]
    fn parse_count_predicate() {
        let input = r#"
            schema "count" {
                pattern "p" {
                    rule context="$.root" {
                        assert count("$.items", >=, 1)
                            message="need items";
                    }
                }
            }
        "#;
        let schema = parse_schema(input).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        assert!(matches!(
            &check.test,
            Predicate::Count {
                cmp: Comparison::Ge,
                expected: 1,
                ..
            }
        ));
    }

    #[test]
    fn parse_logical_connectives() {
        let input = r#"
            schema "logic" {
                pattern "p" {
                    rule context="$.root" {
                        assert exists("$.a") and exists("$.b")
                            message="need both";
                    }
                }
            }
        "#;
        let schema = parse_schema(input).unwrap();
        let check = &schema.patterns[0].rules[0].checks[0];
        assert!(matches!(&check.test, Predicate::And { .. }));
    }

    #[test]
    fn parse_error_reports_location() {
        let input = "schema \"test\" {\n  bad_token\n}";
        let err = parse_schema(input).unwrap_err();
        assert!(err.line >= 2);
    }
}
