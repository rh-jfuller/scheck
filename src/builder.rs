//! Builder API for constructing schemas from Rust code.
//!
//! Provides a fluent, type-safe interface for building validation
//! rules without parsing DSL or JSON:
//!
//! ```rust
//! use scheck::builder::*;
//! use scheck::Severity;
//!
//! let schema = schema("CSAF Checks")
//!     .pattern("required-fields", |p| p
//!         .title("Core required fields")
//!         .rule("$", |r| r
//!             .assert(exists("$.document"), "must have document")
//!             .assert(
//!                 matches("$.document.tracking.id", "^[A-Z]"),
//!                 "tracking ID must start uppercase",
//!             )
//!             .report_with(
//!                 exists("$.vulnerabilities"),
//!                 "has vulnerabilities",
//!                 Severity::Info,
//!             )
//!         )
//!     )
//!     .build();
//! ```

use crate::rule::{
    Check, CheckKind, Comparison, DiagnosticDef, LetBinding, Pattern, Phase, Predicate, Rule,
    Schema, Severity,
};

// -- Predicate constructors -----------------------------------------------

/// Node at path must exist.
#[must_use]
pub fn exists(path: &str) -> Predicate {
    Predicate::Exists {
        path: path.to_owned(),
    }
}

/// Node at path must not exist.
#[must_use]
pub fn not_exists(path: &str) -> Predicate {
    Predicate::NotExists {
        path: path.to_owned(),
    }
}

/// Scalar at path must equal value.
#[must_use]
pub fn equals(path: &str, value: &str) -> Predicate {
    Predicate::Equals {
        path: path.to_owned(),
        value: value.to_owned(),
    }
}

/// Scalar at path must match regex.
#[must_use]
pub fn matches(path: &str, pattern: &str) -> Predicate {
    Predicate::Matches {
        path: path.to_owned(),
        pattern: pattern.to_owned(),
    }
}

/// Count of nodes at path must satisfy comparison.
#[must_use]
pub fn count(path: &str, cmp: Comparison, expected: usize) -> Predicate {
    Predicate::Count {
        path: path.to_owned(),
        cmp,
        expected,
    }
}

/// Logical AND of two predicates.
#[must_use]
pub fn and(left: Predicate, right: Predicate) -> Predicate {
    Predicate::And {
        left: Box::new(left),
        right: Box::new(right),
    }
}

/// Logical OR of two predicates.
#[must_use]
pub fn or(left: Predicate, right: Predicate) -> Predicate {
    Predicate::Or {
        left: Box::new(left),
        right: Box::new(right),
    }
}

/// Logical NOT of a predicate.
#[must_use]
pub fn not(inner: Predicate) -> Predicate {
    Predicate::Not {
        inner: Box::new(inner),
    }
}

/// Value at path must be a valid email address.
#[must_use]
pub fn is_email(path: &str) -> Predicate {
    Predicate::Named {
        name: "email".to_owned(),
        path: path.to_owned(),
    }
}

/// Value at path must be an HTTP(S) URL.
#[must_use]
pub fn is_url(path: &str) -> Predicate {
    Predicate::Named {
        name: "url".to_owned(),
        path: path.to_owned(),
    }
}

/// Value at path must be a CVE identifier (CVE-YYYY-NNNNN+).
#[must_use]
pub fn is_cve_id(path: &str) -> Predicate {
    Predicate::Named {
        name: "cve_id".to_owned(),
        path: path.to_owned(),
    }
}

/// Value at path must be a Package URL (pkg: scheme).
#[must_use]
pub fn is_purl(path: &str) -> Predicate {
    Predicate::Named {
        name: "purl".to_owned(),
        path: path.to_owned(),
    }
}

/// Value at path must be a semantic version (X.Y.Z).
#[must_use]
pub fn is_semver(path: &str) -> Predicate {
    Predicate::Named {
        name: "semver".to_owned(),
        path: path.to_owned(),
    }
}

/// Value at path must be a UUID.
#[must_use]
pub fn is_uuid(path: &str) -> Predicate {
    Predicate::Named {
        name: "uuid".to_owned(),
        path: path.to_owned(),
    }
}

/// Value at path must be an ISO 8601 date (YYYY-MM-DD).
#[must_use]
pub fn is_iso_date(path: &str) -> Predicate {
    Predicate::Named {
        name: "iso_date".to_owned(),
        path: path.to_owned(),
    }
}

/// Value at path must be an ISO 8601 datetime.
#[must_use]
pub fn is_iso_datetime(path: &str) -> Predicate {
    Predicate::Named {
        name: "iso_datetime".to_owned(),
        path: path.to_owned(),
    }
}

/// Value at path must be a CPE identifier (v2.2 or v2.3).
#[must_use]
pub fn is_cpe(path: &str) -> Predicate {
    Predicate::Named {
        name: "cpe".to_owned(),
        path: path.to_owned(),
    }
}

/// Named test type by string name and path.
#[must_use]
pub fn named(name: &str, path: &str) -> Predicate {
    Predicate::Named {
        name: name.to_owned(),
        path: path.to_owned(),
    }
}

// -- Schema builder -------------------------------------------------------

/// Start building a schema with the given title.
#[must_use]
pub fn schema(title: &str) -> SchemaBuilder {
    SchemaBuilder {
        title: title.to_owned(),
        description: String::new(),
        default_phase: String::new(),
        phases: Vec::new(),
        diagnostics: Vec::new(),
        patterns: Vec::new(),
    }
}

/// Builder for `Schema`.
pub struct SchemaBuilder {
    title: String,
    description: String,
    default_phase: String,
    phases: Vec<Phase>,
    diagnostics: Vec<DiagnosticDef>,
    patterns: Vec<Pattern>,
}

impl SchemaBuilder {
    /// Set the schema description.
    #[must_use]
    pub fn description(mut self, desc: &str) -> Self {
        desc.clone_into(&mut self.description);
        self
    }

    /// Set the default phase name.
    #[must_use]
    pub fn default_phase(mut self, phase: &str) -> Self {
        phase.clone_into(&mut self.default_phase);
        self
    }

    /// Add a phase.
    #[must_use]
    pub fn phase(mut self, name: &str, active: &[&str]) -> Self {
        self.phases.push(Phase {
            name: name.to_owned(),
            description: String::new(),
            active_patterns: active.iter().map(|s| (*s).to_owned()).collect(),
        });
        self
    }

    /// Add a diagnostic.
    #[must_use]
    pub fn diagnostic(mut self, id: &str, message: &str) -> Self {
        self.diagnostics.push(DiagnosticDef {
            id: id.to_owned(),
            message: message.to_owned(),
        });
        self
    }

    /// Add a pattern using a closure that configures it.
    #[must_use]
    pub fn pattern(mut self, name: &str, f: impl FnOnce(PatternBuilder) -> PatternBuilder) -> Self {
        let pb = f(PatternBuilder::new(name));
        self.patterns.push(pb.build());
        self
    }

    /// Finish building the schema.
    #[must_use]
    pub fn build(self) -> Schema {
        Schema {
            title: self.title,
            description: self.description,
            default_phase: self.default_phase,
            phases: self.phases,
            diagnostics: self.diagnostics,
            patterns: self.patterns,
        }
    }
}

// -- Pattern builder ------------------------------------------------------

/// Builder for `Pattern`.
pub struct PatternBuilder {
    name: String,
    title: String,
    rules: Vec<Rule>,
}

impl PatternBuilder {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            title: String::new(),
            rules: Vec::new(),
        }
    }

    /// Set the pattern title.
    #[must_use]
    pub fn title(mut self, title: &str) -> Self {
        title.clone_into(&mut self.title);
        self
    }

    /// Add a rule using a closure that configures it.
    #[must_use]
    pub fn rule(mut self, context: &str, f: impl FnOnce(RuleBuilder) -> RuleBuilder) -> Self {
        let rb = f(RuleBuilder::new(context));
        self.rules.push(rb.build());
        self
    }

    fn build(self) -> Pattern {
        Pattern {
            name: self.name,
            title: self.title,
            rules: self.rules,
        }
    }
}

// -- Rule builder ---------------------------------------------------------

/// Builder for `Rule`.
pub struct RuleBuilder {
    id: String,
    context: String,
    lets: Vec<LetBinding>,
    checks: Vec<Check>,
}

impl RuleBuilder {
    fn new(context: &str) -> Self {
        Self {
            id: String::new(),
            context: context.to_owned(),
            lets: Vec::new(),
            checks: Vec::new(),
        }
    }

    /// Set the rule ID.
    #[must_use]
    pub fn id(mut self, id: &str) -> Self {
        id.clone_into(&mut self.id);
        self
    }

    /// Add a let binding.
    #[must_use]
    pub fn let_bind(mut self, name: &str, path: &str) -> Self {
        self.lets.push(LetBinding {
            name: name.to_owned(),
            path: path.to_owned(),
        });
        self
    }

    /// Add an assert (default severity: error).
    #[must_use]
    pub fn assert(mut self, test: Predicate, message: &str) -> Self {
        self.checks.push(Check {
            kind: CheckKind::Assert,
            test,
            message: message.to_owned(),
            severity: Severity::Error,
            flag: String::new(),
            diagnostics: Vec::new(),
        });
        self
    }

    /// Add an assert with explicit severity.
    #[must_use]
    pub fn assert_with(mut self, test: Predicate, message: &str, severity: Severity) -> Self {
        self.checks.push(Check {
            kind: CheckKind::Assert,
            test,
            message: message.to_owned(),
            severity,
            flag: String::new(),
            diagnostics: Vec::new(),
        });
        self
    }

    /// Add a report (default severity: info).
    #[must_use]
    pub fn report(mut self, test: Predicate, message: &str) -> Self {
        self.checks.push(Check {
            kind: CheckKind::Report,
            test,
            message: message.to_owned(),
            severity: Severity::Info,
            flag: String::new(),
            diagnostics: Vec::new(),
        });
        self
    }

    /// Add a report with explicit severity.
    #[must_use]
    pub fn report_with(mut self, test: Predicate, message: &str, severity: Severity) -> Self {
        self.checks.push(Check {
            kind: CheckKind::Report,
            test,
            message: message.to_owned(),
            severity,
            flag: String::new(),
            diagnostics: Vec::new(),
        });
        self
    }

    fn build(self) -> Rule {
        Rule {
            id: self.id,
            context: self.context,
            lets: self.lets,
            checks: self.checks,
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn build_and_validate() {
        let s = schema("test")
            .pattern("p", |p| {
                p.rule("$", |r| {
                    r.assert(exists("$.name"), "name required")
                        .assert_with(
                            matches("$.name", "^[A-Z]"),
                            "name must start uppercase",
                            Severity::Warning,
                        )
                        .report(exists("$.metadata"), "has metadata")
                })
            })
            .build();

        assert_eq!(s.title, "test");
        assert_eq!(s.patterns.len(), 1);
        assert_eq!(s.patterns[0].rules[0].checks.len(), 3);
        assert_eq!(s.patterns[0].rules[0].checks[0].kind, CheckKind::Assert);
        assert_eq!(s.patterns[0].rules[0].checks[2].kind, CheckKind::Report);

        // Validate against a document
        let doc = crate::document::from_json(r#"{"name": "Alice", "metadata": {}}"#).unwrap();
        let report = crate::eval::validate(&s, &doc);
        assert!(report.is_ok());
    }

    #[test]
    fn build_with_phases() {
        let s = schema("phased")
            .default_phase("quick")
            .phase("quick", &["basic"])
            .phase("full", &["basic", "strict"])
            .pattern("basic", |p| {
                p.rule("$", |r| r.assert(exists("$.id"), "need id"))
            })
            .pattern("strict", |p| {
                p.rule("$", |r| {
                    r.assert(matches("$.id", "^[A-Z]"), "id must start uppercase")
                })
            })
            .build();

        assert_eq!(s.phases.len(), 2);
        assert_eq!(s.active_patterns("quick").len(), 1);
        assert_eq!(s.active_patterns("full").len(), 2);
    }

    #[test]
    fn build_with_diagnostics() {
        let s = schema("diags")
            .diagnostic("d1", "See spec section 4.2")
            .pattern("p", |p| p.rule("$", |r| r.assert(exists("$.x"), "need x")))
            .build();

        assert_eq!(s.diagnostic("d1"), Some("See spec section 4.2"));
    }

    #[test]
    fn build_complex_predicates() {
        let s = schema("complex")
            .pattern("p", |p| {
                p.rule("$", |r| {
                    r.assert(
                        and(exists("$.name"), or(exists("$.email"), exists("$.phone"))),
                        "need name and contact info",
                    )
                    .assert(not(exists("$.password")), "must not contain password")
                    .assert(
                        count("$.tags[*]", Comparison::Ge, 1),
                        "need at least one tag",
                    )
                })
            })
            .build();

        assert_eq!(s.patterns[0].rules[0].checks.len(), 3);
    }

    #[test]
    fn schema_round_trips_through_json() {
        let s = schema("rt")
            .description("round-trip test")
            .pattern("p", |p| {
                p.title("checks").rule("$", |r| {
                    r.assert(exists("$.x"), "need x")
                        .assert(equals("$.status", "active"), "must be active")
                })
            })
            .build();

        let json = serde_json::to_string_pretty(&s).unwrap();
        let s2: Schema = serde_json::from_str(&json).unwrap();
        assert_eq!(s2.title, "rt");
        assert_eq!(s2.patterns[0].rules[0].checks.len(), 2);
    }
}
