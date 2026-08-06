//! Rule model for scheck — inspired by ISO Schematron (ISO/IEC 19757-3).
//!
//! Hierarchy mirrors Schematron faithfully:
//!
//!   Schema
//!     +-- Phase (named subset of patterns to activate)
//!     +-- Diagnostic (reusable diagnostic messages)
//!     +-- Pattern (group of related rules)
//!           +-- title / description (human documentation)
//!           +-- Rule (context selects nodes)
//!                 +-- let (variable bindings)
//!                 +-- Assert (must be true -- fires on failure)
//!                 +-- Report (fires on success -- positive diagnostic)
//!
//! Key Schematron concepts preserved:
//! - assert vs report (failure diagnostic vs success diagnostic)
//! - phases for selective validation
//! - let bindings for reusable path selections
//! - diagnostics for shared human-readable messages
//! - severity (Schematron 2025 addition)
//! - flag/role for categorization
//!
//! All path expressions are `JSONPath` (RFC 9535) strings,
//! parsed and evaluated at validation time via `serde_json_path`.

use serde::{Deserialize, Serialize};

/// Top-level schema: the complete set of validation rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_phase: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phases: Vec<Phase>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<DiagnosticDef>,
    pub patterns: Vec<Pattern>,
}

impl Schema {
    /// Get patterns activated by a phase name.
    /// If phase is "all" or empty, return all patterns.
    #[must_use]
    pub fn active_patterns(&self, phase_name: &str) -> Vec<&Pattern> {
        if phase_name.is_empty() || phase_name == "all" {
            return self.patterns.iter().collect();
        }
        let Some(phase) = self.phases.iter().find(|p| p.name == phase_name) else {
            return self.patterns.iter().collect();
        };
        self.patterns
            .iter()
            .filter(|p| phase.active_patterns.contains(&p.name))
            .collect()
    }

    /// Look up a diagnostic by ID.
    #[must_use]
    pub fn diagnostic(&self, id: &str) -> Option<&str> {
        self.diagnostics
            .iter()
            .find(|d| d.id == id)
            .map(|d| d.message.as_str())
    }
}

/// A phase: a named subset of patterns for selective validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub active_patterns: Vec<String>,
}

/// A reusable diagnostic message, referenced by ID from assertions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticDef {
    pub id: String,
    pub message: String,
}

/// A pattern: a group of related rules with documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    pub rules: Vec<Rule>,
}

/// A rule: selects nodes via context path, then evaluates
/// assertions and reports against each matched node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    pub context: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lets: Vec<LetBinding>,
    pub checks: Vec<Check>,
}

/// A `let` binding: binds a path selection to a variable name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LetBinding {
    pub name: String,
    pub path: String,
}

/// A check: either an `assert` (fires on failure) or a `report`
/// (fires on success).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub kind: CheckKind,
    pub test: Predicate,
    pub message: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flag: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

fn default_severity() -> Severity {
    Severity::Error
}

/// Whether a check is an assert (fires on failure) or
/// report (fires on success).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckKind {
    Assert,
    Report,
}

impl std::fmt::Display for CheckKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Assert => write!(f, "assert"),
            Self::Report => write!(f, "report"),
        }
    }
}

/// Severity levels for check results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
    Fatal,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Fatal => write!(f, "fatal"),
        }
    }
}

/// Predicate: a boolean expression evaluated against a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Predicate {
    /// Node selected by path exists.
    Exists { path: String },
    /// Node selected by path must not exist.
    NotExists { path: String },
    /// Scalar value at path equals expected value.
    Equals { path: String, value: String },
    /// Scalar value at path matches a regex pattern.
    Matches { path: String, pattern: String },
    /// Count of nodes matching path satisfies a comparison.
    Count {
        path: String,
        cmp: Comparison,
        expected: usize,
    },
    /// Reference to a let-bound variable (resolved during eval).
    Var { name: String },
    /// Logical AND of two predicates.
    And {
        left: Box<Predicate>,
        right: Box<Predicate>,
    },
    /// Logical OR of two predicates.
    Or {
        left: Box<Predicate>,
        right: Box<Predicate>,
    },
    /// Logical NOT of a predicate.
    Not { inner: Box<Predicate> },
    /// Named built-in test type. See `named_pattern()` for supported names.
    Named { name: String, path: String },
}

/// Built-in named test type patterns.
/// Returns `None` if name is not recognized.
#[must_use]
pub fn named_pattern(name: &str) -> Option<&'static str> {
    match name {
        "email" => Some(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
        "url" => Some(r"^https?://\S+"),
        "cve_id" | "cve-id" => Some(r"^CVE-[0-9]{4}-[0-9]{4,}$"),
        "purl" => Some(r"^pkg:[a-z][a-z0-9._-]*/"),
        "semver" => {
            Some(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$")
        }
        "uuid" => Some(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
        "iso_date" | "iso-date" => Some(r"^\d{4}-\d{2}-\d{2}$"),
        "iso_datetime" | "iso-datetime" => Some(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
        "cpe" => Some(r"^cpe:2\.[23]:[aohe\*\-]:"),
        _ => None,
    }
}

/// Comparison operators for count predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Comparison {
    #[serde(rename = "==")]
    Eq,
    #[serde(rename = "!=")]
    Ne,
    #[serde(rename = "<")]
    Lt,
    #[serde(rename = "<=")]
    Le,
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = ">=")]
    Ge,
}

impl Comparison {
    /// Evaluate the comparison.
    #[must_use]
    pub fn eval(self, actual: usize, expected: usize) -> bool {
        match self {
            Self::Eq => actual == expected,
            Self::Ne => actual != expected,
            Self::Lt => actual < expected,
            Self::Le => actual <= expected,
            Self::Gt => actual > expected,
            Self::Ge => actual >= expected,
        }
    }
}

impl std::fmt::Display for Comparison {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eq => write!(f, "=="),
            Self::Ne => write!(f, "!="),
            Self::Lt => write!(f, "<"),
            Self::Le => write!(f, "<="),
            Self::Gt => write!(f, ">"),
            Self::Ge => write!(f, ">="),
        }
    }
}
