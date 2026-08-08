//! Validation report — inspired by Schematron SVRL
//! (Schematron Validation Report Language).
//!
//! SVRL defines three key result types:
//! - `fired-rule`: a rule's context matched at least one node
//! - `failed-assert`: an assert whose test was false
//! - `successful-report`: a report whose test was true
//!
//! scheck mirrors this structure for complete traceability.

use std::fmt;
use std::fmt::Write;

use crate::rule::Severity;

/// Complete validation report.
#[derive(Debug, Clone)]
pub struct Report {
    pub schema_title: String,
    pub phase: String,
    pub fired_rules: Vec<FiredRule>,
    pub results: Vec<CheckResult>,
}

/// A rule that fired (its context matched at least one node).
///
/// SVRL equivalent: `<svrl:fired-rule>`.
#[derive(Debug, Clone)]
pub struct FiredRule {
    pub rule_id: String,
    pub pattern: String,
    pub context_path: String,
}

/// Result of a single check evaluation.
///
/// SVRL equivalents:
/// - `FailedAssert` -> `<svrl:failed-assert>`
/// - `SuccessfulReport` -> `<svrl:successful-report>`
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub kind: ResultKind,
    pub fired: bool,
    pub rule_id: String,
    pub pattern: String,
    pub path: String,
    pub severity: Severity,
    pub message: String,
    pub diagnostic: String,
    pub flag: String,
}

/// The kind of check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultKind {
    /// Assert test was false — a failure.
    FailedAssert,
    /// Report test was true — a positive finding.
    SuccessfulReport,
}

impl fmt::Display for ResultKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailedAssert => write!(f, "failed-assert"),
            Self::SuccessfulReport => {
                write!(f, "successful-report")
            }
        }
    }
}

impl Report {
    #[must_use]
    pub fn new(
        schema_title: String,
        phase: String,
        fired_rules: Vec<FiredRule>,
        results: Vec<CheckResult>,
    ) -> Self {
        Self {
            schema_title,
            phase,
            fired_rules,
            results,
        }
    }

    /// No failed asserts at error/warning/fatal severity.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        !self.results.iter().any(|r| {
            r.fired && r.kind == ResultKind::FailedAssert && r.severity >= Severity::Warning
        })
    }

    /// All results that fired (failed asserts + successful
    /// reports).
    #[must_use]
    pub fn findings(&self) -> Vec<&CheckResult> {
        self.results.iter().filter(|r| r.fired).collect()
    }

    /// Failed asserts only.
    #[must_use]
    pub fn failures(&self) -> Vec<&CheckResult> {
        self.results
            .iter()
            .filter(|r| r.fired && r.kind == ResultKind::FailedAssert)
            .collect()
    }

    /// Successful reports only.
    #[must_use]
    pub fn reports(&self) -> Vec<&CheckResult> {
        self.results
            .iter()
            .filter(|r| r.fired && r.kind == ResultKind::SuccessfulReport)
            .collect()
    }

    #[must_use]
    pub fn fatal_count(&self) -> usize {
        self.count_failures(Severity::Fatal)
    }

    #[must_use]
    pub fn error_count(&self) -> usize {
        self.count_failures(Severity::Error)
    }

    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.count_failures(Severity::Warning)
    }

    #[must_use]
    pub fn info_count(&self) -> usize {
        self.count_findings(Severity::Info)
    }

    fn count_failures(&self, sev: Severity) -> usize {
        self.results
            .iter()
            .filter(|r| r.fired && r.kind == ResultKind::FailedAssert && r.severity == sev)
            .count()
    }

    fn count_findings(&self, sev: Severity) -> usize {
        self.results
            .iter()
            .filter(|r| r.fired && r.severity == sev)
            .count()
    }

    // ── Output formats ──────────────────────────────────────

    /// Human-readable text report.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut buf = String::new();
        let findings = self.findings();

        if findings.is_empty() {
            buf.push_str("OK: all checks passed\n");
            return buf;
        }

        for f in &findings {
            let prefix = match f.kind {
                ResultKind::FailedAssert | ResultKind::SuccessfulReport => {
                    format!("[{}]", f.severity)
                }
            };

            let _ = writeln!(buf, "{} {} at {}: {}", prefix, f.pattern, f.path, f.message);

            if !f.diagnostic.is_empty() {
                let _ = writeln!(buf, "       {}", f.diagnostic);
            }
        }

        let fc = self.fatal_count();
        let ec = self.error_count();
        let wc = self.warning_count();
        let ic = self.info_count();

        buf.push('\n');
        if fc > 0 {
            let _ = write!(buf, "{fc} fatal(s), ");
        }
        let _ = writeln!(buf, "{ec} error(s), {wc} warning(s), {ic} info(s)");

        buf
    }

    /// Structured JSON report (SVRL-inspired).
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut buf = String::from("{\n");
        let _ = writeln!(
            buf,
            "  \"schema\": \"{}\",",
            json_escape(&self.schema_title)
        );
        let _ = writeln!(buf, "  \"phase\": \"{}\",", json_escape(&self.phase));
        let _ = writeln!(buf, "  \"ok\": {},", self.is_ok());

        self.write_fired_rules_json(&mut buf);
        self.write_findings_json(&mut buf);
        self.write_summary_json(&mut buf);

        buf.push('}');
        buf
    }

    fn write_fired_rules_json(&self, buf: &mut String) {
        buf.push_str("  \"fired-rules\": [\n");
        for (i, fr) in self.fired_rules.iter().enumerate() {
            buf.push_str("    {\n");
            let _ = writeln!(buf, "      \"rule\": \"{}\",", json_escape(&fr.rule_id));
            let _ = writeln!(buf, "      \"pattern\": \"{}\",", json_escape(&fr.pattern));
            let _ = writeln!(
                buf,
                "      \"context\": \"{}\"",
                json_escape(&fr.context_path)
            );
            trailing_comma(buf, i, self.fired_rules.len());
        }
        buf.push_str("  ],\n");
    }

    fn write_findings_json(&self, buf: &mut String) {
        let findings = self.findings();
        buf.push_str("  \"findings\": [\n");
        for (i, f) in findings.iter().enumerate() {
            buf.push_str("    {\n");
            let _ = writeln!(buf, "      \"type\": \"{}\",", f.kind);
            let _ = writeln!(buf, "      \"severity\": \"{}\",", f.severity);
            let _ = writeln!(buf, "      \"pattern\": \"{}\",", json_escape(&f.pattern));
            let _ = writeln!(buf, "      \"path\": \"{}\",", json_escape(&f.path));
            let _ = write!(buf, "      \"message\": \"{}\"", json_escape(&f.message));
            if !f.diagnostic.is_empty() {
                let _ = write!(
                    buf,
                    ",\n      \"diagnostic\": \"{}\"",
                    json_escape(&f.diagnostic)
                );
            }
            if !f.flag.is_empty() {
                let _ = write!(buf, ",\n      \"flag\": \"{}\"", json_escape(&f.flag));
            }
            buf.push('\n');
            trailing_comma(buf, i, findings.len());
        }
        buf.push_str("  ],\n");
    }

    /// SARIF v2.1.0 report for GitHub Code Scanning.
    #[must_use]
    pub fn to_sarif(&self, document_path: &str) -> String {
        let mut buf = String::from("{\n");
        buf.push_str("  \"version\": \"2.1.0\",\n");
        buf.push_str(
            "  \"$schema\": \"https://raw.githubusercontent.com\
             /oasis-tcs/sarif-spec/main/sarif-2.1\
             /schema/sarif-schema-2.1.0.json\",\n",
        );
        buf.push_str("  \"runs\": [\n    {\n");

        // tool
        buf.push_str("      \"tool\": {\n");
        buf.push_str("        \"driver\": {\n");
        buf.push_str("          \"name\": \"scheck\",\n");
        let _ = writeln!(
            buf,
            "          \"version\": \"{}\",",
            env!("CARGO_PKG_VERSION")
        );
        let _ = writeln!(
            buf,
            "          \"informationUri\": \
             \"https://github.com/rh-jfuller/scheck\","
        );
        self.write_sarif_rules(&mut buf);
        buf.push_str("        }\n");
        buf.push_str("      },\n");

        // results
        self.write_sarif_results(&mut buf, document_path);

        buf.push_str("    }\n  ]\n}");
        buf
    }

    fn write_sarif_rules(&self, buf: &mut String) {
        let findings = self.findings();
        // Deduplicate rule IDs
        let mut seen = Vec::new();
        buf.push_str("          \"rules\": [\n");
        let mut count = 0;
        for f in &findings {
            let rule_id = &f.pattern;
            if seen.contains(rule_id) {
                continue;
            }
            seen.push(rule_id.clone());
            if count > 0 {
                buf.push_str(",\n");
            }
            buf.push_str("            {\n");
            let _ = writeln!(buf, "              \"id\": \"{}\",", json_escape(rule_id));
            let _ = writeln!(
                buf,
                "              \"shortDescription\": \
                 {{ \"text\": \"{}\" }},",
                json_escape(rule_id)
            );
            let _ = write!(
                buf,
                "              \"defaultConfiguration\": \
                 {{ \"level\": \"{}\" }}",
                sarif_level(f.severity)
            );
            buf.push_str("\n            }");
            count += 1;
        }
        buf.push('\n');
        buf.push_str("          ]\n");
    }

    fn write_sarif_results(&self, buf: &mut String, document_path: &str) {
        let findings = self.findings();
        buf.push_str("      \"results\": [\n");
        for (i, f) in findings.iter().enumerate() {
            buf.push_str("        {\n");
            let _ = writeln!(
                buf,
                "          \"ruleId\": \"{}\",",
                json_escape(&f.pattern)
            );
            let _ = writeln!(buf, "          \"level\": \"{}\",", sarif_level(f.severity));
            let _ = writeln!(
                buf,
                "          \"message\": {{ \"text\": \"{}\" }},",
                json_escape(&f.message)
            );
            buf.push_str("          \"locations\": [\n");
            buf.push_str("            {\n");
            buf.push_str("              \"physicalLocation\": {\n");
            let _ = writeln!(
                buf,
                "                \"artifactLocation\": \
                 {{ \"uri\": \"{}\" }},",
                json_escape(document_path)
            );
            buf.push_str(
                "                \"region\": \
                 { \"startLine\": 1 }\n",
            );
            buf.push_str("              },\n");
            let _ = writeln!(
                buf,
                "              \"logicalLocations\": \
                 [{{ \"name\": \"{}\" }}]",
                json_escape(&f.path)
            );
            buf.push_str("            }\n");
            buf.push_str("          ]\n");
            trailing_comma(buf, i, findings.len());
        }
        buf.push_str("      ]\n");
    }

    fn write_summary_json(&self, buf: &mut String) {
        buf.push_str("  \"summary\": {\n");
        let _ = writeln!(buf, "    \"fatal\": {},", self.fatal_count());
        let _ = writeln!(buf, "    \"errors\": {},", self.error_count());
        let _ = writeln!(buf, "    \"warnings\": {},", self.warning_count());
        let _ = writeln!(buf, "    \"infos\": {}", self.info_count());
        buf.push_str("  }\n");
    }
}

fn trailing_comma(buf: &mut String, i: usize, len: usize) {
    if i + 1 < len {
        buf.push_str("    },\n");
    } else {
        buf.push_str("    }\n");
    }
}

fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Fatal | Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_text())
    }
}
