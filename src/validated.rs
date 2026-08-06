//! Proof wrapper ensuring a document passed validation.
//!
//! `Validated<Document>` can only be constructed through
//! successful validation, preventing unchecked documents
//! from flowing downstream.

use crate::document::Document;
use crate::eval;
use crate::report::Report;
use crate::rule::Schema;

/// Wrapper proving a document passed all validation rules.
///
/// Cannot be constructed directly -- only through
/// `try_validate` or `try_validate_phase`.
#[derive(Debug, Clone)]
pub struct Validated {
    document: Document,
    report: Report,
}

impl Validated {
    /// Access the validated document.
    #[must_use]
    pub fn document(&self) -> &Document {
        &self.document
    }

    /// Access the validation report.
    #[must_use]
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// Consume wrapper, returning the document.
    #[must_use]
    pub fn into_document(self) -> Document {
        self.document
    }

    /// Consume wrapper, returning both document and report.
    #[must_use]
    pub fn into_parts(self) -> (Document, Report) {
        (self.document, self.report)
    }
}

/// Validation failed -- contains the report with findings.
#[derive(Debug, Clone)]
pub struct ValidationFailed {
    report: Report,
}

impl ValidationFailed {
    /// Access the failure report.
    #[must_use]
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// Consume, returning the report.
    #[must_use]
    pub fn into_report(self) -> Report {
        self.report
    }
}

impl std::fmt::Display for ValidationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.report.to_text())
    }
}

impl std::error::Error for ValidationFailed {}

/// Validate a document, returning `Validated` on success.
///
/// # Errors
///
/// Returns `ValidationFailed` if any check fails at
/// warning severity or above.
pub fn try_validate(schema: &Schema, doc: Document) -> Result<Validated, ValidationFailed> {
    try_validate_phase(schema, doc, "")
}

/// Validate with a named phase, returning `Validated` on success.
///
/// # Errors
///
/// Returns `ValidationFailed` if any check fails at
/// warning severity or above.
pub fn try_validate_phase(
    schema: &Schema,
    doc: Document,
    phase: &str,
) -> Result<Validated, ValidationFailed> {
    let report = eval::validate_phase(schema, &doc, phase);
    if report.is_ok() {
        Ok(Validated {
            document: doc,
            report,
        })
    } else {
        Err(ValidationFailed { report })
    }
}
