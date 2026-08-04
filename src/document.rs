//! Format-agnostic document wrapper for semantic validation.
//!
//! The document is a thin wrapper around `serde_json::Value`.
//! JSON and YAML both deserialize into this common representation.

use std::fmt;

/// A loaded document ready for validation.
#[derive(Debug, Clone)]
pub struct Document {
    pub root: serde_json::Value,
    pub source_format: SourceFormat,
}

/// Wire format the document was loaded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    Json,
    Yaml,
}

impl fmt::Display for SourceFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Yaml => write!(f, "yaml"),
        }
    }
}

/// Load a document from a JSON string.
///
/// # Errors
///
/// Returns an error if the JSON is malformed.
pub fn from_json(input: &str) -> Result<Document, DocumentError> {
    let root: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| DocumentError::Parse(format!("invalid JSON: {e}")))?;
    Ok(Document {
        root,
        source_format: SourceFormat::Json,
    })
}

/// Load a document from a YAML string.
///
/// # Errors
///
/// Returns an error if the YAML is malformed.
pub fn from_yaml(input: &str) -> Result<Document, DocumentError> {
    let root: serde_json::Value = serde_yml::from_str(input)
        .map_err(|e| DocumentError::Parse(format!("invalid YAML: {e}")))?;
    Ok(Document {
        root,
        source_format: SourceFormat::Yaml,
    })
}

/// Load a document, auto-detecting format from content.
///
/// # Errors
///
/// Returns an error if format detection fails or parsing fails.
pub fn load(input: &str) -> Result<Document, DocumentError> {
    let trimmed = input.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        from_json(input)
    } else {
        from_yaml(input)
    }
}

/// Errors from document loading.
#[derive(Debug, thiserror::Error)]
pub enum DocumentError {
    #[error("{0}")]
    Parse(String),
}
