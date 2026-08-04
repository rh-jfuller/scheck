pub mod builder;
mod document;
mod eval;
mod freetext;
mod parser;
mod report;
mod rule;
mod schematron;

pub use document::{Document, DocumentError, from_json, from_yaml, load};
pub use eval::{
    check, check_freetext, check_json, check_ok, check_phase, check_schematron, validate,
    validate_json, validate_phase,
};
pub use freetext::{FreetextError, parse_freetext};
pub use parser::{ParseError, parse_schema};
pub use report::{CheckResult, FiredRule, Report, ResultKind};
pub use rule::{
    Check, CheckKind, Comparison, DiagnosticDef, LetBinding, Pattern, Phase, Predicate, Rule,
    Schema, Severity,
};
pub use schematron::{SchematronError, parse_schematron};

#[cfg(feature = "wasm")]
mod wasm_api;
