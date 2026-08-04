#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

// -- DSL rules (.scheck) ------------------------------------------------

/// Validate a document against `.scheck` DSL rules.
/// Returns a JSON report.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_check(rules: &str, document: &str) -> Result<String, JsValue> {
    let report = crate::eval::check(rules, document).map_err(|e| JsValue::from_str(&e))?;
    Ok(report.to_json())
}

/// Validate a document against `.scheck` DSL rules.
/// Returns a text report.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_check_text(rules: &str, document: &str) -> Result<String, JsValue> {
    let report = crate::eval::check(rules, document).map_err(|e| JsValue::from_str(&e))?;
    Ok(report.to_text())
}

// -- JSON rules ----------------------------------------------------------

/// Validate a document against rules provided as JSON.
/// Returns a JSON report.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_check_json(rules_json: &str, document: &str) -> Result<String, JsValue> {
    let report =
        crate::eval::check_json(rules_json, document).map_err(|e| JsValue::from_str(&e))?;
    Ok(report.to_json())
}

/// Validate a document against rules provided as JSON.
/// Returns a text report.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_check_json_text(rules_json: &str, document: &str) -> Result<String, JsValue> {
    let report =
        crate::eval::check_json(rules_json, document).map_err(|e| JsValue::from_str(&e))?;
    Ok(report.to_text())
}

// -- Schematron XML rules ------------------------------------------------

/// Validate a document against Schematron XML rules.
/// Returns a JSON report.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_check_schematron(rules_xml: &str, document: &str) -> Result<String, JsValue> {
    let report =
        crate::eval::check_schematron(rules_xml, document).map_err(|e| JsValue::from_str(&e))?;
    Ok(report.to_json())
}

/// Validate a document against Schematron XML rules.
/// Returns a text report.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_check_schematron_text(rules_xml: &str, document: &str) -> Result<String, JsValue> {
    let report =
        crate::eval::check_schematron(rules_xml, document).map_err(|e| JsValue::from_str(&e))?;
    Ok(report.to_text())
}

// -- Free-text rules -----------------------------------------------------

/// Validate a document against free-text rules.
/// Returns a JSON report.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_check_freetext(rules_text: &str, document: &str) -> Result<String, JsValue> {
    let report =
        crate::eval::check_freetext(rules_text, document).map_err(|e| JsValue::from_str(&e))?;
    Ok(report.to_json())
}

/// Validate a document against free-text rules.
/// Returns a text report.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_check_freetext_text(rules_text: &str, document: &str) -> Result<String, JsValue> {
    let report =
        crate::eval::check_freetext(rules_text, document).map_err(|e| JsValue::from_str(&e))?;
    Ok(report.to_text())
}

// -- Parsing utilities ---------------------------------------------------

/// Parse `.scheck` DSL rules and return the schema as JSON.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_parse_rules(rules: &str) -> Result<String, JsValue> {
    let schema =
        crate::parser::parse_schema(rules).map_err(|e| JsValue::from_str(&format!("{e}")))?;
    serde_json::to_string_pretty(&schema).map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// Parse Schematron XML and return the schema as JSON.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_parse_schematron(xml: &str) -> Result<String, JsValue> {
    let schema =
        crate::schematron::parse_schematron(xml).map_err(|e| JsValue::from_str(&format!("{e}")))?;
    serde_json::to_string_pretty(&schema).map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// Parse free-text rules and return the schema as JSON.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_parse_freetext(text: &str) -> Result<String, JsValue> {
    let schema =
        crate::freetext::parse_freetext(text).map_err(|e| JsValue::from_str(&format!("{e}")))?;
    serde_json::to_string_pretty(&schema).map_err(|e| JsValue::from_str(&format!("{e}")))
}
