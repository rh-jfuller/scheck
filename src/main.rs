#[cfg(feature = "cli")]
use clap::Parser as ClapParser;
use std::process::ExitCode;

/// Default maximum input file size (10 MiB).
/// Override with `SCHECK_MAX_FILE_SIZE` (in bytes).
#[cfg(feature = "cli")]
const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

#[cfg(feature = "cli")]
fn max_file_size() -> u64 {
    std::env::var("SCHECK_MAX_FILE_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_FILE_SIZE)
}

#[cfg(feature = "cli")]
#[derive(ClapParser)]
#[command(
    name = "scheck",
    about = "Semantic validation of structured data \
             using assertion-based rules",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[cfg(feature = "cli")]
#[derive(clap::Subcommand)]
enum Command {
    /// Validate a document against one or more rule files
    Validate {
        /// Document to validate (JSON or YAML); use "-" to read from stdin
        document: String,

        /// Rule file(s) -- repeat for multiple independent rulesets
        #[arg(short, long, required = true)]
        rules: Vec<String>,

        /// Rule format (auto-detected from extension if omitted)
        #[arg(
            long,
            value_parser = ["dsl", "json", "schematron", "freetext"]
        )]
        rule_format: Option<String>,

        /// Phase to activate (default: schema's `default_phase`)
        #[arg(short, long)]
        phase: Option<String>,

        /// Validate only a document subtree at given path
        #[arg(short, long)]
        context: Option<String>,

        /// Output format
        #[arg(
            short,
            long,
            default_value = "text",
            value_parser = ["text", "json", "sarif"]
        )]
        format: String,

        /// Minimum severity that causes a non-zero exit code
        #[arg(
            long,
            default_value = "error",
            value_parser = ["fatal", "error", "warning", "info", "never"]
        )]
        fail_on: String,
    },

    /// Parse and validate a rule file (check for syntax errors)
    Check {
        /// Rule file to validate
        rules: String,

        /// Rule format (auto-detected from extension if omitted)
        #[arg(
            long,
            value_parser = ["dsl", "json", "schematron", "freetext"]
        )]
        rule_format: Option<String>,
    },

    /// Convert rules from another format to scheck JSON
    Convert {
        /// Input rule file to convert
        input: String,

        /// Source format
        #[arg(long, value_parser = ["spectral"])]
        from: String,
    },
}

/// Exit code returned when validation finds issues at or above the
/// `--fail-on` threshold.
#[cfg(feature = "cli")]
const EXIT_FINDINGS: u8 = 1;

/// Exit code returned when the tool itself fails (I/O, parse errors).
#[cfg(feature = "cli")]
const EXIT_TOOL_ERROR: u8 = 2;

/// Result of running a command: the text to print plus the exit code.
#[cfg(feature = "cli")]
struct Outcome {
    output: String,
    code: ExitCode,
}

fn main() -> ExitCode {
    #[cfg(feature = "cli")]
    {
        let cli = Cli::parse();
        match run(&cli) {
            Ok(outcome) => {
                #[expect(clippy::print_stdout)]
                {
                    print!("{}", outcome.output);
                }
                outcome.code
            }
            Err(e) => {
                #[expect(clippy::print_stderr)]
                {
                    eprintln!("error: {e}");
                }
                ExitCode::from(EXIT_TOOL_ERROR)
            }
        }
    }

    #[cfg(not(feature = "cli"))]
    {
        ExitCode::FAILURE
    }
}

#[cfg(feature = "cli")]
fn run(cli: &Cli) -> Result<Outcome, String> {
    match &cli.command {
        Command::Validate {
            document,
            rules,
            rule_format,
            phase,
            context,
            format,
            fail_on,
        } => run_validate(
            document,
            rules,
            rule_format.as_deref(),
            phase.as_deref(),
            context.as_deref(),
            format,
            fail_on,
        ),
        Command::Check { rules, rule_format } => run_check(rules, rule_format.as_deref()),
        Command::Convert { input, from } => run_convert(input, from),
    }
}

/// Parse the `--fail-on` threshold. `None` means never fail on findings.
#[cfg(feature = "cli")]
fn parse_fail_on(value: &str) -> Option<scheck::Severity> {
    match value {
        "fatal" => Some(scheck::Severity::Fatal),
        "warning" => Some(scheck::Severity::Warning),
        "info" => Some(scheck::Severity::Info),
        "never" => None,
        _ => Some(scheck::Severity::Error),
    }
}

/// Compute the exit code for a report given a `--fail-on` threshold.
#[cfg(feature = "cli")]
fn exit_code_for(report: &scheck::Report, fail_on: &str) -> ExitCode {
    let Some(threshold) = parse_fail_on(fail_on) else {
        return ExitCode::SUCCESS;
    };
    match report.worst_severity() {
        Some(worst) if worst >= threshold => ExitCode::from(EXIT_FINDINGS),
        _ => ExitCode::SUCCESS,
    }
}

#[cfg(feature = "cli")]
fn detect_format<'a>(path: &'a str, explicit: Option<&'a str>) -> &'a str {
    if let Some(fmt) = explicit {
        return fmt;
    }
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "json" => "json",
        "xml" | "sch" => "schematron",
        "txt" => "freetext",
        _ => "dsl",
    }
}

#[cfg(feature = "cli")]
fn load_schema(rules_src: &str, fmt: &str) -> Result<scheck::Schema, String> {
    match fmt {
        "json" => serde_json::from_str(rules_src).map_err(|e| format!("JSON error: {e}")),
        "schematron" => scheck::parse_schematron(rules_src).map_err(|e| format!("{e}")),
        "freetext" => scheck::parse_freetext(rules_src).map_err(|e| format!("{e}")),
        _ => scheck::parse_schema(rules_src).map_err(|e| format!("{e}")),
    }
}

#[cfg(feature = "cli")]
fn read_file_bounded(path: &str) -> Result<String, String> {
    let limit = max_file_size();
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot stat {path}: {e}"))?;
    if meta.len() > limit {
        return Err(format!(
            "{path}: file too large ({} bytes, max {limit}; \
             override with SCHECK_MAX_FILE_SIZE)",
            meta.len(),
        ));
    }
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
}

/// Read a document from a file path, or from stdin when `path` is `-`.
#[cfg(feature = "cli")]
fn read_document(path: &str) -> Result<String, String> {
    if path == "-" {
        read_stdin_bounded()
    } else {
        read_file_bounded(path)
    }
}

/// Read all of stdin into a string, enforcing the configured size limit.
#[cfg(feature = "cli")]
fn read_stdin_bounded() -> Result<String, String> {
    use std::io::Read;

    let limit = max_file_size();
    let mut buf = String::new();
    let read = std::io::stdin()
        .lock()
        .take(limit + 1)
        .read_to_string(&mut buf)
        .map_err(|e| format!("cannot read stdin: {e}"))?;
    if read as u64 > limit {
        return Err(format!(
            "stdin: input too large (max {limit} bytes; \
             override with SCHECK_MAX_FILE_SIZE)"
        ));
    }
    Ok(buf)
}

#[cfg(feature = "cli")]
fn run_validate(
    doc_path: &str,
    rules_paths: &[String],
    rule_format: Option<&str>,
    phase: Option<&str>,
    context: Option<&str>,
    format: &str,
    fail_on: &str,
) -> Result<Outcome, String> {
    let doc_src = read_document(doc_path)?;
    let doc = scheck::load(&doc_src).map_err(|e| format!("Document error: {e}"))?;

    let mut schemas = Vec::new();
    for rules_path in rules_paths {
        let rules_src = read_file_bounded(rules_path)?;
        let fmt = detect_format(rules_path, rule_format);
        schemas.push(load_schema(&rules_src, fmt)?);
    }

    let schema_refs: Vec<&scheck::Schema> = schemas.iter().collect();
    let phase_str = phase.unwrap_or("");

    let report = if let Some(ctx) = context {
        // Partial validation does not support multi-ruleset yet;
        // run each independently and combine
        let mut all_fired = Vec::new();
        let mut all_results = Vec::new();
        let mut titles = Vec::new();
        for schema in &schemas {
            let r = scheck::validate_context(schema, &doc, ctx, phase_str);
            titles.push(r.schema_title.clone());
            all_fired.extend(r.fired_rules);
            all_results.extend(r.results);
        }
        scheck::Report::new(
            titles.join(" + "),
            phase_str.to_owned(),
            all_fired,
            all_results,
        )
    } else {
        scheck::validate_all_phase(&schema_refs, &doc, phase_str)
    };

    let sarif_uri = if doc_path == "-" { "stdin" } else { doc_path };
    let output = match format {
        "json" => report.to_json(),
        "sarif" => report.to_sarif(sarif_uri),
        _ => report.to_text(),
    };

    let code = exit_code_for(&report, fail_on);
    Ok(Outcome { output, code })
}

#[cfg(feature = "cli")]
fn run_check(rules_path: &str, rule_format: Option<&str>) -> Result<Outcome, String> {
    let rules_src = read_file_bounded(rules_path)?;

    let fmt = detect_format(rules_path, rule_format);
    let schema = load_schema(&rules_src, fmt)?;

    Ok(Outcome {
        output: format!(
            "OK: schema \"{}\" — {} pattern(s), {} phase(s) [{}]\n",
            schema.title,
            schema.patterns.len(),
            schema.phases.len(),
            fmt,
        ),
        code: ExitCode::SUCCESS,
    })
}

#[cfg(feature = "cli")]
fn run_convert(input_path: &str, from: &str) -> Result<Outcome, String> {
    use std::fmt::Write;

    let src = read_file_bounded(input_path)?;

    match from {
        "spectral" => {
            let result = scheck::spectral::convert_spectral(&src)?;
            let mut output = String::new();

            if !result.skipped.is_empty() {
                for (name, reason) in &result.skipped {
                    let _ = writeln!(output, "# skipped: {name} ({reason})");
                }
                output.push('\n');
            }

            let json = serde_json::to_string_pretty(&result.schema)
                .map_err(|e| format!("JSON serialization error: {e}"))?;
            output.push_str(&json);
            output.push('\n');

            Ok(Outcome {
                output,
                code: ExitCode::SUCCESS,
            })
        }
        other => Err(format!("unknown source format: {other}")),
    }
}
