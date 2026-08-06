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
    /// Validate a document against a rule file
    Validate {
        /// Document to validate (JSON or YAML)
        document: String,

        /// Rule file (.scheck, .json, .xml, or .txt)
        #[arg(short, long)]
        rules: String,

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
            value_parser = ["text", "json"]
        )]
        format: String,
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
}

fn main() -> ExitCode {
    #[cfg(feature = "cli")]
    {
        let cli = Cli::parse();
        match run(&cli) {
            Ok(output) => {
                #[expect(clippy::print_stdout)]
                {
                    print!("{output}");
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                #[expect(clippy::print_stderr)]
                {
                    eprintln!("error: {e}");
                }
                ExitCode::FAILURE
            }
        }
    }

    #[cfg(not(feature = "cli"))]
    {
        ExitCode::FAILURE
    }
}

#[cfg(feature = "cli")]
fn run(cli: &Cli) -> Result<String, String> {
    match &cli.command {
        Command::Validate {
            document,
            rules,
            rule_format,
            phase,
            context,
            format,
        } => run_validate(
            document,
            rules,
            rule_format.as_deref(),
            phase.as_deref(),
            context.as_deref(),
            format,
        ),
        Command::Check { rules, rule_format } => run_check(rules, rule_format.as_deref()),
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

#[cfg(feature = "cli")]
fn run_validate(
    doc_path: &str,
    rules_path: &str,
    rule_format: Option<&str>,
    phase: Option<&str>,
    context: Option<&str>,
    format: &str,
) -> Result<String, String> {
    let rules_src = read_file_bounded(rules_path)?;
    let doc_src = read_file_bounded(doc_path)?;

    let fmt = detect_format(rules_path, rule_format);
    let schema = load_schema(&rules_src, fmt)?;
    let doc = scheck::load(&doc_src).map_err(|e| format!("Document error: {e}"))?;
    let phase_str = phase.unwrap_or("");
    let report = match context {
        Some(ctx) => scheck::validate_context(&schema, &doc, ctx, phase_str),
        None => scheck::validate_phase(&schema, &doc, phase_str),
    };

    let output = match format {
        "json" => report.to_json(),
        _ => report.to_text(),
    };

    Ok(output)
}

#[cfg(feature = "cli")]
fn run_check(rules_path: &str, rule_format: Option<&str>) -> Result<String, String> {
    let rules_src = read_file_bounded(rules_path)?;

    let fmt = detect_format(rules_path, rule_format);
    let schema = load_schema(&rules_src, fmt)?;

    Ok(format!(
        "OK: schema \"{}\" — {} pattern(s), {} phase(s) [{}]\n",
        schema.title,
        schema.patterns.len(),
        schema.phases.len(),
        fmt,
    ))
}
