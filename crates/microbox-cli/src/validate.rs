use crate::{
    args::{DiagnosticFormat, ValidateArgs},
    runner::{prepare_context, select_backend_for_policy},
};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ValidationReport {
    tool: String,
    backend: String,
    secure_enforcement: bool,
    valid: bool,
    policy_summary: Option<Vec<String>>,
    policy_error: Option<String>,
    notes: Vec<String>,
}

pub fn run(args: ValidateArgs) -> Result<i32, microbox_core::SandboxError> {
    let backend = select_backend_for_policy(args.policy.backend)?;
    let capabilities = backend.capabilities();
    let policy_result = prepare_context(&args.policy);
    let report = ValidationReport {
        tool: env!("CARGO_PKG_NAME").to_string(),
        backend: capabilities.name.to_string(),
        secure_enforcement: capabilities.secure_enforcement,
        valid: policy_result.is_ok(),
        policy_summary: policy_result
            .as_ref()
            .ok()
            .map(|context| context.policy.summary_lines()),
        policy_error: policy_result.as_ref().err().map(|error| error.to_string()),
        notes: capabilities.notes.clone(),
    };

    let rendered = match args.format {
        DiagnosticFormat::Text => render_text(&report),
        DiagnosticFormat::Json => render_json(&report)?,
    };

    println!("{rendered}");

    Ok(if report.valid { 0 } else { 1 })
}

fn render_text(report: &ValidationReport) -> String {
    let mut lines = vec![
        "MicroBox validate".to_string(),
        format!("backend = {}", report.backend),
        format!(
            "secure_enforcement = {}",
            if report.secure_enforcement {
                "yes"
            } else {
                "no"
            }
        ),
        format!("valid = {}", if report.valid { "yes" } else { "no" }),
    ];

    if let Some(error) = &report.policy_error {
        lines.push(format!("policy_error = {}", error));
    } else if let Some(summary) = &report.policy_summary {
        for line in summary {
            lines.push(line.to_string());
        }
    }

    if !report.notes.is_empty() {
        lines.push("notes:".to_string());
        for note in &report.notes {
            lines.push(format!("  - {}", note));
        }
    }

    lines.join("\n")
}

fn render_json(report: &ValidationReport) -> Result<String, microbox_core::SandboxError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| microbox_core::SandboxError::LaunchFailed(error.to_string()))
}
