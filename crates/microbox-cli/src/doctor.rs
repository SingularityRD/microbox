use crate::{
    args::{DiagnosticFormat, DoctorArgs, PolicyArgs},
    runner::prepare_context,
};
use microbox_backend::default_backend;
use serde::Serialize;
use std::{env, path::Path, process::Command};

#[derive(Debug, Serialize)]
struct PeerAvailability {
    docker: bool,
    podman: bool,
    bwrap: bool,
    firejail: bool,
    e2b: bool,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    tool: String,
    platform: String,
    backend: String,
    production_ready: bool,
    secure_enforcement: bool,
    config_found: bool,
    policy_resolved: bool,
    policy_summary: Option<Vec<String>>,
    policy_error: Option<String>,
    features: Vec<String>,
    peer_targets: PeerAvailability,
    e2b_mode: String,
    notes: Vec<String>,
    linux_support: String,
}

pub fn run(args: DoctorArgs) -> Result<i32, microbox_core::SandboxError> {
    let report = build_report(&args.policy);
    let rendered = match args.format {
        DiagnosticFormat::Text => render_text(&report),
        DiagnosticFormat::Json => render_json(&report)?,
    };

    println!("{rendered}");
    Ok(0)
}

fn build_report(policy_args: &PolicyArgs) -> DoctorReport {
    let backend = default_backend();
    let capabilities = backend.capabilities();
    let config_found = policy_config_exists(policy_args);
    let policy_result = prepare_context(policy_args);
    let production_ready = capabilities.secure_enforcement && cfg!(target_os = "linux");
    let policy_summary = policy_result
        .as_ref()
        .ok()
        .map(|context| context.policy.summary_lines());
    let policy_error = policy_result.as_ref().err().map(|error| error.to_string());

    let mut features = vec![
        "cli".to_string(),
        "validate".to_string(),
        "bench".to_string(),
        "benchmark reports".to_string(),
        "peer sandbox comparisons".to_string(),
        "policy compiler".to_string(),
        "preset resolution".to_string(),
        "config discovery".to_string(),
        "persistent workspaces and snapshots".to_string(),
        "cross-platform compat backend".to_string(),
        "Linux outbound allowlists".to_string(),
        "machine-readable doctor output".to_string(),
        "machine-readable validate output".to_string(),
    ];
    if cfg!(target_os = "linux") {
        features.push("Linux secure backend".to_string());
    }

    let notes = capabilities.notes.clone();

    DoctorReport {
        tool: env!("CARGO_PKG_NAME").to_string(),
        platform: format!("{}-{}", env::consts::OS, env::consts::ARCH),
        backend: capabilities.name.to_string(),
        production_ready,
        secure_enforcement: capabilities.secure_enforcement,
        config_found,
        policy_resolved: policy_result.is_ok(),
        policy_summary,
        policy_error,
        features,
        peer_targets: PeerAvailability {
            docker: container_runtime_ready("docker"),
            podman: container_runtime_ready("podman"),
            bwrap: cfg!(target_os = "linux") && binary_available("bwrap"),
            firejail: cfg!(target_os = "linux") && binary_available("firejail"),
            e2b: e2b_available(),
        },
        e2b_mode: e2b_mode().to_string(),
        notes,
        linux_support: if cfg!(target_os = "linux") {
            "secure backend with namespaces, Landlock, seccomp, and cgroup best-effort".to_string()
        } else {
            "build on Linux for full sandbox enforcement".to_string()
        },
    }
}

fn render_text(report: &DoctorReport) -> String {
    let mut lines = vec![
        "MicroBox doctor".to_string(),
        format!("platform = {}", report.platform),
        format!("backend = {}", report.backend),
        format!(
            "production_ready = {}",
            if report.production_ready { "yes" } else { "no" }
        ),
        format!(
            "secure_enforcement = {}",
            if report.secure_enforcement {
                "yes"
            } else {
                "no"
            }
        ),
        format!(
            "config_found = {}",
            if report.config_found { "yes" } else { "no" }
        ),
        format!(
            "policy_resolved = {}",
            if report.policy_resolved { "yes" } else { "no" }
        ),
        format!("features = {}", report.features.join(", ")),
    ];

    if let Some(error) = &report.policy_error {
        lines.push(format!("policy_error = {}", error));
    } else if let Some(summary) = &report.policy_summary {
        lines.push("policy_summary:".to_string());
        for line in summary {
            lines.push(format!("  - {}", line));
        }
    }

    lines.push(format!(
        "peer_targets = docker:{}, podman:{}, bwrap:{}, firejail:{}, e2b:{}",
        flag(report.peer_targets.docker),
        flag(report.peer_targets.podman),
        flag(report.peer_targets.bwrap),
        flag(report.peer_targets.firejail),
        flag(report.peer_targets.e2b)
    ));
    lines.push(format!("e2b_mode = {}", report.e2b_mode));

    if !report.notes.is_empty() {
        lines.push("notes:".to_string());
        for note in &report.notes {
            lines.push(format!("  - {}", note));
        }
    }

    lines.push(format!("linux_support = {}", report.linux_support));

    lines.join("\n")
}

fn render_json(report: &DoctorReport) -> Result<String, microbox_core::SandboxError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| microbox_core::SandboxError::LaunchFailed(error.to_string()))
}

fn flag(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn policy_config_exists(args: &PolicyArgs) -> bool {
    args.config
        .as_ref()
        .map(|path| path.exists())
        .unwrap_or_else(|| Path::new("microbox.toml").exists())
}

fn binary_available(binary: &str) -> bool {
    Command::new(if cfg!(windows) { "where" } else { "which" })
        .arg(binary)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn container_runtime_ready(runtime: &str) -> bool {
    if !binary_available(runtime) {
        return false;
    }

    Command::new(runtime)
        .arg("info")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn e2b_available() -> bool {
    matches!(std::env::var("E2B_API_KEY"), Ok(value) if !value.trim().is_empty())
        && python_available()
}

fn e2b_mode() -> &'static str {
    if std::env::var("E2B_DOMAIN")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        "self-hosted"
    } else if e2b_available() {
        "hosted"
    } else {
        "unavailable"
    }
}

fn python_available() -> bool {
    let candidates = if cfg!(windows) {
        ["python.exe", "python"]
    } else {
        ["python3", "python"]
    };

    candidates.iter().any(|candidate| {
        Command::new(if cfg!(windows) { "where" } else { "which" })
            .arg(candidate)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    })
}
