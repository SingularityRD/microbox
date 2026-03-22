use crate::{args::PolicyArgs, runner::prepare_context};
use microbox_backend::default_backend;
use std::{env, path::Path, process::Command};

pub fn render() -> String {
    let backend = default_backend();
    let capabilities = backend.capabilities();
    let config_exists = Path::new("microbox.toml").exists();
    let production_ready = capabilities.secure_enforcement && cfg!(target_os = "linux");
    let policy_result = prepare_context(&PolicyArgs::default());

    let mut lines = vec![
        format!("MicroBox doctor"),
        format!("platform = {}-{}", env::consts::OS, env::consts::ARCH),
        format!("backend = {}", capabilities.name),
        format!(
            "production_ready = {}",
            if production_ready { "yes" } else { "no" }
        ),
        format!(
            "secure_enforcement = {}",
            if capabilities.secure_enforcement {
                "yes"
            } else {
                "no"
            }
        ),
        format!(
            "config_found = {}",
            if config_exists { "yes" } else { "no" }
        ),
        format!(
            "policy_resolved = {}",
            if policy_result.is_ok() { "yes" } else { "no" }
        ),
        "features = cli, validate, bench, benchmark reports, peer sandbox comparisons, policy compiler, preset resolution, config discovery, cross-platform compat backend, Linux outbound allowlists"
            .to_string(),
    ];

    if let Err(error) = policy_result {
        lines.push(format!("policy_error = {}", error));
    } else if let Ok(context) = &policy_result {
        lines.push("policy_summary:".to_string());
        for line in context.policy.summary_lines() {
            lines.push(format!("  - {}", line));
        }
    }

    lines.push(format!(
        "peer_targets = docker:{}, podman:{}, bwrap:{}, firejail:{}, e2b:{}",
        availability_flag(container_runtime_ready("docker")),
        availability_flag(container_runtime_ready("podman")),
        availability_flag(cfg!(target_os = "linux") && binary_available("bwrap")),
        availability_flag(cfg!(target_os = "linux") && binary_available("firejail")),
        availability_flag(e2b_available())
    ));
    lines.push(format!("e2b_mode = {}", e2b_mode()));

    if !capabilities.notes.is_empty() {
        lines.push("notes:".to_string());
        for note in capabilities.notes {
            lines.push(format!("  - {}", note));
        }
    }

    if cfg!(target_os = "linux") {
        lines.push(
            "linux_support = secure backend with namespaces, Landlock, seccomp, and cgroup best-effort"
                .to_string(),
        );
    } else {
        lines.push("linux_support = build on Linux for full sandbox enforcement".to_string());
    }

    lines.join("\n")
}

fn availability_flag(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
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
