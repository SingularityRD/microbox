use crate::args::BenchmarkProfile;
use crate::args::{BaselineSource, BenchArgs, OutputFormat, PeerTarget};
use crate::runner::{prepare_context, select_backend_for_policy, RunContext};
use microbox_backend::SandboxBackend;
use microbox_core::{shell_escape, CommandPlan, ExecutionResult, RunRequest, SandboxError};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub tool: String,
    pub version: String,
    pub generated_at_unix: u64,
    pub platform: String,
    #[serde(default)]
    pub profile: String,
    pub backend_requested: String,
    pub backend_selected: String,
    pub backend_secure_enforcement: bool,
    pub backend_notes: Vec<String>,
    pub comparison_baseline: String,
    pub policy_resolution_us: u64,
    pub iterations: u32,
    pub warmups: u32,
    pub mode: String,
    pub adoption: AdoptionMetrics,
    pub summary: BenchmarkSummary,
    pub scenarios: Vec<ScenarioReport>,
    #[serde(default)]
    pub peer_reports: Vec<PeerBenchmarkReport>,
    #[serde(default)]
    pub profile_reports: Vec<ProfileBenchmarkReport>,
    pub baseline_report_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileBenchmarkReport {
    pub profile: String,
    pub summary: BenchmarkSummary,
    pub scenarios: Vec<ScenarioReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerBenchmarkReport {
    pub target: String,
    pub available: bool,
    pub reason: Option<String>,
    pub report: Option<Box<BenchmarkReport>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdoptionMetrics {
    pub command_surface: String,
    pub explicit_policy_flags: usize,
    pub explicit_benchmark_flags: usize,
    pub setup_steps: usize,
    pub friction_score: usize,
    pub first_successful_run_us: Option<u64>,
    pub first_successful_scenario: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    pub scenario_count: usize,
    pub passed_scenarios: usize,
    pub failed_scenarios: usize,
    pub matched_baseline_scenarios: usize,
    pub average_of_averages_us: Option<u64>,
    pub fastest_scenario: Option<String>,
    pub fastest_average_us: Option<u64>,
    pub slowest_scenario: Option<String>,
    pub slowest_average_us: Option<u64>,
    pub best_overall_us: Option<u64>,
    pub worst_overall_us: Option<u64>,
    pub first_successful_run_us: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub name: String,
    pub description: String,
    pub command: String,
    pub samples_us: Vec<u64>,
    pub average_us: Option<u64>,
    pub best_us: Option<u64>,
    pub worst_us: Option<u64>,
    pub success: bool,
    pub timed_out: bool,
    pub exit_code: Option<i32>,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub error: Option<String>,
    pub comparison: Option<ScenarioComparison>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioComparison {
    pub baseline_label: String,
    pub baseline_average_us: u64,
    pub delta_us: i64,
    pub delta_percent: Option<f64>,
    pub speedup: Option<f64>,
}

#[derive(Debug, Clone)]
struct BenchmarkScenario {
    name: &'static str,
    description: &'static str,
    command: CommandPlan,
    notes: Vec<&'static str>,
}

#[derive(Debug, Clone)]
struct PortableScenario {
    name: &'static str,
    description: &'static str,
    command: String,
    notes: Vec<&'static str>,
}

pub fn run(args: BenchArgs) -> Result<i32, SandboxError> {
    let prep_start = Instant::now();
    let RunContext {
        working_dir,
        policy,
    } = prepare_context(&args.policy)?;
    let policy_resolution_us = micros_u64(prep_start.elapsed());

    if matches!(args.baseline_source, BaselineSource::E2b) && !args.command.is_empty() {
        return Err(SandboxError::BackendUnavailable(
            "E2B baseline comparison currently supports the built-in benchmark suite only"
                .to_string(),
        ));
    }

    let scenarios = build_scenarios(&args)?;
    let portable_scenarios = build_portable_scenarios(&args)?;
    let scenario_specs = portable_scenarios_to_specs(&portable_scenarios);
    let baseline_report = match args.baseline_source {
        BaselineSource::Report => match args.baseline_report.as_ref() {
            Some(path) => Some(load_report(path)?),
            None => None,
        },
        BaselineSource::E2b => Some(load_e2b_report(&args, &scenario_specs)?),
    };

    let backend: Arc<dyn SandboxBackend> =
        Arc::from(select_backend_for_policy(args.policy.backend)?);
    let backend_name = backend.name().to_string();
    let backend_capabilities = backend.capabilities();
    let run_ctx = BenchmarkRunContext {
        args: &args,
        working_dir: &working_dir,
        policy: &policy,
        policy_resolution_us,
        baseline_report: baseline_report.as_ref(),
        backend,
        backend_name,
        backend_capabilities,
    };

    let report = build_benchmark_report(&run_ctx, scenarios, portable_scenarios, scenario_specs)?;

    if matches!(args.baseline_source, BaselineSource::E2b) {
        if let (Some(output), Some(report)) =
            (args.baseline_output.as_ref(), baseline_report.as_ref())
        {
            let raw = serde_json::to_string_pretty(report)
                .map_err(|error| SandboxError::LaunchFailed(error.to_string()))?;
            fs::write(output, raw).map_err(|error| SandboxError::Io(error.to_string()))?;
        }
    }

    let rendered = render_report(&report, args.format)?;
    println!("{rendered}");

    if let Some(output) = args.output.as_ref() {
        fs::write(output, &rendered).map_err(|error| SandboxError::Io(error.to_string()))?;
    }

    Ok(if report.summary.failed_scenarios == 0 {
        0
    } else {
        1
    })
}

fn build_scenarios(args: &BenchArgs) -> Result<Vec<BenchmarkScenario>, SandboxError> {
    if !args.command.is_empty() {
        return Ok(vec![BenchmarkScenario {
            name: "custom-command",
            description: "User-supplied benchmark command",
            command: CommandPlan::from_raw(args.command.clone())?,
            notes: vec!["Benchmarks the exact command path the user provided."],
        }]);
    }

    Ok(vec![
        BenchmarkScenario {
            name: "startup-noop",
            description: "Pure launch overhead for a successful no-op command",
            command: startup_noop_command(),
            notes: vec![
                "Approximates the minimum cost of launching a sandboxed command.",
                "Useful for comparing spawn overhead across backends.",
            ],
        },
        BenchmarkScenario {
            name: "shell-echo",
            description: "Shell entrypoint and stdout roundtrip",
            command: CommandPlan::Shell {
                command: "echo microbox".to_string(),
            },
            notes: vec![
                "Represents zero-change DX where users keep their original shell workflow.",
                "Exercises shell parsing and output plumbing.",
            ],
        },
        BenchmarkScenario {
            name: "workspace-write",
            description: "Writable workspace roundtrip",
            command: workspace_write_command(),
            notes: vec![
                "Confirms the default code-edit friendly workspace policy.",
                "Matches the 'run code without modifying source' onboarding path.",
            ],
        },
    ])
}

fn build_portable_scenarios(args: &BenchArgs) -> Result<Vec<PortableScenario>, SandboxError> {
    if !args.command.is_empty() {
        return Ok(vec![PortableScenario {
            name: "custom-command",
            description: "User-supplied benchmark command",
            command: portable_command_string(&CommandPlan::from_raw(args.command.clone())?),
            notes: vec!["Benchmarks the exact command path the user provided."],
        }]);
    }

    Ok(vec![
        PortableScenario {
            name: "startup-noop",
            description: "Pure launch overhead for a successful no-op command",
            command: "true".to_string(),
            notes: vec![
                "Approximates the minimum cost of launching a sandboxed command.",
                "Useful for comparing spawn overhead across backends.",
            ],
        },
        PortableScenario {
            name: "shell-echo",
            description: "Shell entrypoint and stdout roundtrip",
            command: "echo microbox".to_string(),
            notes: vec![
                "Represents zero-change DX where users keep their original shell workflow.",
                "Exercises shell parsing and output plumbing.",
            ],
        },
        PortableScenario {
            name: "workspace-write",
            description: "Writable workspace roundtrip",
            command: "printf microbox > .microbox-bench-write && rm -f .microbox-bench-write"
                .to_string(),
            notes: vec![
                "Confirms the default code-edit friendly workspace policy.",
                "Matches the 'run code without modifying source' onboarding path.",
            ],
        },
    ])
}

fn portable_scenarios_to_specs(scenarios: &[PortableScenario]) -> Vec<RemoteScenarioSpec> {
    scenarios
        .iter()
        .map(|scenario| RemoteScenarioSpec {
            name: scenario.name.to_string(),
            description: scenario.description.to_string(),
            command: scenario.command.clone(),
            notes: scenario
                .notes
                .iter()
                .map(|note| (*note).to_string())
                .collect(),
        })
        .collect()
}

fn portable_command_string(plan: &CommandPlan) -> String {
    match plan {
        CommandPlan::Direct { argv } => argv
            .iter()
            .map(|arg| shell_escape(arg))
            .collect::<Vec<_>>()
            .join(" "),
        CommandPlan::Shell { command } => command.clone(),
    }
}

fn run_scenario(
    context: &mut ScenarioRunContext<'_>,
    scenario: BenchmarkScenario,
    iterations: u32,
    warmups: u32,
    profile: BenchmarkProfile,
    stagger_delay_ms: u64,
) -> ScenarioReport {
    let request = RunRequest::new(
        scenario.command.clone(),
        context.working_dir.to_path_buf(),
        context.policy.clone(),
    );
    let notes = scenario
        .notes
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();

    for warmup_index in 0..warmups {
        let result = match context.backend.run(&request) {
            Ok(result) => result,
            Err(error) => {
                return ScenarioReport {
                    name: scenario.name.to_string(),
                    description: scenario.description.to_string(),
                    command: scenario.command.display(),
                    samples_us: Vec::new(),
                    average_us: None,
                    best_us: None,
                    worst_us: None,
                    success: false,
                    timed_out: false,
                    exit_code: None,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    error: Some(format!("warmup {warmup_index} failed: {error}")),
                    comparison: None,
                    notes,
                };
            }
        };
        if result.timed_out {
            return ScenarioReport {
                name: scenario.name.to_string(),
                description: scenario.description.to_string(),
                command: scenario.command.display(),
                samples_us: Vec::new(),
                average_us: None,
                best_us: None,
                worst_us: None,
                success: false,
                timed_out: true,
                exit_code: Some(result.exit_code()),
                stdout_bytes: result.stdout.len(),
                stderr_bytes: result.stderr.len(),
                error: Some(format!("warmup {warmup_index} timed out")),
                comparison: None,
                notes,
            };
        }
    }

    let sample_results = run_sample_batch(
        context.backend.clone(),
        &request,
        profile,
        iterations,
        stagger_delay_ms,
    );

    let mut samples = Vec::with_capacity(sample_results.len());
    let mut best: Option<u64> = None;
    let mut worst: Option<u64> = None;
    let mut exit_code = None;
    let mut timed_out = false;
    let mut stdout_bytes = 0usize;
    let mut stderr_bytes = 0usize;
    let mut error = None;

    for result in sample_results {
        match result {
            Ok(result) => {
                let sample_us = micros_u64(result.duration);
                if context.first_successful_run_us.is_none()
                    && !result.timed_out
                    && result.exit_code() == 0
                {
                    *context.first_successful_run_us =
                        Some(micros_u64(context.benchmark_started.elapsed()));
                    *context.first_successful_scenario = Some(scenario.name.to_string());
                }

                stdout_bytes += result.stdout.len();
                stderr_bytes += result.stderr.len();
                timed_out |= result.timed_out;
                exit_code = Some(result.exit_code());
                samples.push(sample_us);
                best = Some(best.map_or(sample_us, |current: u64| current.min(sample_us)));
                worst = Some(worst.map_or(sample_us, |current: u64| current.max(sample_us)));

                if result.exit_code() != 0 {
                    error = Some(format!("command exited with {}", result.exit_code()));
                    break;
                }
            }
            Err(run_error) => {
                error = Some(run_error.to_string());
                break;
            }
        }
    }

    let average_us = if samples.is_empty() {
        None
    } else {
        Some((samples.iter().copied().sum::<u64>() / samples.len() as u64).max(1))
    };

    let success = error.is_none() && !samples.is_empty() && !timed_out;

    ScenarioReport {
        name: scenario.name.to_string(),
        description: scenario.description.to_string(),
        command: scenario.command.display(),
        samples_us: samples,
        average_us,
        best_us: best,
        worst_us: worst,
        success,
        timed_out,
        exit_code,
        stdout_bytes,
        stderr_bytes,
        error,
        comparison: None,
        notes,
    }
}

struct ScenarioRunContext<'a> {
    backend: Arc<dyn SandboxBackend>,
    working_dir: &'a Path,
    policy: &'a microbox_policy::ResolvedPolicy,
    benchmark_started: Instant,
    first_successful_run_us: &'a mut Option<u64>,
    first_successful_scenario: &'a mut Option<String>,
}

struct BenchmarkRunContext<'a> {
    args: &'a BenchArgs,
    working_dir: &'a Path,
    policy: &'a microbox_policy::ResolvedPolicy,
    policy_resolution_us: u64,
    baseline_report: Option<&'a BenchmarkReport>,
    backend: Arc<dyn SandboxBackend>,
    backend_name: String,
    backend_capabilities: microbox_backend::BackendCapabilities,
}

fn build_benchmark_report(
    ctx: &BenchmarkRunContext<'_>,
    scenarios: Vec<BenchmarkScenario>,
    portable_scenarios: Vec<PortableScenario>,
    scenario_specs: Vec<RemoteScenarioSpec>,
) -> Result<BenchmarkReport, SandboxError> {
    let requested_profile = ctx.args.profile;

    let profile_reports = if requested_profile == BenchmarkProfile::All {
        let mut reports = Vec::new();
        for profile in [
            BenchmarkProfile::Sequential,
            BenchmarkProfile::Staggered,
            BenchmarkProfile::Burst,
        ] {
            let report = build_profile_report(
                ctx,
                scenarios.clone(),
                portable_scenarios.clone(),
                scenario_specs.clone(),
                profile,
            )?;
            reports.push(report);
        }
        reports
    } else {
        Vec::new()
    };

    let primary_profile = if requested_profile == BenchmarkProfile::All {
        BenchmarkProfile::Sequential
    } else {
        requested_profile
    };

    let mut report = build_profile_report(
        ctx,
        scenarios,
        portable_scenarios,
        scenario_specs,
        primary_profile,
    )?;

    if requested_profile == BenchmarkProfile::All {
        report.profile = "all".to_string();
        report.profile_reports = profile_reports
            .into_iter()
            .map(|profile_report| ProfileBenchmarkReport {
                profile: profile_report.profile,
                summary: profile_report.summary,
                scenarios: profile_report.scenarios,
            })
            .collect();
    }

    Ok(report)
}

fn build_profile_report(
    ctx: &BenchmarkRunContext<'_>,
    scenarios: Vec<BenchmarkScenario>,
    portable_scenarios: Vec<PortableScenario>,
    scenario_specs: Vec<RemoteScenarioSpec>,
    profile: BenchmarkProfile,
) -> Result<BenchmarkReport, SandboxError> {
    let benchmark_started = Instant::now();
    let mut first_successful_run_us = None;
    let mut first_successful_scenario = None;
    let mut scenario_reports = Vec::with_capacity(scenarios.len());

    for scenario in scenarios {
        let mut run_context = ScenarioRunContext {
            backend: Arc::clone(&ctx.backend),
            working_dir: ctx.working_dir,
            policy: ctx.policy,
            benchmark_started,
            first_successful_run_us: &mut first_successful_run_us,
            first_successful_scenario: &mut first_successful_scenario,
        };
        let report = run_scenario(
            &mut run_context,
            scenario,
            ctx.args.iterations.max(1),
            ctx.args.warmups,
            profile,
            ctx.args.stagger_delay_ms,
        );
        scenario_reports.push(report);
    }

    let comparison_baseline = ctx.args.baseline_label.clone();
    let scenario_reports =
        attach_comparisons(scenario_reports, ctx.baseline_report, &comparison_baseline);

    let peer_reports = build_peer_reports(
        ctx.args,
        ctx.working_dir,
        ctx.policy,
        &portable_scenarios,
        &scenario_specs,
    );

    let summary = summarize(&scenario_reports, first_successful_run_us);
    let adoption = AdoptionMetrics {
        command_surface: "microbox run <command>".to_string(),
        explicit_policy_flags: count_explicit_policy_flags(&ctx.args.policy),
        explicit_benchmark_flags: count_explicit_benchmark_flags(ctx.args),
        setup_steps: 1
            + count_explicit_policy_flags(&ctx.args.policy)
            + count_explicit_benchmark_flags(ctx.args),
        friction_score: 1
            + count_explicit_policy_flags(&ctx.args.policy)
            + count_explicit_benchmark_flags(ctx.args),
        first_successful_run_us,
        first_successful_scenario,
    };

    Ok(BenchmarkReport {
        tool: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at_unix: system_time_unix_secs(),
        platform: format!(
            "{}-{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::env::consts::FAMILY
        ),
        profile: benchmark_profile_label(profile),
        backend_requested: ctx.args.policy.backend.to_string(),
        backend_selected: ctx.backend_name.clone(),
        backend_secure_enforcement: ctx.backend_capabilities.secure_enforcement,
        backend_notes: ctx.backend_capabilities.notes.clone(),
        comparison_baseline,
        policy_resolution_us: ctx.policy_resolution_us,
        iterations: ctx.args.iterations.max(1),
        warmups: ctx.args.warmups,
        mode: if ctx.args.command.is_empty() {
            "suite".to_string()
        } else {
            "custom-command".to_string()
        },
        adoption,
        summary,
        scenarios: scenario_reports,
        peer_reports,
        profile_reports: Vec::new(),
        baseline_report_path: match ctx.args.baseline_source {
            BaselineSource::Report => ctx.args.baseline_report.clone(),
            BaselineSource::E2b => ctx.args.baseline_output.clone(),
        },
    })
}

fn run_sample_batch(
    backend: Arc<dyn SandboxBackend>,
    request: &RunRequest,
    profile: BenchmarkProfile,
    iterations: u32,
    stagger_delay_ms: u64,
) -> Vec<Result<ExecutionResult, SandboxError>> {
    match profile {
        BenchmarkProfile::Sequential => (0..iterations)
            .map(|_| backend.run(request))
            .collect::<Vec<_>>(),
        BenchmarkProfile::Staggered => {
            let mut results = Vec::with_capacity(iterations as usize);
            for index in 0..iterations {
                results.push(backend.run(request));
                if index + 1 < iterations {
                    thread::sleep(Duration::from_millis(stagger_delay_ms));
                }
            }
            results
        }
        BenchmarkProfile::Burst => {
            let mut handles = Vec::with_capacity(iterations as usize);
            for _ in 0..iterations {
                let backend = Arc::clone(&backend);
                let request = request.clone();
                handles.push(thread::spawn(move || backend.run(&request)));
            }
            handles
                .into_iter()
                .map(|handle| {
                    handle.join().map_err(|_| {
                        SandboxError::LaunchFailed(
                            "burst benchmark worker thread panicked".to_string(),
                        )
                    })?
                })
                .collect::<Vec<_>>()
        }
        BenchmarkProfile::All => unreachable!("all is expanded before execution"),
    }
}

fn benchmark_profile_label(profile: BenchmarkProfile) -> String {
    match profile {
        BenchmarkProfile::Sequential => "sequential".to_string(),
        BenchmarkProfile::Staggered => "staggered".to_string(),
        BenchmarkProfile::Burst => "burst".to_string(),
        BenchmarkProfile::All => "all".to_string(),
    }
}

fn attach_comparisons(
    reports: Vec<ScenarioReport>,
    baseline: Option<&BenchmarkReport>,
    baseline_label: &str,
) -> Vec<ScenarioReport> {
    let Some(baseline) = baseline else {
        return reports;
    };

    let baseline_map: HashMap<&str, &ScenarioReport> = baseline
        .scenarios
        .iter()
        .map(|scenario| (scenario.name.as_str(), scenario))
        .collect();

    reports
        .into_iter()
        .map(|mut report| {
            if let (Some(current), Some(base)) =
                (report.average_us, baseline_map.get(report.name.as_str()))
            {
                if let Some(baseline_average_us) = base.average_us {
                    let delta_us = current as i64 - baseline_average_us as i64;
                    let delta_percent = if baseline_average_us == 0 {
                        None
                    } else {
                        Some((delta_us as f64 / baseline_average_us as f64) * 100.0)
                    };
                    let speedup = if current == 0 {
                        None
                    } else {
                        Some(baseline_average_us as f64 / current as f64)
                    };
                    report.comparison = Some(ScenarioComparison {
                        baseline_label: baseline_label.to_string(),
                        baseline_average_us,
                        delta_us,
                        delta_percent,
                        speedup,
                    });
                }
            }
            report
        })
        .collect()
}

fn summarize(reports: &[ScenarioReport], first_successful_run_us: Option<u64>) -> BenchmarkSummary {
    let mut passed_scenarios = 0usize;
    let mut failed_scenarios = 0usize;
    let mut matched_baseline_scenarios = 0usize;
    let mut best_overall_us: Option<u64> = None;
    let mut worst_overall_us: Option<u64> = None;
    let mut fastest_scenario = None;
    let mut slowest_scenario = None;
    let mut fastest_average_us = None;
    let mut slowest_average_us = None;
    let mut average_sum = 0u64;
    let mut average_count = 0u64;

    for report in reports {
        if report.success {
            passed_scenarios += 1;
        } else {
            failed_scenarios += 1;
        }

        if report.comparison.is_some() {
            matched_baseline_scenarios += 1;
        }

        if let Some(avg) = report.average_us {
            average_sum = average_sum.saturating_add(avg);
            average_count += 1;

            if fastest_average_us.map_or(true, |current| avg < current) {
                fastest_average_us = Some(avg);
                fastest_scenario = Some(report.name.clone());
            }
            if slowest_average_us.map_or(true, |current| avg > current) {
                slowest_average_us = Some(avg);
                slowest_scenario = Some(report.name.clone());
            }
        }

        if let Some(best) = report.best_us {
            best_overall_us = Some(best_overall_us.map_or(best, |current: u64| current.min(best)));
        }
        if let Some(worst) = report.worst_us {
            worst_overall_us =
                Some(worst_overall_us.map_or(worst, |current: u64| current.max(worst)));
        }
    }

    BenchmarkSummary {
        scenario_count: reports.len(),
        passed_scenarios,
        failed_scenarios,
        matched_baseline_scenarios,
        average_of_averages_us: if average_count == 0 {
            None
        } else {
            Some(average_sum / average_count)
        },
        fastest_scenario,
        fastest_average_us,
        slowest_scenario,
        slowest_average_us,
        best_overall_us,
        worst_overall_us,
        first_successful_run_us,
    }
}

fn render_report(report: &BenchmarkReport, format: OutputFormat) -> Result<String, SandboxError> {
    match format {
        OutputFormat::Text => Ok(render_text(report)),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| SandboxError::LaunchFailed(error.to_string())),
        OutputFormat::Markdown => Ok(render_markdown(report)),
    }
}

fn render_text(report: &BenchmarkReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "MicroBox benchmark report");
    let _ = writeln!(output, "tool = {}", report.tool);
    let _ = writeln!(output, "version = {}", report.version);
    let _ = writeln!(output, "profile = {}", report.profile);
    let _ = writeln!(output, "platform = {}", report.platform);
    let _ = writeln!(output, "backend_requested = {}", report.backend_requested);
    let _ = writeln!(output, "backend_selected = {}", report.backend_selected);
    let _ = writeln!(
        output,
        "backend_secure_enforcement = {}",
        report.backend_secure_enforcement
    );
    for note in &report.backend_notes {
        let _ = writeln!(output, "backend_note = {}", note);
    }
    let _ = writeln!(
        output,
        "comparison_baseline = {}",
        report.comparison_baseline
    );
    let _ = writeln!(output, "mode = {}", report.mode);
    let _ = writeln!(
        output,
        "policy_resolution_us = {}",
        report.policy_resolution_us
    );
    let _ = writeln!(output, "iterations = {}", report.iterations);
    let _ = writeln!(output, "warmups = {}", report.warmups);
    let _ = writeln!(output);
    let _ = writeln!(output, "Adoption");
    let _ = writeln!(
        output,
        "command_surface = {}",
        report.adoption.command_surface
    );
    let _ = writeln!(
        output,
        "explicit_policy_flags = {}",
        report.adoption.explicit_policy_flags
    );
    let _ = writeln!(
        output,
        "explicit_benchmark_flags = {}",
        report.adoption.explicit_benchmark_flags
    );
    let _ = writeln!(output, "setup_steps = {}", report.adoption.setup_steps);
    let _ = writeln!(
        output,
        "friction_score = {}",
        report.adoption.friction_score
    );
    let _ = writeln!(
        output,
        "first_successful_run_us = {}",
        format_opt_u64(report.adoption.first_successful_run_us)
    );
    let _ = writeln!(
        output,
        "first_successful_scenario = {}",
        report
            .adoption
            .first_successful_scenario
            .as_deref()
            .unwrap_or("-")
    );
    let _ = writeln!(output);
    let _ = writeln!(output, "Summary");
    let _ = writeln!(output, "scenario_count = {}", report.summary.scenario_count);
    let _ = writeln!(
        output,
        "passed_scenarios = {}",
        report.summary.passed_scenarios
    );
    let _ = writeln!(
        output,
        "failed_scenarios = {}",
        report.summary.failed_scenarios
    );
    let _ = writeln!(
        output,
        "matched_baseline_scenarios = {}",
        report.summary.matched_baseline_scenarios
    );
    let _ = writeln!(
        output,
        "average_of_averages_us = {}",
        format_opt_u64(report.summary.average_of_averages_us)
    );
    let _ = writeln!(
        output,
        "fastest_scenario = {}",
        report.summary.fastest_scenario.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        output,
        "fastest_average_us = {}",
        format_opt_u64(report.summary.fastest_average_us)
    );
    let _ = writeln!(
        output,
        "slowest_scenario = {}",
        report.summary.slowest_scenario.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        output,
        "slowest_average_us = {}",
        format_opt_u64(report.summary.slowest_average_us)
    );
    let _ = writeln!(
        output,
        "best_overall_us = {}",
        format_opt_u64(report.summary.best_overall_us)
    );
    let _ = writeln!(
        output,
        "worst_overall_us = {}",
        format_opt_u64(report.summary.worst_overall_us)
    );

    let _ = writeln!(output);
    let _ = writeln!(output, "Scenarios");
    for scenario in &report.scenarios {
        let _ = writeln!(output, "- {}", scenario.name);
        let _ = writeln!(output, "  description = {}", scenario.description);
        let _ = writeln!(output, "  command = {}", scenario.command);
        let _ = writeln!(output, "  success = {}", scenario.success);
        let _ = writeln!(output, "  timed_out = {}", scenario.timed_out);
        let _ = writeln!(
            output,
            "  exit_code = {}",
            scenario
                .exit_code
                .map_or("-".to_string(), |value| value.to_string())
        );
        let _ = writeln!(
            output,
            "  average_us = {}",
            format_opt_u64(scenario.average_us)
        );
        let _ = writeln!(output, "  best_us = {}", format_opt_u64(scenario.best_us));
        let _ = writeln!(output, "  worst_us = {}", format_opt_u64(scenario.worst_us));
        let _ = writeln!(output, "  stdout_bytes = {}", scenario.stdout_bytes);
        let _ = writeln!(output, "  stderr_bytes = {}", scenario.stderr_bytes);
        if let Some(error) = &scenario.error {
            let _ = writeln!(output, "  error = {}", error);
        }
        if let Some(comparison) = &scenario.comparison {
            let _ = writeln!(output, "  baseline_label = {}", comparison.baseline_label);
            let _ = writeln!(
                output,
                "  baseline_average_us = {}",
                comparison.baseline_average_us
            );
            let _ = writeln!(output, "  delta_us = {}", comparison.delta_us);
            let _ = writeln!(
                output,
                "  delta_percent = {}",
                comparison
                    .delta_percent
                    .map_or_else(|| "-".to_string(), |value| format!("{value:.2}"))
            );
            let _ = writeln!(
                output,
                "  speedup = {}",
                comparison
                    .speedup
                    .map_or_else(|| "-".to_string(), |value| format!("{value:.2}x"))
            );
        }
        for note in &scenario.notes {
            let _ = writeln!(output, "  note = {}", note);
        }
    }

    if !report.peer_reports.is_empty() {
        let _ = writeln!(output);
        let _ = writeln!(output, "Peer targets");
        for peer in &report.peer_reports {
            let _ = writeln!(
                output,
                "- target = {} available = {}",
                peer.target,
                if peer.available { "yes" } else { "no" }
            );
            if let Some(reason) = &peer.reason {
                let _ = writeln!(output, "  reason = {}", reason);
            }
            if let Some(peer_report) = &peer.report {
                let _ = writeln!(
                    output,
                    "  passed_scenarios = {}",
                    peer_report.summary.passed_scenarios
                );
                let _ = writeln!(
                    output,
                    "  failed_scenarios = {}",
                    peer_report.summary.failed_scenarios
                );
                let _ = writeln!(
                    output,
                    "  average_of_averages_us = {}",
                    format_opt_u64(peer_report.summary.average_of_averages_us)
                );
                let _ = writeln!(
                    output,
                    "  fastest_scenario = {}",
                    peer_report
                        .summary
                        .fastest_scenario
                        .as_deref()
                        .unwrap_or("-")
                );
                let _ = writeln!(
                    output,
                    "  slowest_scenario = {}",
                    peer_report
                        .summary
                        .slowest_scenario
                        .as_deref()
                        .unwrap_or("-")
                );
            }
        }
    }

    if !report.profile_reports.is_empty() {
        let _ = writeln!(output);
        let _ = writeln!(output, "Profile runs");
        for profile in &report.profile_reports {
            let _ = writeln!(output, "- profile = {}", profile.profile);
            let _ = writeln!(
                output,
                "  scenario_count = {}",
                profile.summary.scenario_count
            );
            let _ = writeln!(
                output,
                "  passed_scenarios = {}",
                profile.summary.passed_scenarios
            );
            let _ = writeln!(
                output,
                "  failed_scenarios = {}",
                profile.summary.failed_scenarios
            );
            let _ = writeln!(
                output,
                "  average_of_averages_us = {}",
                format_opt_u64(profile.summary.average_of_averages_us)
            );
            let _ = writeln!(
                output,
                "  fastest_scenario = {}",
                profile.summary.fastest_scenario.as_deref().unwrap_or("-")
            );
            let _ = writeln!(
                output,
                "  slowest_scenario = {}",
                profile.summary.slowest_scenario.as_deref().unwrap_or("-")
            );
        }
    }

    output
}

fn render_markdown(report: &BenchmarkReport) -> String {
    let has_comparison = report
        .scenarios
        .iter()
        .any(|scenario| scenario.comparison.is_some());
    let mut output = String::new();
    let _ = writeln!(output, "# MicroBox benchmark report");
    let _ = writeln!(output);
    let _ = writeln!(output, "- Tool: `{}`", report.tool);
    let _ = writeln!(output, "- Version: `{}`", report.version);
    let _ = writeln!(output, "- Profile: `{}`", report.profile);
    let _ = writeln!(output, "- Platform: `{}`", report.platform);
    let _ = writeln!(
        output,
        "- Backend requested: `{}`",
        report.backend_requested
    );
    let _ = writeln!(output, "- Backend selected: `{}`", report.backend_selected);
    let _ = writeln!(
        output,
        "- Secure enforcement: `{}`",
        report.backend_secure_enforcement
    );
    let _ = writeln!(
        output,
        "- Comparison baseline: `{}`",
        report.comparison_baseline
    );
    let _ = writeln!(output, "- Mode: `{}`", report.mode);
    let _ = writeln!(
        output,
        "- Policy resolution: `{}` us",
        report.policy_resolution_us
    );
    let _ = writeln!(output, "- Iterations: `{}`", report.iterations);
    let _ = writeln!(output, "- Warmups: `{}`", report.warmups);
    if !report.backend_notes.is_empty() {
        let _ = writeln!(output);
        let _ = writeln!(output, "### Backend notes");
        for note in &report.backend_notes {
            let _ = writeln!(output, "- {}", note);
        }
    }
    let _ = writeln!(output);
    let _ = writeln!(output, "## Adoption");
    let _ = writeln!(
        output,
        "- Command surface: `{}`",
        report.adoption.command_surface
    );
    let _ = writeln!(
        output,
        "- Explicit policy flags: `{}`",
        report.adoption.explicit_policy_flags
    );
    let _ = writeln!(
        output,
        "- Explicit benchmark flags: `{}`",
        report.adoption.explicit_benchmark_flags
    );
    let _ = writeln!(output, "- Setup steps: `{}`", report.adoption.setup_steps);
    let _ = writeln!(
        output,
        "- Friction score: `{}`",
        report.adoption.friction_score
    );
    let _ = writeln!(
        output,
        "- First successful run: `{}` us",
        format_opt_u64(report.adoption.first_successful_run_us)
    );
    let _ = writeln!(
        output,
        "- First successful scenario: `{}`",
        report
            .adoption
            .first_successful_scenario
            .as_deref()
            .unwrap_or("-")
    );
    let _ = writeln!(output);
    let _ = writeln!(output, "## Summary");
    let _ = writeln!(output, "- Scenarios: `{}`", report.summary.scenario_count);
    let _ = writeln!(output, "- Passed: `{}`", report.summary.passed_scenarios);
    let _ = writeln!(output, "- Failed: `{}`", report.summary.failed_scenarios);
    let _ = writeln!(
        output,
        "- Baseline matches: `{}`",
        report.summary.matched_baseline_scenarios
    );
    let _ = writeln!(
        output,
        "- Average of averages: `{}` us",
        format_opt_u64(report.summary.average_of_averages_us)
    );
    let _ = writeln!(
        output,
        "- Fastest scenario: `{}`",
        report.summary.fastest_scenario.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        output,
        "- Fastest average: `{}` us",
        format_opt_u64(report.summary.fastest_average_us)
    );
    let _ = writeln!(
        output,
        "- Slowest scenario: `{}`",
        report.summary.slowest_scenario.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        output,
        "- Slowest average: `{}` us",
        format_opt_u64(report.summary.slowest_average_us)
    );
    let _ = writeln!(
        output,
        "- Best overall sample: `{}` us",
        format_opt_u64(report.summary.best_overall_us)
    );
    let _ = writeln!(
        output,
        "- Worst overall sample: `{}` us",
        format_opt_u64(report.summary.worst_overall_us)
    );
    let _ = writeln!(output);
    let _ = writeln!(output, "## Scenarios");
    let _ = writeln!(output);
    if has_comparison {
        let _ = writeln!(
            output,
            "| Scenario | Success | Avg (us) | Best (us) | Worst (us) | Baseline (us) | Delta (us) | Speedup | Notes |"
        );
        let _ = writeln!(
            output,
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |"
        );
    } else {
        let _ = writeln!(
            output,
            "| Scenario | Success | Avg (us) | Best (us) | Worst (us) | Notes |"
        );
        let _ = writeln!(output, "| --- | --- | ---: | ---: | ---: | --- |");
    }

    for scenario in &report.scenarios {
        let notes = scenario.notes.join(" · ");
        if let Some(comparison) = &scenario.comparison {
            let _ = writeln!(
                output,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                escape_md(&scenario.name),
                if scenario.success { "yes" } else { "no" },
                format_opt_u64(scenario.average_us),
                format_opt_u64(scenario.best_us),
                format_opt_u64(scenario.worst_us),
                comparison.baseline_average_us,
                comparison.delta_us,
                comparison
                    .speedup
                    .map_or_else(|| "-".to_string(), |value| format!("{value:.2}x")),
                escape_md(&notes),
            );
        } else {
            let _ = writeln!(
                output,
                "| {} | {} | {} | {} | {} | {} |",
                escape_md(&scenario.name),
                if scenario.success { "yes" } else { "no" },
                format_opt_u64(scenario.average_us),
                format_opt_u64(scenario.best_us),
                format_opt_u64(scenario.worst_us),
                escape_md(&notes),
            );
        }
    }

    if !report.peer_reports.is_empty() {
        let _ = writeln!(output);
        let _ = writeln!(output, "## Peer Targets");
        let _ = writeln!(output);
        let _ = writeln!(
            output,
            "| Target | Available | Passed | Failed | Avg of avgs (us) | Notes |"
        );
        let _ = writeln!(output, "| --- | --- | ---: | ---: | ---: | --- |");
        for peer in &report.peer_reports {
            let (passed, failed, avg) = if let Some(peer_report) = &peer.report {
                (
                    peer_report.summary.passed_scenarios.to_string(),
                    peer_report.summary.failed_scenarios.to_string(),
                    format_opt_u64(peer_report.summary.average_of_averages_us),
                )
            } else {
                ("-".to_string(), "-".to_string(), "-".to_string())
            };
            let notes = peer
                .reason
                .as_deref()
                .map_or_else(|| "-".to_string(), escape_md);
            let _ = writeln!(
                output,
                "| {} | {} | {} | {} | {} | {} |",
                escape_md(&peer.target),
                if peer.available { "yes" } else { "no" },
                passed,
                failed,
                avg,
                notes,
            );
        }
    }

    if !report.profile_reports.is_empty() {
        let _ = writeln!(output);
        let _ = writeln!(output, "## Profile Runs");
        let _ = writeln!(output);
        let _ = writeln!(
            output,
            "| Profile | Scenarios | Passed | Failed | Avg of avgs (us) | Fastest | Slowest |"
        );
        let _ = writeln!(output, "| --- | ---: | ---: | ---: | ---: | --- | --- |");
        for profile in &report.profile_reports {
            let _ = writeln!(
                output,
                "| {} | {} | {} | {} | {} | {} | {} |",
                escape_md(&profile.profile),
                profile.summary.scenario_count,
                profile.summary.passed_scenarios,
                profile.summary.failed_scenarios,
                format_opt_u64(profile.summary.average_of_averages_us),
                escape_md(profile.summary.fastest_scenario.as_deref().unwrap_or("-")),
                escape_md(profile.summary.slowest_scenario.as_deref().unwrap_or("-")),
            );
        }
    }

    output
}

fn load_report(path: &Path) -> Result<BenchmarkReport, SandboxError> {
    let raw = fs::read_to_string(path).map_err(|error| SandboxError::Io(error.to_string()))?;
    serde_json::from_str(&raw).map_err(|error| {
        SandboxError::LaunchFailed(format!(
            "failed to parse baseline benchmark report {}: {error}",
            path.display()
        ))
    })
}

fn load_e2b_report(
    args: &BenchArgs,
    scenarios: &[RemoteScenarioSpec],
) -> Result<BenchmarkReport, SandboxError> {
    let api_key = std::env::var("E2B_API_KEY").map_err(|_| {
        SandboxError::BackendUnavailable(
            "E2B_API_KEY is required for --baseline-source e2b".to_string(),
        )
    })?;

    if api_key.trim().is_empty() {
        return Err(SandboxError::BackendUnavailable(
            "E2B_API_KEY is empty".to_string(),
        ));
    }

    let temp_root = std::env::temp_dir().join(format!(
        "microbox-e2b-{}",
        system_time_unix_secs().saturating_add(std::process::id() as u64)
    ));
    fs::create_dir_all(&temp_root).map_err(|error| SandboxError::Io(error.to_string()))?;

    let request_path = temp_root.join("request.json");
    let report_path = temp_root.join("report.json");
    let script_path = temp_root.join("e2b_benchmark.py");
    let venv_path = temp_root.join("venv");

    let request = RemoteBenchmarkRequest {
        iterations: args.iterations.max(1),
        warmups: args.warmups,
        timeout_secs: args.e2b_timeout_secs,
        scenarios: scenarios.to_vec(),
        e2b_domain: std::env::var("E2B_DOMAIN").ok(),
    };

    let request_json = serde_json::to_string_pretty(&request)
        .map_err(|error| SandboxError::LaunchFailed(error.to_string()))?;
    fs::write(&request_path, request_json).map_err(|error| SandboxError::Io(error.to_string()))?;
    fs::write(&script_path, E2B_BENCHMARK_SCRIPT)
        .map_err(|error| SandboxError::Io(error.to_string()))?;

    let python = find_python_executable()?;
    ensure_e2b_venv(&python, &venv_path)?;
    let runner = venv_python_path(&venv_path);
    let output = Command::new(&runner)
        .arg(&script_path)
        .arg(&request_path)
        .arg(&report_path)
        .env("E2B_API_KEY", api_key)
        .output()
        .map_err(|error| {
            SandboxError::LaunchFailed(format!("failed to run E2B benchmark: {error}"))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::LaunchFailed(format!(
            "E2B benchmark failed: {}",
            stderr.trim()
        )));
    }

    let raw = fs::read_to_string(&report_path).map_err(|error| {
        SandboxError::LaunchFailed(format!("failed to read E2B report: {error}"))
    })?;
    serde_json::from_str(&raw)
        .map_err(|error| SandboxError::LaunchFailed(format!("failed to parse E2B report: {error}")))
}

fn ensure_e2b_venv(python: &Path, venv_path: &Path) -> Result<(), SandboxError> {
    if venv_python_path(venv_path).exists() {
        return Ok(());
    }

    let venv_status = Command::new(python)
        .args(["-m", "venv"])
        .arg(venv_path)
        .status()
        .map_err(|error| {
            SandboxError::LaunchFailed(format!("failed to create E2B venv: {error}"))
        })?;
    if !venv_status.success() {
        return Err(SandboxError::LaunchFailed(
            "failed to create E2B benchmark virtual environment".to_string(),
        ));
    }

    let pip = venv_python_path(venv_path);
    let install_status = Command::new(&pip)
        .args(["-m", "pip", "install", "--upgrade", "pip", "e2b"])
        .status()
        .map_err(|error| {
            SandboxError::LaunchFailed(format!("failed to install E2B SDK: {error}"))
        })?;
    if !install_status.success() {
        return Err(SandboxError::LaunchFailed(
            "failed to install E2B SDK into the benchmark virtual environment".to_string(),
        ));
    }

    Ok(())
}

fn find_python_executable() -> Result<PathBuf, SandboxError> {
    let candidates = if cfg!(windows) {
        vec!["python.exe", "python"]
    } else {
        vec!["python3", "python"]
    };

    for candidate in candidates {
        if let Ok(path) = which(candidate) {
            return Ok(path);
        }
    }

    Err(SandboxError::BackendUnavailable(
        "python is required to run E2B benchmarks".to_string(),
    ))
}

fn which(executable: &str) -> Result<PathBuf, SandboxError> {
    let output = Command::new(if cfg!(windows) { "where" } else { "which" })
        .arg(executable)
        .output()
        .map_err(|error| {
            SandboxError::LaunchFailed(format!("failed to locate {executable}: {error}"))
        })?;
    if !output.status.success() {
        return Err(SandboxError::BackendUnavailable(format!(
            "could not locate {executable}"
        )));
    }

    let resolved = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if resolved.is_empty() {
        return Err(SandboxError::BackendUnavailable(format!(
            "could not locate {executable}"
        )));
    }
    Ok(PathBuf::from(resolved))
}

fn venv_python_path(venv_path: &Path) -> PathBuf {
    if cfg!(windows) {
        venv_path.join("Scripts").join("python.exe")
    } else {
        venv_path.join("bin").join("python")
    }
}

fn startup_noop_command() -> CommandPlan {
    if cfg!(windows) {
        CommandPlan::Direct {
            argv: vec![
                "cmd.exe".to_string(),
                "/C".to_string(),
                "exit".to_string(),
                "0".to_string(),
            ],
        }
    } else {
        CommandPlan::Direct {
            argv: vec!["true".to_string()],
        }
    }
}

fn workspace_write_command() -> CommandPlan {
    if cfg!(windows) {
        CommandPlan::Shell {
            command: "echo microbox> .microbox-bench-write && del /F /Q .microbox-bench-write"
                .to_string(),
        }
    } else {
        CommandPlan::Shell {
            command: "printf microbox > .microbox-bench-write && rm -f .microbox-bench-write"
                .to_string(),
        }
    }
}

fn count_explicit_policy_flags(args: &crate::args::PolicyArgs) -> usize {
    args.config.is_some() as usize
        + (args.backend != microbox_backend::BackendPreference::Auto) as usize
        + args.preset.is_some() as usize
        + args.level.is_some() as usize
        + args
            .allow_net
            .as_ref()
            .is_some_and(|value| !value.is_empty()) as usize
        + args
            .allow_fs
            .as_ref()
            .is_some_and(|value| !value.is_empty()) as usize
        + args
            .allow_env
            .as_ref()
            .is_some_and(|value| !value.is_empty()) as usize
        + args.max_cpu.is_some() as usize
        + args.max_ram.is_some() as usize
        + args.max_disk.is_some() as usize
        + args.timeout.is_some() as usize
}

fn count_explicit_benchmark_flags(args: &BenchArgs) -> usize {
    (args.profile != BenchmarkProfile::Sequential) as usize
        + (args.stagger_delay_ms != 200) as usize
        + (args.format != OutputFormat::Text) as usize
        + (args.baseline_source != BaselineSource::Report) as usize
        + (args.baseline_label != "E2B-style") as usize
        + args.baseline_report.is_some() as usize
        + args.baseline_output.is_some() as usize
        + args.output.is_some() as usize
        + args
            .peer_targets
            .as_ref()
            .is_some_and(|value| !value.is_empty()) as usize
        + (args.peer_image != "alpine:3.20") as usize
        + (args.e2b_timeout_secs != 300) as usize
}

fn build_peer_reports(
    args: &BenchArgs,
    working_dir: &Path,
    policy: &microbox_policy::ResolvedPolicy,
    portable_scenarios: &[PortableScenario],
    scenario_specs: &[RemoteScenarioSpec],
) -> Vec<PeerBenchmarkReport> {
    let mut reports = Vec::new();

    for adapter in fresh_sandbox_adapters(args) {
        let report = adapter.probe(
            args,
            working_dir,
            policy,
            portable_scenarios,
            scenario_specs,
        );
        reports.push(report);
    }

    reports
}

trait FreshSandboxAdapter {
    fn probe(
        &self,
        args: &BenchArgs,
        working_dir: &Path,
        policy: &microbox_policy::ResolvedPolicy,
        portable_scenarios: &[PortableScenario],
        scenario_specs: &[RemoteScenarioSpec],
    ) -> PeerBenchmarkReport;
}

struct E2bFreshSandboxAdapter;

struct DockerFreshSandboxAdapter;

struct PodmanFreshSandboxAdapter;

struct BubblewrapFreshSandboxAdapter;

struct FirejailFreshSandboxAdapter;

impl FreshSandboxAdapter for E2bFreshSandboxAdapter {
    fn probe(
        &self,
        args: &BenchArgs,
        _working_dir: &Path,
        _policy: &microbox_policy::ResolvedPolicy,
        _portable_scenarios: &[PortableScenario],
        scenario_specs: &[RemoteScenarioSpec],
    ) -> PeerBenchmarkReport {
        build_e2b_peer_report(args, scenario_specs)
    }
}

impl FreshSandboxAdapter for DockerFreshSandboxAdapter {
    fn probe(
        &self,
        args: &BenchArgs,
        working_dir: &Path,
        policy: &microbox_policy::ResolvedPolicy,
        portable_scenarios: &[PortableScenario],
        _scenario_specs: &[RemoteScenarioSpec],
    ) -> PeerBenchmarkReport {
        build_container_peer_report(
            "docker",
            &args.peer_image,
            args,
            working_dir,
            policy,
            portable_scenarios,
        )
    }
}

impl FreshSandboxAdapter for PodmanFreshSandboxAdapter {
    fn probe(
        &self,
        args: &BenchArgs,
        working_dir: &Path,
        policy: &microbox_policy::ResolvedPolicy,
        portable_scenarios: &[PortableScenario],
        _scenario_specs: &[RemoteScenarioSpec],
    ) -> PeerBenchmarkReport {
        build_container_peer_report(
            "podman",
            &args.peer_image,
            args,
            working_dir,
            policy,
            portable_scenarios,
        )
    }
}

impl FreshSandboxAdapter for BubblewrapFreshSandboxAdapter {
    fn probe(
        &self,
        args: &BenchArgs,
        working_dir: &Path,
        policy: &microbox_policy::ResolvedPolicy,
        portable_scenarios: &[PortableScenario],
        _scenario_specs: &[RemoteScenarioSpec],
    ) -> PeerBenchmarkReport {
        build_bwrap_peer_report(args, working_dir, policy, portable_scenarios)
    }
}

impl FreshSandboxAdapter for FirejailFreshSandboxAdapter {
    fn probe(
        &self,
        args: &BenchArgs,
        working_dir: &Path,
        policy: &microbox_policy::ResolvedPolicy,
        portable_scenarios: &[PortableScenario],
        _scenario_specs: &[RemoteScenarioSpec],
    ) -> PeerBenchmarkReport {
        build_firejail_peer_report(args, working_dir, policy, portable_scenarios)
    }
}

fn fresh_sandbox_adapters(args: &BenchArgs) -> Vec<Box<dyn FreshSandboxAdapter>> {
    let mut adapters: Vec<Box<dyn FreshSandboxAdapter>> = Vec::new();

    for target in resolve_peer_targets(args.peer_targets.as_deref()) {
        match target {
            PeerTarget::Auto => unreachable!("auto is expanded before execution"),
            PeerTarget::E2b => adapters.push(Box::new(E2bFreshSandboxAdapter)),
            PeerTarget::Docker => adapters.push(Box::new(DockerFreshSandboxAdapter)),
            PeerTarget::Podman => adapters.push(Box::new(PodmanFreshSandboxAdapter)),
            PeerTarget::Bubblewrap => adapters.push(Box::new(BubblewrapFreshSandboxAdapter)),
            PeerTarget::Firejail => adapters.push(Box::new(FirejailFreshSandboxAdapter)),
        }
    }

    adapters
}

fn resolve_peer_targets(raw: Option<&[PeerTarget]>) -> Vec<PeerTarget> {
    let Some(raw) = raw else {
        return Vec::new();
    };

    let mut resolved = Vec::new();
    let mut seen = HashSet::new();

    for target in raw {
        let expanded: Vec<PeerTarget> = match target {
            PeerTarget::Auto => {
                let mut available = Vec::new();
                if e2b_available() {
                    available.push(PeerTarget::E2b);
                }
                if container_runtime_ready("docker") {
                    available.push(PeerTarget::Docker);
                }
                if container_runtime_ready("podman") {
                    available.push(PeerTarget::Podman);
                }
                if cfg!(target_os = "linux") && binary_available("bwrap") {
                    available.push(PeerTarget::Bubblewrap);
                }
                if cfg!(target_os = "linux") && binary_available("firejail") {
                    available.push(PeerTarget::Firejail);
                }
                available
            }
            other => vec![*other],
        };

        for item in expanded {
            if seen.insert(item) {
                resolved.push(item);
            }
        }
    }

    resolved
}

fn e2b_available() -> bool {
    matches!(std::env::var("E2B_API_KEY"), Ok(value) if !value.trim().is_empty())
        && find_python_executable().is_ok()
}

fn binary_available(binary: &str) -> bool {
    which(binary).is_ok()
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

fn build_e2b_peer_report(
    args: &BenchArgs,
    scenario_specs: &[RemoteScenarioSpec],
) -> PeerBenchmarkReport {
    match load_e2b_report(args, scenario_specs) {
        Ok(report) => PeerBenchmarkReport {
            target: "e2b".to_string(),
            available: true,
            reason: None,
            report: Some(Box::new(report)),
        },
        Err(error) => PeerBenchmarkReport {
            target: "e2b".to_string(),
            available: false,
            reason: Some(error.to_string()),
            report: None,
        },
    }
}

fn build_container_peer_report(
    runtime: &'static str,
    image: &str,
    args: &BenchArgs,
    working_dir: &Path,
    policy: &microbox_policy::ResolvedPolicy,
    portable_scenarios: &[PortableScenario],
) -> PeerBenchmarkReport {
    if !container_runtime_ready(runtime) {
        let reason = Command::new(runtime)
            .arg("info")
            .output()
            .ok()
            .map(|output| {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if stderr.is_empty() {
                    format!("{runtime} daemon is not reachable")
                } else {
                    stderr
                }
            })
            .unwrap_or_else(|| format!("{runtime} daemon is not reachable"));

        return PeerBenchmarkReport {
            target: runtime.to_string(),
            available: false,
            reason: Some(reason),
            report: None,
        };
    }

    if !policy.allow_net.is_empty() {
        return PeerBenchmarkReport {
            target: runtime.to_string(),
            available: false,
            reason: Some(
                "peer sandbox comparison currently supports the built-in no-network suite only"
                    .to_string(),
            ),
            report: None,
        };
    }

    let Some(report) = run_container_peer_report(
        runtime,
        image,
        working_dir,
        policy,
        portable_scenarios,
        args.iterations.max(1),
        args.warmups,
    ) else {
        return PeerBenchmarkReport {
            target: runtime.to_string(),
            available: false,
            reason: Some(format!("{runtime} is not available")),
            report: None,
        };
    };

    PeerBenchmarkReport {
        target: runtime.to_string(),
        available: true,
        reason: None,
        report: Some(Box::new(report)),
    }
}

fn build_bwrap_peer_report(
    args: &BenchArgs,
    working_dir: &Path,
    policy: &microbox_policy::ResolvedPolicy,
    portable_scenarios: &[PortableScenario],
) -> PeerBenchmarkReport {
    if !cfg!(target_os = "linux") {
        return PeerBenchmarkReport {
            target: "bwrap".to_string(),
            available: false,
            reason: Some("bubblewrap peer target is only available on Linux".to_string()),
            report: None,
        };
    }

    if !policy.allow_net.is_empty() {
        return PeerBenchmarkReport {
            target: "bwrap".to_string(),
            available: false,
            reason: Some(
                "peer sandbox comparison currently supports the built-in no-network suite only"
                    .to_string(),
            ),
            report: None,
        };
    }

    let Some(report) = run_bwrap_peer_report(
        working_dir,
        policy,
        portable_scenarios,
        args.iterations.max(1),
        args.warmups,
    ) else {
        return PeerBenchmarkReport {
            target: "bwrap".to_string(),
            available: false,
            reason: Some("bubblewrap is not available".to_string()),
            report: None,
        };
    };

    PeerBenchmarkReport {
        target: "bwrap".to_string(),
        available: true,
        reason: None,
        report: Some(Box::new(report)),
    }
}

fn build_firejail_peer_report(
    args: &BenchArgs,
    working_dir: &Path,
    policy: &microbox_policy::ResolvedPolicy,
    portable_scenarios: &[PortableScenario],
) -> PeerBenchmarkReport {
    if !cfg!(target_os = "linux") {
        return PeerBenchmarkReport {
            target: "firejail".to_string(),
            available: false,
            reason: Some("firejail peer target is only available on Linux".to_string()),
            report: None,
        };
    }

    if !binary_available("firejail") {
        return PeerBenchmarkReport {
            target: "firejail".to_string(),
            available: false,
            reason: Some("firejail is not installed".to_string()),
            report: None,
        };
    }

    if !policy.allow_net.is_empty() {
        return PeerBenchmarkReport {
            target: "firejail".to_string(),
            available: false,
            reason: Some(
                "peer sandbox comparison currently supports the built-in no-network suite only"
                    .to_string(),
            ),
            report: None,
        };
    }

    match run_firejail_peer_report(
        working_dir,
        policy,
        portable_scenarios,
        args.iterations.max(1),
        args.warmups,
    ) {
        Some(report) => PeerBenchmarkReport {
            target: "firejail".to_string(),
            available: true,
            reason: None,
            report: Some(Box::new(report)),
        },
        None => PeerBenchmarkReport {
            target: "firejail".to_string(),
            available: false,
            reason: Some("firejail could not launch the peer scenario".to_string()),
            report: None,
        },
    }
}

fn run_container_peer_report(
    runtime: &'static str,
    image: &str,
    working_dir: &Path,
    policy: &microbox_policy::ResolvedPolicy,
    portable_scenarios: &[PortableScenario],
    iterations: u32,
    warmups: u32,
) -> Option<BenchmarkReport> {
    let runtime_bin = if binary_available(runtime) {
        runtime
    } else {
        return None;
    };

    let prep_started = Instant::now();
    let policy_resolution_us = micros_u64(prep_started.elapsed());
    let mut scenario_reports = Vec::new();

    for scenario in portable_scenarios {
        let request = RunRequest::new(
            CommandPlan::Shell {
                command: scenario.command.clone(),
            },
            working_dir.to_path_buf(),
            policy.clone(),
        );

        let report = run_peer_scenario(runtime_bin, image, &request, scenario, iterations, warmups);
        scenario_reports.push(report);
    }

    let summary = summarize(&scenario_reports, None);

    Some(BenchmarkReport {
        tool: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at_unix: system_time_unix_secs(),
        platform: format!(
            "{}-{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::env::consts::FAMILY
        ),
        backend_requested: runtime.to_string(),
        backend_selected: runtime.to_string(),
        backend_secure_enforcement: false,
        backend_notes: vec![
            format!("{runtime} peer target benchmark"),
            format!("container image: {image}"),
        ],
        comparison_baseline: "microbox-peer".to_string(),
        policy_resolution_us,
        iterations,
        warmups,
        mode: "suite".to_string(),
        profile: "peer".to_string(),
        adoption: AdoptionMetrics {
            command_surface: format!("{runtime} peer target"),
            explicit_policy_flags: count_explicit_policy_flags(&args_for_peer(policy)),
            explicit_benchmark_flags: 0,
            setup_steps: 1,
            friction_score: 1,
            first_successful_run_us: None,
            first_successful_scenario: None,
        },
        summary,
        scenarios: scenario_reports,
        peer_reports: Vec::new(),
        profile_reports: Vec::new(),
        baseline_report_path: None,
    })
}

fn run_bwrap_peer_report(
    working_dir: &Path,
    policy: &microbox_policy::ResolvedPolicy,
    portable_scenarios: &[PortableScenario],
    iterations: u32,
    warmups: u32,
) -> Option<BenchmarkReport> {
    let _ = policy;
    if which("bwrap").is_err() {
        return None;
    }

    let prep_started = Instant::now();
    let policy_resolution_us = micros_u64(prep_started.elapsed());
    let mut scenario_reports = Vec::new();

    for scenario in portable_scenarios {
        let request = RunRequest::new(
            CommandPlan::Shell {
                command: scenario.command.clone(),
            },
            working_dir.to_path_buf(),
            policy.clone(),
        );

        let report = run_peer_scenario("bwrap", "", &request, scenario, iterations, warmups);
        scenario_reports.push(report);
    }

    let summary = summarize(&scenario_reports, None);

    Some(BenchmarkReport {
        tool: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at_unix: system_time_unix_secs(),
        platform: format!(
            "{}-{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::env::consts::FAMILY
        ),
        backend_requested: "bwrap".to_string(),
        backend_selected: "bwrap".to_string(),
        backend_secure_enforcement: true,
        backend_notes: vec!["bubblewrap peer target benchmark".to_string()],
        comparison_baseline: "microbox-peer".to_string(),
        policy_resolution_us,
        iterations,
        warmups,
        mode: "suite".to_string(),
        profile: "peer".to_string(),
        adoption: AdoptionMetrics {
            command_surface: "bwrap peer target".to_string(),
            explicit_policy_flags: count_explicit_policy_flags(&args_for_peer(policy)),
            explicit_benchmark_flags: 0,
            setup_steps: 1,
            friction_score: 1,
            first_successful_run_us: None,
            first_successful_scenario: None,
        },
        summary,
        scenarios: scenario_reports,
        peer_reports: Vec::new(),
        profile_reports: Vec::new(),
        baseline_report_path: None,
    })
}

fn run_firejail_peer_report(
    working_dir: &Path,
    policy: &microbox_policy::ResolvedPolicy,
    portable_scenarios: &[PortableScenario],
    iterations: u32,
    warmups: u32,
) -> Option<BenchmarkReport> {
    let prep_started = Instant::now();
    let policy_resolution_us = micros_u64(prep_started.elapsed());
    let mut scenario_reports = Vec::new();

    for scenario in portable_scenarios {
        let request = RunRequest::new(
            CommandPlan::Shell {
                command: scenario.command.clone(),
            },
            working_dir.to_path_buf(),
            policy.clone(),
        );

        let report = run_firejail_scenario(&request, scenario, iterations, warmups);
        scenario_reports.push(report);
    }

    let summary = summarize(&scenario_reports, None);

    Some(BenchmarkReport {
        tool: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at_unix: system_time_unix_secs(),
        platform: format!(
            "{}-{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::env::consts::FAMILY
        ),
        backend_requested: "firejail".to_string(),
        backend_selected: "firejail".to_string(),
        backend_secure_enforcement: true,
        backend_notes: vec!["firejail peer target benchmark".to_string()],
        comparison_baseline: "microbox-peer".to_string(),
        policy_resolution_us,
        iterations,
        warmups,
        mode: "suite".to_string(),
        profile: "peer".to_string(),
        adoption: AdoptionMetrics {
            command_surface: "firejail peer target".to_string(),
            explicit_policy_flags: count_explicit_policy_flags(&args_for_peer(policy)),
            explicit_benchmark_flags: 0,
            setup_steps: 1,
            friction_score: 1,
            first_successful_run_us: None,
            first_successful_scenario: None,
        },
        summary,
        scenarios: scenario_reports,
        peer_reports: Vec::new(),
        profile_reports: Vec::new(),
        baseline_report_path: None,
    })
}

fn run_firejail_scenario(
    request: &RunRequest,
    scenario: &PortableScenario,
    iterations: u32,
    warmups: u32,
) -> ScenarioReport {
    let notes = scenario
        .notes
        .iter()
        .map(|note| (*note).to_string())
        .collect::<Vec<_>>();

    for warmup_index in 0..warmups {
        let result = match execute_firejail_command(request) {
            Ok(result) => result,
            Err(error) => {
                return ScenarioReport {
                    name: scenario.name.to_string(),
                    description: scenario.description.to_string(),
                    command: scenario.command.clone(),
                    samples_us: Vec::new(),
                    average_us: None,
                    best_us: None,
                    worst_us: None,
                    success: false,
                    timed_out: false,
                    exit_code: None,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    error: Some(format!("warmup {warmup_index} failed: {error}")),
                    comparison: None,
                    notes,
                };
            }
        };
        if result.timed_out {
            return ScenarioReport {
                name: scenario.name.to_string(),
                description: scenario.description.to_string(),
                command: scenario.command.clone(),
                samples_us: Vec::new(),
                average_us: None,
                best_us: None,
                worst_us: None,
                success: false,
                timed_out: true,
                exit_code: Some(result.exit_code()),
                stdout_bytes: result.stdout.len(),
                stderr_bytes: result.stderr.len(),
                error: Some(format!("warmup {warmup_index} timed out")),
                comparison: None,
                notes,
            };
        }
    }

    let mut samples = Vec::with_capacity(iterations as usize);
    let mut best: Option<u64> = None;
    let mut worst: Option<u64> = None;
    let mut exit_code = None;
    let mut timed_out = false;
    let mut stdout_bytes = 0usize;
    let mut stderr_bytes = 0usize;
    let mut error = None;

    for _ in 0..iterations {
        let result = match execute_firejail_command(request) {
            Ok(result) => result,
            Err(run_error) => {
                error = Some(run_error.to_string());
                break;
            }
        };
        let sample_us = micros_u64(result.duration);
        stdout_bytes += result.stdout.len();
        stderr_bytes += result.stderr.len();
        timed_out |= result.timed_out;
        exit_code = Some(result.exit_code());
        samples.push(sample_us);
        best = Some(best.map_or(sample_us, |current: u64| current.min(sample_us)));
        worst = Some(worst.map_or(sample_us, |current: u64| current.max(sample_us)));

        if result.exit_code() != 0 {
            error = Some(format!("command exited with {}", result.exit_code()));
            break;
        }
    }

    let average_us = if samples.is_empty() {
        None
    } else {
        Some((samples.iter().copied().sum::<u64>() / samples.len() as u64).max(1))
    };

    let success = error.is_none() && !samples.is_empty() && !timed_out;

    ScenarioReport {
        name: scenario.name.to_string(),
        description: scenario.description.to_string(),
        command: scenario.command.clone(),
        samples_us: samples,
        average_us,
        best_us: best,
        worst_us: worst,
        success,
        timed_out,
        exit_code,
        stdout_bytes,
        stderr_bytes,
        error,
        comparison: None,
        notes,
    }
}

fn execute_firejail_command(request: &RunRequest) -> Result<ExecutionResult, SandboxError> {
    let mut command = build_firejail_command(request)?;
    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| SandboxError::LaunchFailed(format!("firejail: {error}")))?;
    let collected = collect_output(&mut child, request.policy.timeout)?;
    let duration = start.elapsed();

    Ok(ExecutionResult::from_status(
        collected.status,
        collected.stdout,
        collected.stderr,
        duration,
        collected.timed_out,
    ))
}

fn build_firejail_command(request: &RunRequest) -> Result<Command, SandboxError> {
    let mut command = Command::new("firejail");
    command.arg("--quiet");
    command.arg("--noprofile");
    command.arg("--private");
    command.arg("--net=none");
    command.arg("--nosound");
    command.arg("--caps.drop=all");
    command.arg("--chdir").arg(&request.working_dir);
    command.arg("--");
    command.arg("/bin/sh");
    command.arg("-lc");
    command.arg(match &request.command {
        CommandPlan::Direct { argv } => argv
            .iter()
            .map(|arg| shell_escape(arg))
            .collect::<Vec<_>>()
            .join(" "),
        CommandPlan::Shell { command } => command.clone(),
    });

    apply_peer_command_defaults(&mut command, request);
    Ok(command)
}

fn args_for_peer(policy: &microbox_policy::ResolvedPolicy) -> crate::args::PolicyArgs {
    let _ = policy;
    crate::args::PolicyArgs::default()
}

fn run_peer_scenario(
    runtime: &'static str,
    image: &str,
    request: &RunRequest,
    scenario: &PortableScenario,
    iterations: u32,
    warmups: u32,
) -> ScenarioReport {
    let notes = scenario
        .notes
        .iter()
        .map(|note| (*note).to_string())
        .collect::<Vec<_>>();

    for warmup_index in 0..warmups {
        let result = match execute_peer_command(runtime, image, request) {
            Ok(result) => result,
            Err(error) => {
                return ScenarioReport {
                    name: scenario.name.to_string(),
                    description: scenario.description.to_string(),
                    command: scenario.command.clone(),
                    samples_us: Vec::new(),
                    average_us: None,
                    best_us: None,
                    worst_us: None,
                    success: false,
                    timed_out: false,
                    exit_code: None,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    error: Some(format!("warmup {warmup_index} failed: {error}")),
                    comparison: None,
                    notes,
                };
            }
        };
        if result.timed_out {
            return ScenarioReport {
                name: scenario.name.to_string(),
                description: scenario.description.to_string(),
                command: scenario.command.clone(),
                samples_us: Vec::new(),
                average_us: None,
                best_us: None,
                worst_us: None,
                success: false,
                timed_out: true,
                exit_code: Some(result.exit_code()),
                stdout_bytes: result.stdout.len(),
                stderr_bytes: result.stderr.len(),
                error: Some(format!("warmup {warmup_index} timed out")),
                comparison: None,
                notes,
            };
        }
    }

    let mut samples = Vec::with_capacity(iterations as usize);
    let mut best: Option<u64> = None;
    let mut worst: Option<u64> = None;
    let mut exit_code = None;
    let mut timed_out = false;
    let mut stdout_bytes = 0usize;
    let mut stderr_bytes = 0usize;
    let mut error = None;

    for _ in 0..iterations {
        let result = match execute_peer_command(runtime, image, request) {
            Ok(result) => result,
            Err(run_error) => {
                error = Some(run_error.to_string());
                break;
            }
        };
        let sample_us = micros_u64(result.duration);
        stdout_bytes += result.stdout.len();
        stderr_bytes += result.stderr.len();
        timed_out |= result.timed_out;
        exit_code = Some(result.exit_code());
        samples.push(sample_us);
        best = Some(best.map_or(sample_us, |current: u64| current.min(sample_us)));
        worst = Some(worst.map_or(sample_us, |current: u64| current.max(sample_us)));

        if result.exit_code() != 0 {
            error = Some(format!("command exited with {}", result.exit_code()));
            break;
        }
    }

    let average_us = if samples.is_empty() {
        None
    } else {
        Some((samples.iter().copied().sum::<u64>() / samples.len() as u64).max(1))
    };

    let success = error.is_none() && !samples.is_empty() && !timed_out;

    ScenarioReport {
        name: scenario.name.to_string(),
        description: scenario.description.to_string(),
        command: scenario.command.clone(),
        samples_us: samples,
        average_us,
        best_us: best,
        worst_us: worst,
        success,
        timed_out,
        exit_code,
        stdout_bytes,
        stderr_bytes,
        error,
        comparison: None,
        notes,
    }
}

fn execute_peer_command(
    runtime: &'static str,
    image: &str,
    request: &RunRequest,
) -> Result<ExecutionResult, SandboxError> {
    let mut command = match runtime {
        "docker" | "podman" => build_container_command(runtime, image, request)?,
        "bwrap" => build_bwrap_command(request)?,
        other => {
            return Err(SandboxError::BackendUnavailable(format!(
                "unsupported peer runtime: {other}"
            )))
        }
    };

    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| SandboxError::LaunchFailed(format!("{runtime}: {error}")))?;
    let collected = collect_output(&mut child, request.policy.timeout)?;
    let duration = start.elapsed();

    Ok(ExecutionResult::from_status(
        collected.status,
        collected.stdout,
        collected.stderr,
        duration,
        collected.timed_out,
    ))
}

fn build_container_command(
    runtime: &str,
    image: &str,
    request: &RunRequest,
) -> Result<Command, SandboxError> {
    let mut command = Command::new(runtime);
    command.arg("run");
    command.arg("--rm");
    command.arg("--network");
    command.arg("none");
    command.arg("-v");
    command.arg(format!("{}:/work", request.working_dir.display()));
    command.arg("-w");
    command.arg("/work");
    for (key, value) in bootstrap_env_pairs() {
        command.arg("-e");
        command.arg(format!("{key}={value}"));
    }
    for (key, value) in request.policy.filtered_env_pairs() {
        command.arg("-e");
        command.arg(format!("{key}={value}"));
    }
    command.arg(image);
    command.arg("sh");
    command.arg("-lc");
    command.arg(match &request.command {
        CommandPlan::Direct { argv } => argv
            .iter()
            .map(|arg| shell_escape(arg))
            .collect::<Vec<_>>()
            .join(" "),
        CommandPlan::Shell { command } => command.clone(),
    });

    apply_peer_command_defaults(&mut command, request);
    Ok(command)
}

fn build_bwrap_command(request: &RunRequest) -> Result<Command, SandboxError> {
    if !cfg!(target_os = "linux") {
        return Err(SandboxError::BackendUnavailable(
            "bubblewrap peer target is only available on Linux".to_string(),
        ));
    }

    let mut command = Command::new("bwrap");
    command.arg("--die-with-parent");
    command.arg("--new-session");
    command.arg("--unshare-user");
    command.arg("--unshare-pid");
    command.arg("--unshare-ipc");
    command.arg("--unshare-uts");
    command.arg("--unshare-cgroup");
    command.arg("--unshare-net");
    command.arg("--clearenv");
    command.arg("--ro-bind").arg("/").arg("/");
    command.arg("--dev").arg("/dev");
    command.arg("--proc").arg("/proc");
    command.arg("--tmpfs").arg("/tmp");
    command.arg("--dir").arg("/var/tmp");
    command.arg("--chdir").arg(&request.working_dir);
    command
        .arg("--bind")
        .arg(&request.working_dir)
        .arg(&request.working_dir);
    for (key, value) in bootstrap_env_pairs() {
        command.arg("--setenv").arg(key).arg(value);
    }
    for (key, value) in request.policy.filtered_env_pairs() {
        command.arg("--setenv").arg(key).arg(value);
    }
    command.arg("--");
    command.arg("/bin/sh");
    command.arg("-lc");
    command.arg(match &request.command {
        CommandPlan::Direct { argv } => argv
            .iter()
            .map(|arg| shell_escape(arg))
            .collect::<Vec<_>>()
            .join(" "),
        CommandPlan::Shell { command } => command.clone(),
    });

    apply_peer_command_defaults(&mut command, request);
    Ok(command)
}

fn apply_peer_command_defaults(command: &mut Command, request: &RunRequest) {
    command.current_dir(&request.working_dir);
    command.env_clear();
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    for (key, value) in bootstrap_env_pairs() {
        command.env(key, value);
    }
    for (key, value) in request.policy.filtered_env_pairs() {
        command.env(key, value);
    }
}

fn bootstrap_env_pairs() -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for key in [
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SystemRoot",
        "ComSpec",
        "SHELL",
        "TERM",
    ] {
        if let Ok(value) = std::env::var(key) {
            pairs.push((key.to_string(), value));
        }
    }
    pairs
}

fn collect_output(child: &mut Child, timeout: Duration) -> Result<CollectedOutput, SandboxError> {
    let stdout = child.stdout.take().map(read_pipe);
    let stderr = child.stderr.take().map(read_pipe);
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| SandboxError::LaunchFailed(error.to_string()))?
        {
            let stdout = join_pipe(stdout)?;
            let stderr = join_pipe(stderr)?;
            return Ok(CollectedOutput {
                status,
                stdout,
                stderr,
                timed_out,
            });
        }

        if Instant::now() >= deadline {
            timed_out = true;
            terminate_child(child);
            let status = child
                .wait()
                .map_err(|error| SandboxError::LaunchFailed(error.to_string()))?;
            let stdout = join_pipe(stdout)?;
            let stderr = join_pipe(stderr)?;
            return Ok(CollectedOutput {
                status,
                stdout,
                stderr,
                timed_out,
            });
        }

        thread::sleep(Duration::from_millis(10));
    }
}

struct CollectedOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
}

fn read_pipe<T>(mut pipe: T) -> thread::JoinHandle<io::Result<Vec<u8>>>
where
    T: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = Vec::new();
        pipe.read_to_end(&mut buffer)?;
        Ok(buffer)
    })
}

fn join_pipe(
    handle: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
) -> Result<Vec<u8>, SandboxError> {
    match handle {
        Some(handle) => handle
            .join()
            .map_err(|_| SandboxError::LaunchFailed("output reader thread panicked".to_string()))?
            .map_err(|error| SandboxError::LaunchFailed(error.to_string())),
        None => Ok(Vec::new()),
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
}

fn micros_u64(duration: std::time::Duration) -> u64 {
    let micros = duration.as_micros();
    if micros > u64::MAX as u128 {
        u64::MAX
    } else {
        micros as u64
    }
}

fn system_time_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn format_opt_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn escape_md(input: &str) -> String {
    input.replace('|', "\\|").replace('\n', " ")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemoteBenchmarkRequest {
    iterations: u32,
    warmups: u32,
    timeout_secs: u64,
    e2b_domain: Option<String>,
    scenarios: Vec<RemoteScenarioSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemoteScenarioSpec {
    name: String,
    description: String,
    command: String,
    notes: Vec<String>,
}

const E2B_BENCHMARK_SCRIPT: &str = r#"
import json
import os
import sys
import time

from e2b import Sandbox


def run_scenario(sandbox, scenario, iterations, warmups, timeout_secs):
    samples_us = []
    stdout_bytes = 0
    stderr_bytes = 0
    timed_out = False
    exit_code = None
    error = None

    for _ in range(warmups):
        try:
            sandbox.commands.run(scenario["command"], request_timeout=timeout_secs)
        except Exception as exc:
            return {
                "name": scenario["name"],
                "description": scenario["description"],
                "command": scenario["command"],
                "samples_us": [],
                "average_us": None,
                "best_us": None,
                "worst_us": None,
                "success": False,
                "timed_out": False,
                "exit_code": None,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "error": f"warmup failed: {exc}",
                "comparison": None,
                "notes": scenario["notes"],
            }

    for _ in range(iterations):
        started = time.perf_counter_ns()
        try:
            result = sandbox.commands.run(scenario["command"], request_timeout=timeout_secs)
            exit_code = getattr(result, "exit_code", 0)
            stdout = getattr(result, "stdout", "") or ""
            stderr = getattr(result, "stderr", "") or ""
            duration_us = max(1, (time.perf_counter_ns() - started) // 1000)
            stdout_bytes += len(stdout.encode("utf-8", "ignore"))
            stderr_bytes += len(stderr.encode("utf-8", "ignore"))
            samples_us.append(int(duration_us))
            if exit_code not in (0, None):
                error = f"command exited with {exit_code}"
                break
        except Exception as exc:
            error = str(exc)
            break

    average_us = None
    best_us = None
    worst_us = None
    if samples_us:
        average_us = max(1, sum(samples_us) // len(samples_us))
        best_us = min(samples_us)
        worst_us = max(samples_us)

    success = error is None and not timed_out and bool(samples_us)
    return {
        "name": scenario["name"],
        "description": scenario["description"],
        "command": scenario["command"],
        "samples_us": samples_us,
        "average_us": average_us,
        "best_us": best_us,
        "worst_us": worst_us,
        "success": success,
        "timed_out": timed_out,
        "exit_code": exit_code,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "error": error,
        "comparison": None,
        "notes": scenario["notes"],
    }


def summarize(reports):
    passed = sum(1 for report in reports if report["success"])
    failed = sum(1 for report in reports if not report["success"])
    averages = [report["average_us"] for report in reports if report["average_us"] is not None]
    best_overall = None
    worst_overall = None
    fastest = None
    slowest = None
    fastest_us = None
    slowest_us = None
    for report in reports:
        if report["best_us"] is not None:
            best_overall = report["best_us"] if best_overall is None else min(best_overall, report["best_us"])
        if report["worst_us"] is not None:
            worst_overall = report["worst_us"] if worst_overall is None else max(worst_overall, report["worst_us"])
        if report["average_us"] is not None:
            if fastest_us is None or report["average_us"] < fastest_us:
                fastest_us = report["average_us"]
                fastest = report["name"]
            if slowest_us is None or report["average_us"] > slowest_us:
                slowest_us = report["average_us"]
                slowest = report["name"]
    average_of_averages = None if not averages else sum(averages) // len(averages)
    return {
        "scenario_count": len(reports),
        "passed_scenarios": passed,
        "failed_scenarios": failed,
        "matched_baseline_scenarios": 0,
        "average_of_averages_us": average_of_averages,
        "fastest_scenario": fastest,
        "fastest_average_us": fastest_us,
        "slowest_scenario": slowest,
        "slowest_average_us": slowest_us,
        "best_overall_us": best_overall,
        "worst_overall_us": worst_overall,
        "first_successful_run_us": None,
    }


def main():
    request_path = sys.argv[1]
    report_path = sys.argv[2]
    with open(request_path, "r", encoding="utf-8") as handle:
        request = json.load(handle)

    sandbox_kwargs = {
        "secure": True,
        "allow_internet_access": False,
        "timeout": request["timeout_secs"],
    }
    domain = request.get("e2b_domain") or os.environ.get("E2B_DOMAIN", "").strip()
    if domain:
        sandbox_kwargs["domain"] = domain

    sandbox = Sandbox.create(**sandbox_kwargs)
    try:
        reports = []
        for scenario in request["scenarios"]:
            reports.append(
                run_scenario(
                    sandbox,
                    scenario,
                    request["iterations"],
                    request["warmups"],
                    request["timeout_secs"],
                )
            )

        final = {
            "tool": "e2b-sdk",
            "version": getattr(__import__("e2b"), "__version__", "unknown"),
            "generated_at_unix": int(time.time()),
            "platform": "e2b-self-hosted" if domain else "e2b-cloud",
            "backend_requested": "secure",
            "backend_selected": "e2b-self-hosted-sandbox" if domain else "e2b-cloud-sandbox",
            "backend_secure_enforcement": True,
            "backend_notes": [
                "self-hosted E2B benchmark" if domain else "cloud sandbox baseline using the official E2B SDK",
                "internet access disabled for a fair zero-change benchmark",
                f"domain={domain}" if domain else "hosted E2B control plane",
            ],
            "comparison_baseline": "E2B-style",
            "policy_resolution_us": 0,
            "iterations": request["iterations"],
            "warmups": request["warmups"],
            "mode": "suite" if len(request["scenarios"]) > 1 else "custom-command",
            "adoption": {
                "command_surface": "e2b sandbox.commands.run",
                "explicit_policy_flags": 0,
                "explicit_benchmark_flags": 0,
                "setup_steps": 3,
                "friction_score": 3,
                "first_successful_run_us": None,
                "first_successful_scenario": None,
            },
            "summary": summarize(reports),
            "scenarios": reports,
            "baseline_report_path": None,
        }
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(final, handle, indent=2)
    finally:
        try:
            sandbox.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_scenarios_use_linux_shell_commands() {
        let args = BenchArgs {
            policy: crate::args::PolicyArgs::default(),
            profile: BenchmarkProfile::Sequential,
            iterations: 1,
            warmups: 0,
            format: OutputFormat::Text,
            baseline_source: BaselineSource::Report,
            baseline_label: "E2B-style".to_string(),
            baseline_report: None,
            baseline_output: None,
            peer_targets: None,
            peer_image: "alpine:3.20".to_string(),
            stagger_delay_ms: 200,
            output: None,
            e2b_timeout_secs: 300,
            command: Vec::new(),
        };

        let portable = build_portable_scenarios(&args).unwrap();
        assert!(portable
            .iter()
            .any(|scenario| scenario.command.contains("rm -f")));
    }

    #[test]
    fn peer_targets_deduplicate_explicit_values() {
        let targets = resolve_peer_targets(Some(&[PeerTarget::Docker, PeerTarget::Docker]));
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0], PeerTarget::Docker);
    }
}
