use clap::{Args, Parser, Subcommand, ValueEnum};
use microbox_backend::BackendPreference;
use microbox_policy::{IsolationLevel, PresetKind};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "microbox",
    about = "Policy-first sandbox runtime for AI coding workloads",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run a command inside MicroBox
    Run(RunArgs),
    /// Validate configuration and policy resolution without executing a command
    Validate(ValidateArgs),
    /// Benchmark the selected backend and policy resolution path
    Bench(BenchArgs),
    /// Inspect platform and runtime readiness
    Doctor,
}

#[derive(Debug, Args, Clone)]
pub struct PolicyArgs {
    /// Optional configuration file path
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Backend selection
    #[arg(long, value_enum, default_value_t = BackendPreference::Auto)]
    pub backend: BackendPreference,

    /// Built-in policy preset
    #[arg(long, value_enum)]
    pub preset: Option<PresetKind>,

    /// Isolation level
    #[arg(long, value_enum)]
    pub level: Option<IsolationLevel>,

    /// Allowed network endpoints, comma-separated or repeated
    #[arg(long = "allow-net", value_delimiter = ',', num_args = 1..)]
    pub allow_net: Option<Vec<String>>,

    /// Allowed filesystem paths, use path:rw or path:ro
    #[arg(long = "allow-fs", value_delimiter = ',', num_args = 1..)]
    pub allow_fs: Option<Vec<String>>,

    /// Allowed environment variable names, comma-separated or repeated
    #[arg(long = "allow-env", value_delimiter = ',', num_args = 1..)]
    pub allow_env: Option<Vec<String>>,

    /// Maximum CPU cores
    #[arg(long)]
    pub max_cpu: Option<u32>,

    /// Maximum RAM, for example 512m or 1g
    #[arg(long)]
    pub max_ram: Option<String>,

    /// Maximum disk, for example 1g
    #[arg(long)]
    pub max_disk: Option<String>,

    /// Timeout, for example 60s or 5m
    #[arg(long)]
    pub timeout: Option<String>,
}

impl Default for PolicyArgs {
    fn default() -> Self {
        Self {
            config: None,
            backend: BackendPreference::Auto,
            preset: None,
            level: None,
            allow_net: None,
            allow_fs: None,
            allow_env: None,
            max_cpu: None,
            max_ram: None,
            max_disk: None,
            timeout: None,
        }
    }
}

#[derive(Debug, Args, Clone)]
pub struct RunArgs {
    #[command(flatten)]
    pub policy: PolicyArgs,

    /// Command and arguments, or a single shell string
    #[arg(value_name = "COMMAND", num_args = 1.., trailing_var_arg = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Args, Clone)]
pub struct ValidateArgs {
    #[command(flatten)]
    pub policy: PolicyArgs,
}

#[derive(Debug, Args, Clone)]
pub struct BenchArgs {
    #[command(flatten)]
    pub policy: PolicyArgs,

    /// Benchmark scheduling profile
    #[arg(long, value_enum, default_value_t = BenchmarkProfile::Sequential)]
    pub profile: BenchmarkProfile,

    /// Number of benchmark iterations
    #[arg(long, default_value_t = 5)]
    pub iterations: u32,

    /// Number of warmup runs before collecting timings
    #[arg(long, default_value_t = 1)]
    pub warmups: u32,

    /// Output format for the benchmark report
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Where to source the comparison baseline from
    #[arg(long, value_enum, default_value_t = BaselineSource::Report)]
    pub baseline_source: BaselineSource,

    /// Human label for the comparison baseline
    #[arg(long, default_value = "E2B-style")]
    pub baseline_label: String,

    /// Optional JSON benchmark report to compare against
    #[arg(long)]
    pub baseline_report: Option<PathBuf>,

    /// Optional path to write a generated baseline report
    #[arg(long)]
    pub baseline_output: Option<PathBuf>,

    /// Timeout in seconds for each E2B benchmark scenario and sandbox lifetime
    #[arg(long, default_value_t = 300)]
    pub e2b_timeout_secs: u64,

    /// Optional output file for the rendered report
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Additional sandbox targets to benchmark alongside MicroBox
    #[arg(long = "peer-target", value_enum, num_args = 1..)]
    pub peer_targets: Option<Vec<PeerTarget>>,

    /// Container image used for docker/podman peer targets
    #[arg(long, default_value = "alpine:3.20")]
    pub peer_image: String,

    /// Delay in milliseconds between staggered iterations
    #[arg(long, default_value_t = 200)]
    pub stagger_delay_ms: u64,

    /// Command and arguments to benchmark, or omit for the built-in no-op command
    #[arg(value_name = "COMMAND", num_args = 0.., trailing_var_arg = true)]
    pub command: Vec<String>,
}

impl PolicyArgs {
    pub fn to_overrides(&self) -> Result<microbox_policy::PolicyOverrides, String> {
        let (filesystem_writable, filesystem_readonly) = self
            .allow_fs
            .as_ref()
            .map(|entries| {
                let mut writable = Vec::new();
                let mut readonly = Vec::new();
                for entry in entries {
                    let (w, r) = microbox_policy::parse_allow_fs_entry(entry)
                        .map_err(|error| error.to_string())?;
                    writable.extend(w);
                    readonly.extend(r);
                }
                Ok::<_, String>((Some(writable), Some(readonly)))
            })
            .unwrap_or_else(|| Ok((None, None)))?;

        Ok(microbox_policy::PolicyOverrides {
            level: self.level,
            allow_net: self.allow_net.clone(),
            network_deny_all_other: None,
            filesystem_writable,
            filesystem_readonly,
            filesystem_deny: None,
            env_passthrough: self.allow_env.clone(),
            env_deny: None,
            max_cpu: self.max_cpu,
            max_ram: self.max_ram.clone(),
            max_disk: self.max_disk.clone(),
            timeout: self.timeout.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Markdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BenchmarkProfile {
    Sequential,
    Staggered,
    Burst,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BaselineSource {
    Report,
    E2b,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
pub enum PeerTarget {
    Auto,
    E2b,
    Docker,
    Podman,
    Bubblewrap,
    Firejail,
}
