use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt, fs,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid isolation level: {0}")]
    InvalidIsolationLevel(String),
    #[error("invalid preset: {0}")]
    InvalidPreset(String),
    #[error("invalid human-readable size: {0}")]
    InvalidSize(String),
    #[error("invalid human-readable duration: {0}")]
    InvalidDuration(String),
    #[error("invalid filesystem allow spec: {0}")]
    InvalidFilesystemAllowSpec(String),
    #[error("invalid policy configuration: {0}")]
    InvalidPolicyConfiguration(String),
    #[error("failed to read config file {path}: {source}")]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file: {0}")]
    ConfigParse(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IsolationLevel {
    Fast,
    #[default]
    Safe,
    Paranoid,
}

impl fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IsolationLevel::Fast => "fast",
            IsolationLevel::Safe => "safe",
            IsolationLevel::Paranoid => "paranoid",
        })
    }
}

impl FromStr for IsolationLevel {
    type Err = PolicyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.trim().to_ascii_lowercase().as_str() {
            "fast" => Ok(IsolationLevel::Fast),
            "safe" => Ok(IsolationLevel::Safe),
            "paranoid" => Ok(IsolationLevel::Paranoid),
            other => Err(PolicyError::InvalidIsolationLevel(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PresetKind {
    AiAgent,
    WebServer,
    Hermetic,
}

impl fmt::Display for PresetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PresetKind::AiAgent => "ai-agent",
            PresetKind::WebServer => "web-server",
            PresetKind::Hermetic => "hermetic",
        })
    }
}

impl FromStr for PresetKind {
    type Err = PolicyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.trim().to_ascii_lowercase().as_str() {
            "ai-agent" | "aiagent" | "agent" => Ok(PresetKind::AiAgent),
            "web-server" | "webserver" | "web" => Ok(PresetKind::WebServer),
            "hermetic" => Ok(PresetKind::Hermetic),
            other => Err(PolicyError::InvalidPreset(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfigFile {
    pub version: Option<u32>,
    pub sandbox: Option<SandboxConfig>,
    pub network: Option<NetworkConfig>,
    pub filesystem: Option<FilesystemConfig>,
    pub environment: Option<EnvironmentConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SandboxConfig {
    pub level: Option<IsolationLevel>,
    pub timeout: Option<String>,
    pub max_cpu: Option<u32>,
    pub max_ram: Option<String>,
    pub max_disk: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetworkConfig {
    pub allow: Option<Vec<String>>,
    pub deny_all_other: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FilesystemConfig {
    pub writable: Option<Vec<PathBuf>>,
    pub readonly: Option<Vec<PathBuf>>,
    pub deny: Option<Vec<PathBuf>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EnvironmentConfig {
    pub passthrough: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct PolicySpec {
    pub level: Option<IsolationLevel>,
    pub allow_net: Option<Vec<String>>,
    pub network_deny_all_other: Option<bool>,
    pub filesystem_writable: Option<Vec<PathBuf>>,
    pub filesystem_readonly: Option<Vec<PathBuf>>,
    pub filesystem_deny: Option<Vec<PathBuf>>,
    pub env_passthrough: Option<Vec<String>>,
    pub env_deny: Option<Vec<String>>,
    pub max_cpu: Option<u32>,
    pub max_ram: Option<String>,
    pub max_disk: Option<String>,
    pub timeout: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    pub working_dir: PathBuf,
    pub level: IsolationLevel,
    pub allow_net: Vec<String>,
    pub network_deny_all_other: bool,
    pub filesystem_writable: Vec<PathBuf>,
    pub filesystem_readonly: Vec<PathBuf>,
    pub filesystem_deny: Vec<PathBuf>,
    pub env_passthrough: Vec<String>,
    pub env_deny: Vec<String>,
    pub max_cpu: u32,
    pub max_ram_bytes: u64,
    pub max_disk_bytes: u64,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyOverrides {
    pub level: Option<IsolationLevel>,
    pub allow_net: Option<Vec<String>>,
    pub network_deny_all_other: Option<bool>,
    pub filesystem_writable: Option<Vec<PathBuf>>,
    pub filesystem_readonly: Option<Vec<PathBuf>>,
    pub filesystem_deny: Option<Vec<PathBuf>>,
    pub env_passthrough: Option<Vec<String>>,
    pub env_deny: Option<Vec<String>>,
    pub max_cpu: Option<u32>,
    pub max_ram: Option<String>,
    pub max_disk: Option<String>,
    pub timeout: Option<String>,
}

impl PolicyOverrides {
    pub fn to_spec(self) -> PolicySpec {
        PolicySpec {
            level: self.level,
            allow_net: self.allow_net,
            network_deny_all_other: self.network_deny_all_other,
            filesystem_writable: self.filesystem_writable,
            filesystem_readonly: self.filesystem_readonly,
            filesystem_deny: self.filesystem_deny,
            env_passthrough: self.env_passthrough,
            env_deny: self.env_deny,
            max_cpu: self.max_cpu,
            max_ram: self.max_ram,
            max_disk: self.max_disk,
            timeout: self.timeout,
        }
    }
}

impl ConfigFile {
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let raw = fs::read_to_string(path).map_err(|source| PolicyError::ConfigRead {
            path: path.to_path_buf(),
            source,
        })?;

        let parsed: ConfigFile =
            toml::from_str(&raw).map_err(|source| PolicyError::ConfigParse(source.to_string()))?;

        if let Some(version) = parsed.version {
            if version != 1 {
                return Err(PolicyError::ConfigParse(format!(
                    "unsupported config version: {version}"
                )));
            }
        }

        Ok(parsed)
    }

    pub fn to_spec(&self) -> PolicySpec {
        let mut spec = PolicySpec::default();

        if let Some(sandbox) = &self.sandbox {
            spec.level = sandbox.level;
            spec.timeout = sandbox.timeout.clone();
            spec.max_cpu = sandbox.max_cpu;
            spec.max_ram = sandbox.max_ram.clone();
            spec.max_disk = sandbox.max_disk.clone();
        }

        if let Some(network) = &self.network {
            spec.allow_net = network.allow.clone();
            spec.network_deny_all_other = network.deny_all_other;
        }

        if let Some(filesystem) = &self.filesystem {
            spec.filesystem_writable = filesystem.writable.clone();
            spec.filesystem_readonly = filesystem.readonly.clone();
            spec.filesystem_deny = filesystem.deny.clone();
        }

        if let Some(environment) = &self.environment {
            spec.env_passthrough = environment.passthrough.clone();
            spec.env_deny = environment.deny.clone();
        }

        spec
    }
}

impl PolicySpec {
    pub fn merge(mut self, overlay: PolicySpec) -> Self {
        if overlay.level.is_some() {
            self.level = overlay.level;
        }
        merge_vec(&mut self.allow_net, overlay.allow_net);
        if overlay.network_deny_all_other.is_some() {
            self.network_deny_all_other = overlay.network_deny_all_other;
        }
        merge_vec(&mut self.filesystem_writable, overlay.filesystem_writable);
        merge_vec(&mut self.filesystem_readonly, overlay.filesystem_readonly);
        merge_vec(&mut self.filesystem_deny, overlay.filesystem_deny);
        merge_vec(&mut self.env_passthrough, overlay.env_passthrough);
        merge_vec(&mut self.env_deny, overlay.env_deny);
        if overlay.max_cpu.is_some() {
            self.max_cpu = overlay.max_cpu;
        }
        if overlay.max_ram.is_some() {
            self.max_ram = overlay.max_ram;
        }
        if overlay.max_disk.is_some() {
            self.max_disk = overlay.max_disk;
        }
        if overlay.timeout.is_some() {
            self.timeout = overlay.timeout;
        }

        self
    }
}

fn merge_vec<T>(base: &mut Option<Vec<T>>, overlay: Option<Vec<T>>)
where
    T: Eq + std::hash::Hash + Clone,
{
    let Some(mut incoming) = overlay else {
        return;
    };

    match base {
        Some(existing) => {
            existing.append(&mut incoming);
            let mut seen = HashSet::new();
            existing.retain(|item| seen.insert(item.clone()));
        }
        None => {
            *base = Some(incoming);
        }
    }
}

pub fn resolve_policy(
    working_dir: &Path,
    preset: Option<PresetKind>,
    config: Option<ConfigFile>,
    overrides: PolicyOverrides,
) -> Result<ResolvedPolicy, PolicyError> {
    let mut spec = preset.map(|kind| kind.default_spec()).unwrap_or_default();
    if let Some(config) = config {
        spec = spec.merge(config.to_spec());
    }
    spec = spec.merge(overrides.to_spec());
    ResolvedPolicy::from_spec(working_dir, spec)
}

impl ResolvedPolicy {
    pub fn from_spec(working_dir: &Path, spec: PolicySpec) -> Result<Self, PolicyError> {
        let level = spec.level.unwrap_or_default();
        let defaults = level_defaults(level);

        let allow_net = normalize_strings(spec.allow_net.unwrap_or_default());
        let network_deny_all_other = spec.network_deny_all_other.unwrap_or(true);
        let filesystem_writable = normalize_paths(
            spec.filesystem_writable
                .unwrap_or_else(|| vec![working_dir.to_path_buf(), std::env::temp_dir()]),
        );
        let filesystem_readonly = normalize_paths(spec.filesystem_readonly.unwrap_or_default());
        let filesystem_deny = normalize_paths(spec.filesystem_deny.unwrap_or_default());

        let mut env_passthrough = normalize_strings(spec.env_passthrough.unwrap_or_else(|| {
            safe_infra_env_keys()
                .iter()
                .map(|value| value.to_string())
                .collect()
        }));
        env_passthrough
            .retain(|key| !matches_glob_any(key, spec.env_deny.as_deref().unwrap_or(&[])));

        let env_deny = normalize_strings(spec.env_deny.unwrap_or_default());

        let max_cpu = spec.max_cpu.unwrap_or(defaults.max_cpu);
        let max_ram_bytes = parse_human_size(spec.max_ram.as_deref().unwrap_or(defaults.max_ram))?;
        let max_disk_bytes =
            parse_human_size(spec.max_disk.as_deref().unwrap_or(defaults.max_disk))?;
        let timeout = parse_human_duration(spec.timeout.as_deref().unwrap_or(defaults.timeout))?;

        let policy = Self {
            working_dir: working_dir.to_path_buf(),
            level,
            allow_net,
            network_deny_all_other,
            filesystem_writable,
            filesystem_readonly,
            filesystem_deny,
            env_passthrough,
            env_deny,
            max_cpu,
            max_ram_bytes,
            max_disk_bytes,
            timeout,
        };

        policy.validate()?;
        Ok(policy)
    }

    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!("level = {}", self.level),
            format!("allow_net = {}", format_list(&self.allow_net)),
            format!("deny_all_other = {}", self.network_deny_all_other),
            format!("fs_writable = {}", format_paths(&self.filesystem_writable)),
            format!("fs_readonly = {}", format_paths(&self.filesystem_readonly)),
            format!("env_passthrough = {}", format_list(&self.env_passthrough)),
            format!("max_cpu = {}", self.max_cpu),
            format!("max_ram = {}", format_bytes(self.max_ram_bytes)),
            format!("max_disk = {}", format_bytes(self.max_disk_bytes)),
            format!("timeout = {}", format_duration(self.timeout)),
        ]
    }

    pub fn filtered_env_pairs(&self) -> Vec<(String, String)> {
        let allow_patterns = &self.env_passthrough;
        std::env::vars()
            .filter(|(key, _)| matches_glob_any(key, allow_patterns.as_slice()))
            .filter(|(key, _)| !matches_glob_any(key, self.env_deny.as_slice()))
            .collect()
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.max_cpu == 0 {
            return Err(PolicyError::InvalidPolicyConfiguration(
                "max_cpu must be greater than zero".to_string(),
            ));
        }
        if self.max_ram_bytes == 0 {
            return Err(PolicyError::InvalidPolicyConfiguration(
                "max_ram must be greater than zero".to_string(),
            ));
        }
        if self.max_disk_bytes == 0 {
            return Err(PolicyError::InvalidPolicyConfiguration(
                "max_disk must be greater than zero".to_string(),
            ));
        }
        if self.timeout.is_zero() {
            return Err(PolicyError::InvalidPolicyConfiguration(
                "timeout must be greater than zero".to_string(),
            ));
        }
        if !self.network_deny_all_other && self.allow_net.is_empty() {
            return Err(PolicyError::InvalidPolicyConfiguration(
                "open network requires an explicit allow_net list".to_string(),
            ));
        }
        validate_path_conflicts(
            &self.working_dir,
            "filesystem writable",
            &self.filesystem_writable,
            "filesystem readonly",
            &self.filesystem_readonly,
        )?;
        validate_path_conflicts(
            &self.working_dir,
            "filesystem writable",
            &self.filesystem_writable,
            "filesystem deny",
            &self.filesystem_deny,
        )?;
        validate_path_conflicts(
            &self.working_dir,
            "filesystem readonly",
            &self.filesystem_readonly,
            "filesystem deny",
            &self.filesystem_deny,
        )?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct LevelDefaults {
    max_cpu: u32,
    max_ram: &'static str,
    max_disk: &'static str,
    timeout: &'static str,
}

fn level_defaults(level: IsolationLevel) -> LevelDefaults {
    match level {
        IsolationLevel::Fast => LevelDefaults {
            max_cpu: 1,
            max_ram: "256m",
            max_disk: "512m",
            timeout: "60s",
        },
        IsolationLevel::Safe => LevelDefaults {
            max_cpu: 1,
            max_ram: "512m",
            max_disk: "1g",
            timeout: "5m",
        },
        IsolationLevel::Paranoid => LevelDefaults {
            max_cpu: 1,
            max_ram: "256m",
            max_disk: "512m",
            timeout: "5m",
        },
    }
}

impl PresetKind {
    pub fn default_spec(self) -> PolicySpec {
        match self {
            PresetKind::AiAgent => PolicySpec {
                level: Some(IsolationLevel::Safe),
                allow_net: Some(vec![
                    "api.openai.com:443".to_string(),
                    "api.anthropic.com:443".to_string(),
                ]),
                network_deny_all_other: Some(true),
                filesystem_writable: Some(vec![PathBuf::from("."), std::env::temp_dir()]),
                filesystem_readonly: Some(vec![]),
                filesystem_deny: Some(vec![
                    PathBuf::from("/etc/passwd"),
                    PathBuf::from("/proc"),
                    PathBuf::from("/sys"),
                ]),
                env_passthrough: Some(vec![
                    "OPENAI_API_KEY".to_string(),
                    "ANTHROPIC_API_KEY".to_string(),
                    "NODE_ENV".to_string(),
                ]),
                env_deny: Some(vec!["AWS_SECRET_*".to_string(), "DATABASE_*".to_string()]),
                max_cpu: Some(1),
                max_ram: Some("1g".to_string()),
                max_disk: Some("2g".to_string()),
                timeout: Some("10m".to_string()),
            },
            PresetKind::WebServer => PolicySpec {
                level: Some(IsolationLevel::Safe),
                allow_net: Some(vec![
                    "127.0.0.1:3000".to_string(),
                    "127.0.0.1:8080".to_string(),
                    "127.0.0.1:9000".to_string(),
                ]),
                network_deny_all_other: Some(true),
                filesystem_writable: Some(vec![PathBuf::from("."), std::env::temp_dir()]),
                filesystem_readonly: Some(vec![]),
                filesystem_deny: Some(vec![PathBuf::from("/proc"), PathBuf::from("/sys")]),
                env_passthrough: Some(vec!["NODE_ENV".to_string()]),
                env_deny: Some(vec!["AWS_SECRET_*".to_string(), "DATABASE_*".to_string()]),
                max_cpu: Some(2),
                max_ram: Some("1g".to_string()),
                max_disk: Some("2g".to_string()),
                timeout: Some("30m".to_string()),
            },
            PresetKind::Hermetic => PolicySpec {
                level: Some(IsolationLevel::Safe),
                allow_net: Some(Vec::new()),
                network_deny_all_other: Some(true),
                filesystem_writable: Some(vec![PathBuf::from("."), std::env::temp_dir()]),
                filesystem_readonly: Some(vec![]),
                filesystem_deny: Some(vec![
                    PathBuf::from("/etc"),
                    PathBuf::from("/proc"),
                    PathBuf::from("/sys"),
                ]),
                env_passthrough: Some(Vec::new()),
                env_deny: Some(vec!["*".to_string()]),
                max_cpu: Some(1),
                max_ram: Some("256m".to_string()),
                max_disk: Some("512m".to_string()),
                timeout: Some("5m".to_string()),
            },
        }
    }
}

pub fn parse_allow_fs_entry(input: &str) -> Result<(Vec<PathBuf>, Vec<PathBuf>), PolicyError> {
    let mut writable = Vec::new();
    let mut readonly = Vec::new();

    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (path, mode) = match part.rsplit_once(':') {
            Some((path, mode)) => (path.trim(), mode.trim()),
            None => (part, "rw"),
        };

        let path = PathBuf::from(path);
        match mode.to_ascii_lowercase().as_str() {
            "rw" | "write" | "writable" => writable.push(path),
            "ro" | "read" | "readonly" | "read-only" => readonly.push(path),
            other => return Err(PolicyError::InvalidFilesystemAllowSpec(other.to_string())),
        }
    }

    Ok((writable, readonly))
}

pub fn parse_human_size(input: &str) -> Result<u64, PolicyError> {
    let trimmed = input.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(PolicyError::InvalidSize(input.to_string()));
    }

    let (num, multiplier) = if let Some(value) = trimmed.strip_suffix("kb") {
        (value, 1024u64)
    } else if let Some(value) = trimmed.strip_suffix('k') {
        (value, 1024u64)
    } else if let Some(value) = trimmed.strip_suffix("mb") {
        (value, 1024u64 * 1024)
    } else if let Some(value) = trimmed.strip_suffix('m') {
        (value, 1024u64 * 1024)
    } else if let Some(value) = trimmed.strip_suffix("gb") {
        (value, 1024u64 * 1024 * 1024)
    } else if let Some(value) = trimmed.strip_suffix('g') {
        (value, 1024u64 * 1024 * 1024)
    } else if let Some(value) = trimmed.strip_suffix("tb") {
        (value, 1024u64 * 1024 * 1024 * 1024)
    } else if let Some(value) = trimmed.strip_suffix('t') {
        (value, 1024u64 * 1024 * 1024 * 1024)
    } else {
        (trimmed.as_str(), 1u64)
    };

    let parsed: u64 = num
        .trim()
        .parse()
        .map_err(|_| PolicyError::InvalidSize(input.to_string()))?;
    Ok(parsed.saturating_mul(multiplier))
}

pub fn parse_human_duration(input: &str) -> Result<Duration, PolicyError> {
    let trimmed = input.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(PolicyError::InvalidDuration(input.to_string()));
    }

    let (num, multiplier) = if let Some(value) = trimmed.strip_suffix("ms") {
        (value, 1u64)
    } else if let Some(value) = trimmed.strip_suffix('s') {
        (value, 1_000u64)
    } else if let Some(value) = trimmed.strip_suffix('m') {
        (value, 60_000u64)
    } else if let Some(value) = trimmed.strip_suffix('h') {
        (value, 3_600_000u64)
    } else {
        (trimmed.as_str(), 1_000u64)
    };

    let parsed: u64 = num
        .trim()
        .parse()
        .map_err(|_| PolicyError::InvalidDuration(input.to_string()))?;
    Ok(Duration::from_millis(parsed.saturating_mul(multiplier)))
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB && bytes % GB == 0 {
        format!("{}g", bytes / GB)
    } else if bytes >= MB && bytes % MB == 0 {
        format!("{}m", bytes / MB)
    } else if bytes >= KB && bytes % KB == 0 {
        format!("{}k", bytes / KB)
    } else {
        bytes.to_string()
    }
}

pub fn format_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis % 3_600_000 == 0 {
        format!("{}h", millis / 3_600_000)
    } else if millis % 60_000 == 0 {
        format!("{}m", millis / 60_000)
    } else if millis % 1_000 == 0 {
        format!("{}s", millis / 1_000)
    } else {
        format!("{}ms", millis)
    }
}

fn normalize_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            result.push(trimmed.to_string());
        }
    }
    result
}

fn normalize_paths(values: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            result.push(value);
        }
    }
    result
}

fn format_list(values: &[String]) -> String {
    if values.is_empty() {
        "[]".to_string()
    } else {
        format!("[{}]", values.join(", "))
    }
}

fn format_paths(values: &[PathBuf]) -> String {
    if values.is_empty() {
        "[]".to_string()
    } else {
        let joined = values
            .iter()
            .map(|value| value.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!("[{}]", joined)
    }
}

fn validate_path_conflicts(
    working_dir: &Path,
    left_label: &str,
    left: &[PathBuf],
    right_label: &str,
    right: &[PathBuf],
) -> Result<(), PolicyError> {
    let right_set: HashSet<PathBuf> = right
        .iter()
        .map(|path| normalize_policy_path(working_dir, path))
        .collect();
    let conflicts = left
        .iter()
        .map(|path| normalize_policy_path(working_dir, path))
        .filter(|path| right_set.contains(path))
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();

    if conflicts.is_empty() {
        return Ok(());
    }

    Err(PolicyError::InvalidPolicyConfiguration(format!(
        "{left_label} conflicts with {right_label} for: {}",
        conflicts.join(", ")
    )))
}

fn normalize_policy_path(working_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        working_dir.join(path)
    }
}

fn safe_infra_env_keys() -> &'static [&'static str] {
    &[
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
    ]
}

fn matches_glob_any(candidate: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| matches_glob(pattern, candidate))
}

fn matches_glob(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let pattern = pattern.trim();
    if !pattern.contains('*') {
        return pattern.eq_ignore_ascii_case(candidate);
    }

    let mut remainder = candidate;
    let parts = pattern.split('*');
    let mut first = true;

    for part in parts {
        if part.is_empty() {
            continue;
        }

        if first && !pattern.starts_with('*') {
            if !remainder.starts_with(part) {
                return false;
            }
            remainder = &remainder[part.len()..];
            first = false;
            continue;
        }

        if let Some(index) = remainder.find(part) {
            remainder = &remainder[index + part.len()..];
            first = false;
        } else {
            return false;
        }
    }
    if !pattern.ends_with('*') {
        if let Some(last_part) = pattern.rsplit('*').next() {
            return candidate.ends_with(last_part);
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sizes_and_durations() {
        assert_eq!(parse_human_size("512m").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_human_size("1g").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(
            parse_human_duration("5m").unwrap(),
            Duration::from_secs(300)
        );
        assert_eq!(
            parse_human_duration("250ms").unwrap(),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn resolves_ai_agent_preset() {
        let preset = PresetKind::AiAgent.default_spec();
        assert!(preset
            .allow_net
            .as_ref()
            .unwrap()
            .contains(&"api.openai.com:443".to_string()));
    }

    #[test]
    fn parses_allow_fs_entries() {
        let (writable, readonly) = parse_allow_fs_entry("/tmp:rw,/data:ro").unwrap();
        assert_eq!(writable.len(), 1);
        assert_eq!(readonly.len(), 1);
    }

    #[test]
    fn glob_matching_is_reasonable() {
        assert!(matches_glob("AWS_SECRET_*", "AWS_SECRET_KEY"));
        assert!(matches_glob("*TOKEN*", "OPENAI_TOKEN"));
        assert!(!matches_glob("NODE_ENV", "DATABASE_URL"));
    }

    #[test]
    fn rejects_open_network_without_allowlist() {
        let policy = ResolvedPolicy {
            working_dir: PathBuf::from("."),
            level: IsolationLevel::Safe,
            allow_net: Vec::new(),
            network_deny_all_other: false,
            filesystem_writable: Vec::new(),
            filesystem_readonly: Vec::new(),
            filesystem_deny: Vec::new(),
            env_passthrough: Vec::new(),
            env_deny: Vec::new(),
            max_cpu: 1,
            max_ram_bytes: 1024,
            max_disk_bytes: 1024,
            timeout: Duration::from_secs(1),
        };

        let err = policy.validate().unwrap_err();
        assert!(err.to_string().contains("open network"));
    }

    #[test]
    fn rejects_unsupported_config_version() {
        let unique = format!(
            "microbox-invalid-version-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::write(&path, "version = 2\n").unwrap();

        let err = ConfigFile::load(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);

        assert!(err.to_string().contains("unsupported config version"));
    }

    #[test]
    fn defaults_workspace_to_writable() {
        let policy =
            ResolvedPolicy::from_spec(&PathBuf::from("/workspace"), PolicySpec::default()).unwrap();

        assert!(policy
            .filesystem_writable
            .contains(&PathBuf::from("/workspace")));
        assert!(policy.filesystem_writable.contains(&std::env::temp_dir()));
        assert!(policy.filesystem_readonly.is_empty());
    }

    #[test]
    fn rejects_conflicting_filesystem_rules() {
        let policy = ResolvedPolicy {
            working_dir: PathBuf::from("."),
            level: IsolationLevel::Safe,
            allow_net: vec!["api.openai.com:443".to_string()],
            network_deny_all_other: true,
            filesystem_writable: vec![PathBuf::from("/workspace")],
            filesystem_readonly: vec![PathBuf::from("/workspace")],
            filesystem_deny: vec![],
            env_passthrough: vec![],
            env_deny: vec![],
            max_cpu: 1,
            max_ram_bytes: 1024,
            max_disk_bytes: 1024,
            timeout: Duration::from_secs(1),
        };

        let err = policy.validate().unwrap_err();
        assert!(err.to_string().contains("conflicts"));
    }
}
