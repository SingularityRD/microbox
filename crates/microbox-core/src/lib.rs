use microbox_policy::ResolvedPolicy;
use std::{
    path::PathBuf,
    process::{ExitStatus, Output},
    time::Duration,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandPlan {
    Direct { argv: Vec<String> },
    Shell { command: String },
}

impl CommandPlan {
    pub fn from_raw(raw: Vec<String>) -> Result<Self, SandboxError> {
        if raw.is_empty() {
            return Err(SandboxError::EmptyCommand);
        }

        if raw.len() == 1 && looks_like_shell_command(&raw[0]) {
            Ok(Self::Shell {
                command: raw[0].clone(),
            })
        } else {
            Ok(Self::Direct { argv: raw })
        }
    }

    pub fn display(&self) -> String {
        match self {
            CommandPlan::Direct { argv } => argv
                .iter()
                .map(|arg| shell_escape(arg))
                .collect::<Vec<_>>()
                .join(" "),
            CommandPlan::Shell { command } => command.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunRequest {
    pub command: CommandPlan,
    pub working_dir: PathBuf,
    pub policy: ResolvedPolicy,
}

impl RunRequest {
    pub fn new(command: CommandPlan, working_dir: PathBuf, policy: ResolvedPolicy) -> Self {
        Self {
            command,
            working_dir,
            policy,
        }
    }
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    pub timed_out: bool,
}

impl ExecutionResult {
    pub fn from_output(output: Output, duration: Duration) -> Self {
        Self {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration,
            timed_out: false,
        }
    }

    pub fn from_status(
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        duration: Duration,
        timed_out: bool,
    ) -> Self {
        Self {
            status,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            duration,
            timed_out,
        }
    }

    pub fn exit_code(&self) -> i32 {
        if self.timed_out {
            return 124;
        }
        self.status.code().unwrap_or(1)
    }
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("empty command")]
    EmptyCommand,
    #[error("launch failed: {0}")]
    LaunchFailed(String),
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("policy error: {0}")]
    Policy(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("timed out")]
    TimedOut,
}

fn looks_like_shell_command(input: &str) -> bool {
    input.contains([' ', '\t', '\n'])
        || input.contains("&&")
        || input.contains("||")
        || input.contains('|')
        || input.contains(';')
        || input.contains('>')
        || input.contains('<')
}

pub fn shell_escape(input: &str) -> String {
    if input.is_empty() {
        return "\"\"".to_string();
    }

    if input
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | '\\'))
    {
        return input.to_string();
    }

    let mut escaped = String::with_capacity(input.len() + 2);
    escaped.push('"');
    for ch in input.chars() {
        match ch {
            '\\' | '"' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_detection_is_reasonable() {
        assert!(looks_like_shell_command("npm install && npm start"));
        assert!(!looks_like_shell_command("python"));
    }

    #[test]
    fn direct_command_plan_keeps_args() {
        let plan = CommandPlan::from_raw(vec!["python".into(), "agent.py".into()]).unwrap();
        match plan {
            CommandPlan::Direct { argv } => assert_eq!(argv.len(), 2),
            CommandPlan::Shell { .. } => panic!("expected direct command"),
        }
    }

    #[test]
    fn display_quotes_arguments_with_spaces() {
        let plan = CommandPlan::Direct {
            argv: vec!["echo".into(), "hello world".into()],
        };

        assert_eq!(plan.display(), "echo \"hello world\"");
    }

    #[test]
    fn shell_escape_is_stable_for_simple_inputs() {
        assert_eq!(shell_escape("python"), "python");
        assert_eq!(shell_escape(""), "\"\"");
        assert_eq!(shell_escape("a b"), "\"a b\"");
    }
}
