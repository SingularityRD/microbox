use crate::{args::PolicyArgs, config::discover_config};
use microbox_backend::{select_backend, BackendPreference, SandboxBackend};
use microbox_core::{CommandPlan, ExecutionResult, RunRequest, SandboxError};
use microbox_policy::{resolve_policy, ResolvedPolicy};
use std::{
    env,
    io::Write,
    path::{Path, PathBuf},
};

pub(crate) struct RunContext {
    pub working_dir: PathBuf,
    pub policy: ResolvedPolicy,
}

pub fn run(args: crate::args::RunArgs) -> Result<i32, SandboxError> {
    let result = execute_run(
        args,
        env::current_dir().map_err(|error| SandboxError::Io(error.to_string()))?,
    )?;

    print_execution_result(&result)?;
    Ok(result.exit_code())
}

pub(crate) fn execute_run(
    args: crate::args::RunArgs,
    working_dir: PathBuf,
) -> Result<ExecutionResult, SandboxError> {
    let context = prepare_context_in_dir(&args.policy, working_dir)?;
    let RunContext {
        working_dir,
        policy,
    } = context;
    let command = CommandPlan::from_raw(args.command)?;
    let request = RunRequest::new(command, working_dir, policy);
    let backend = select_backend_for_policy(args.policy.backend)?;
    backend.run(&request)
}

fn print_execution_result(result: &ExecutionResult) -> Result<(), SandboxError> {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();

    if !result.stdout.is_empty() {
        stdout
            .write_all(result.stdout.as_bytes())
            .map_err(|error| SandboxError::Io(error.to_string()))?;
        stdout
            .flush()
            .map_err(|error| SandboxError::Io(error.to_string()))?;
    }

    if !result.stderr.is_empty() {
        stderr
            .write_all(result.stderr.as_bytes())
            .map_err(|error| SandboxError::Io(error.to_string()))?;
        stderr
            .flush()
            .map_err(|error| SandboxError::Io(error.to_string()))?;
    }

    if result.timed_out {
        eprintln!("microbox: command timed out");
    }

    Ok(())
}

pub(crate) fn prepare_context(args: &PolicyArgs) -> Result<RunContext, SandboxError> {
    let working_dir = env::current_dir().map_err(|error| SandboxError::Io(error.to_string()))?;
    prepare_context_in_dir(args, working_dir)
}

pub(crate) fn prepare_context_in_dir(
    args: &PolicyArgs,
    working_dir: PathBuf,
) -> Result<RunContext, SandboxError> {
    let config = discover_config(args.config.clone())
        .map_err(|error| SandboxError::Policy(error.to_string()))?;
    let overrides = args.to_overrides().map_err(SandboxError::Policy)?;
    let policy = resolve_policy(Path::new(&working_dir), args.preset, config, overrides)
        .map_err(|error| SandboxError::Policy(error.to_string()))?;

    Ok(RunContext {
        working_dir,
        policy,
    })
}

pub(crate) fn select_backend_for_policy(
    preference: BackendPreference,
) -> Result<Box<dyn SandboxBackend>, SandboxError> {
    match preference {
        BackendPreference::Auto => select_backend(BackendPreference::Auto),
        BackendPreference::Compat => select_backend(BackendPreference::Compat),
        BackendPreference::Secure => select_backend(BackendPreference::Secure),
    }
}
