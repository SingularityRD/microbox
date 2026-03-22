use clap::ValueEnum;
use microbox_core::{shell_escape, CommandPlan, ExecutionResult, RunRequest, SandboxError};
use std::{
    fmt,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::{
    collections::HashSet,
    net::{SocketAddr, ToSocketAddrs},
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[cfg(target_os = "linux")]
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackendPreference {
    Auto,
    Compat,
    Secure,
}

impl fmt::Display for BackendPreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BackendPreference::Auto => "auto",
            BackendPreference::Compat => "compat",
            BackendPreference::Secure => "secure",
        })
    }
}

pub struct BackendCapabilities {
    pub name: &'static str,
    pub secure_enforcement: bool,
    pub notes: Vec<String>,
}

pub trait SandboxBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> BackendCapabilities;
    fn run(&self, request: &RunRequest) -> Result<ExecutionResult, SandboxError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CompatBackend;

#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxSecureBackend;

pub fn select_backend(
    preference: BackendPreference,
) -> Result<Box<dyn SandboxBackend>, SandboxError> {
    match preference {
        BackendPreference::Auto => Ok(auto_backend()),
        BackendPreference::Compat => Ok(Box::new(CompatBackend)),
        BackendPreference::Secure => {
            if cfg!(target_os = "linux") {
                Ok(Box::new(LinuxSecureBackend))
            } else {
                Err(SandboxError::BackendUnavailable(
                    "secure backend is only available on Linux".to_string(),
                ))
            }
        }
    }
}

pub fn default_backend() -> Box<dyn SandboxBackend> {
    auto_backend()
}

fn auto_backend() -> Box<dyn SandboxBackend> {
    if cfg!(target_os = "linux") {
        Box::new(LinuxSecureBackend)
    } else {
        Box::new(CompatBackend)
    }
}

impl SandboxBackend for CompatBackend {
    fn name(&self) -> &'static str {
        "compat-local-exec"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: self.name(),
            secure_enforcement: false,
            notes: vec![
                "local execution fallback for non-Linux hosts".to_string(),
                "policy model and CLI are production-shaped; kernel enforcement is limited on this backend".to_string(),
            ],
        }
    }

    fn run(&self, request: &RunRequest) -> Result<ExecutionResult, SandboxError> {
        run_with_command(self.name(), request, false)
    }
}

impl SandboxBackend for LinuxSecureBackend {
    fn name(&self) -> &'static str {
        "linux-secure"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: self.name(),
            secure_enforcement: true,
            notes: vec![
                "namespace isolation is attempted when the kernel allows it".to_string(),
                "Landlock filesystem confinement is applied to the command and its direct runtime dependencies".to_string(),
                "seccomp denies escape-oriented syscalls and supervises outbound allowlists".to_string(),
                "cgroups v2 are applied best-effort when delegation is available".to_string(),
            ],
        }
    }

    fn run(&self, request: &RunRequest) -> Result<ExecutionResult, SandboxError> {
        #[cfg(target_os = "linux")]
        {
            if bubblewrap_binary().is_some() {
                if request.policy.allow_net.is_empty() {
                    return run_with_bubblewrap(self.name(), request);
                }
            }

            if !request.policy.allow_net.is_empty() {
                return run_with_command_allowlist(self.name(), request);
            }
        }

        run_with_command(self.name(), request, true)
    }
}

fn run_with_command(
    backend_name: &'static str,
    request: &RunRequest,
    harden: bool,
) -> Result<ExecutionResult, SandboxError> {
    let mut command = build_command(&request.command, request, harden)?;
    let start = Instant::now();
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if !harden && cfg!(windows) && error.kind() == io::ErrorKind::NotFound => {
            let fallback_plan = match &request.command {
                CommandPlan::Direct { argv } => CommandPlan::Shell {
                    command: argv
                        .iter()
                        .map(|arg| shell_escape(arg))
                        .collect::<Vec<_>>()
                        .join(" "),
                },
                CommandPlan::Shell { command } => CommandPlan::Shell {
                    command: command.clone(),
                },
            };
            let mut fallback = build_command(&fallback_plan, request, harden)?;
            fallback
                .spawn()
                .map_err(|error| SandboxError::LaunchFailed(format!("{backend_name}: {error}")))?
        }
        Err(error) => {
            return Err(SandboxError::LaunchFailed(format!(
                "{backend_name}: {error}"
            )));
        }
    };

    #[cfg(target_os = "linux")]
    if harden {
        let _ = apply_cgroup_limits(child.id(), request);
    }

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

#[cfg(target_os = "linux")]
fn run_with_command_allowlist(
    backend_name: &'static str,
    request: &RunRequest,
) -> Result<ExecutionResult, SandboxError> {
    let network_policy = resolve_network_allowlist(&request.policy.allow_net)?;
    let listener_pair = std::os::unix::net::UnixStream::pair()
        .map_err(|error| SandboxError::LaunchFailed(format!("{backend_name}: {error}")))?;
    let listener_sender = listener_pair
        .1
        .try_clone()
        .map_err(|error| SandboxError::LaunchFailed(format!("{backend_name}: {error}")))?;

    let mut command = build_command(&request.command, request, false)?;
    configure_linux_allowlist_hardening(&mut command, request, listener_sender)?;

    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| SandboxError::LaunchFailed(format!("{backend_name}: {error}")))?;

    let listener_fd = receive_listener_fd(&listener_pair.0)?;
    let supervisor = spawn_network_supervisor(listener_fd, network_policy)?;

    #[cfg(target_os = "linux")]
    let _ = apply_cgroup_limits(child.id(), request);

    let collected = collect_output(&mut child, request.policy.timeout)?;
    let duration = start.elapsed();

    supervisor.stop.store(true, Ordering::SeqCst);
    let _ = supervisor.join.join();

    Ok(ExecutionResult::from_status(
        collected.status,
        collected.stdout,
        collected.stderr,
        duration,
        collected.timed_out,
    ))
}

#[cfg(target_os = "linux")]
fn configure_linux_allowlist_hardening(
    command: &mut Command,
    request: &RunRequest,
    listener_sender: std::os::unix::net::UnixStream,
) -> Result<(), SandboxError> {
    use std::os::unix::process::CommandExt;

    let hardening = LinuxHardeningPlan::from_request(request)?;
    let listener_sender = Some(listener_sender);

    unsafe {
        command.pre_exec(move || {
            set_process_group()?;
            attempt_namespace_isolation()?;
            set_no_new_privs()?;
            set_dumpable(false)?;
            set_umask();
            set_resource_limits(&hardening)?;
            apply_landlock(&hardening)?;
            let listener_fd = install_seccomp_filter_allowlist()?;
            if let Some(sender) = listener_sender.as_ref() {
                send_listener_fd(sender.as_raw_fd(), listener_fd)?;
            }
            close_fd(listener_fd)?;
            Ok(())
        });
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn run_with_bubblewrap(
    backend_name: &'static str,
    request: &RunRequest,
) -> Result<ExecutionResult, SandboxError> {
    let mut command = build_bubblewrap_command(&request.command, request)?;
    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| SandboxError::LaunchFailed(format!("{backend_name}: {error}")))?;
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

fn build_command(
    plan: &CommandPlan,
    request: &RunRequest,
    harden: bool,
) -> Result<Command, SandboxError> {
    let mut command = match plan {
        CommandPlan::Direct { argv } => {
            let executable = match resolve_executable_path(&argv[0], &request.working_dir) {
                Ok(path) => path,
                Err(error) if !harden && cfg!(windows) => {
                    let _ = error;
                    PathBuf::from(&argv[0])
                }
                Err(error) => return Err(error),
            };
            let mut command = Command::new(executable);
            command.args(&argv[1..]);
            command
        }
        CommandPlan::Shell { command } => shell_command(command),
    };

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

    if harden {
        configure_linux_hardening(&mut command, request)?;
    }

    Ok(command)
}

#[cfg(target_os = "linux")]
fn build_bubblewrap_command(
    plan: &CommandPlan,
    request: &RunRequest,
) -> Result<Command, SandboxError> {
    let bubblewrap = bubblewrap_binary().ok_or_else(|| {
        SandboxError::LaunchFailed("bubblewrap is not installed or not on PATH".to_string())
    })?;
    let mut command = Command::new(bubblewrap);
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

    for path in &request.policy.filesystem_writable {
        let mounted = ensure_existing_target(path, &request.working_dir);
        command.arg("--bind").arg(&mounted).arg(&mounted);
    }

    for (key, value) in bootstrap_env_pairs() {
        command.arg("--setenv").arg(key).arg(value);
    }
    for (key, value) in request.policy.filtered_env_pairs() {
        command.arg("--setenv").arg(key).arg(value);
    }

    command.arg("--");
    match plan {
        CommandPlan::Direct { argv } => {
            let executable = resolve_executable_path(&argv[0], &request.working_dir)?;
            command.arg(executable);
            command.args(&argv[1..]);
        }
        CommandPlan::Shell { command: shell } => {
            if cfg!(windows) {
                command.arg(windows_shell_binary());
                command.arg("/C");
                command.arg(shell);
            } else {
                command.arg("/bin/sh");
                command.arg("-c");
                command.arg(shell);
            }
        }
    }

    configure_launcher_hardening(&mut command, request)?;
    Ok(command)
}

fn shell_command(command: &str) -> Command {
    if cfg!(windows) {
        let mut shell = Command::new(windows_shell_binary());
        shell.args(["/C", command]);
        shell
    } else {
        let mut shell = Command::new("/bin/sh");
        shell.args(["-c", command]);
        shell
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

fn resolve_executable_path(executable: &str, working_dir: &Path) -> Result<PathBuf, SandboxError> {
    let candidate = Path::new(executable);
    if candidate.is_absolute() || candidate.components().count() > 1 {
        if candidate.is_absolute() {
            return Ok(candidate.to_path_buf());
        }
        return Ok(working_dir.join(candidate));
    }

    let path_var = std::env::var_os("PATH").ok_or_else(|| {
        SandboxError::LaunchFailed(format!(
            "unable to resolve executable `{executable}` without PATH"
        ))
    })?;

    for entry in std::env::split_paths(&path_var) {
        let path = entry.join(executable);
        if path.exists() {
            return Ok(path);
        }
    }

    Err(SandboxError::LaunchFailed(format!(
        "executable `{executable}` not found in PATH"
    )))
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
    #[cfg(target_os = "linux")]
    {
        if let Ok(pid) = i32::try_from(child.id()) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = child.kill();
    }
}

#[cfg(target_os = "linux")]
fn configure_linux_hardening(
    command: &mut Command,
    request: &RunRequest,
) -> Result<(), SandboxError> {
    use std::os::unix::process::CommandExt;

    let hardening = LinuxHardeningPlan::from_request(request)?;

    unsafe {
        command.pre_exec(move || {
            set_process_group()?;
            attempt_namespace_isolation()?;
            set_no_new_privs()?;
            set_dumpable(false)?;
            set_umask();
            set_resource_limits(&hardening)?;
            apply_landlock(&hardening)?;
            install_seccomp_filter_hermetic()?;
            Ok(())
        });
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_linux_hardening(
    _command: &mut Command,
    _request: &RunRequest,
) -> Result<(), SandboxError> {
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct LinuxHardeningPlan {
    working_dir: PathBuf,
    read_only_paths: Vec<PathBuf>,
    writable_paths: Vec<PathBuf>,
    executable_path: Option<PathBuf>,
    max_cpu: u32,
    max_ram_bytes: u64,
    max_disk_bytes: u64,
    timeout_secs: u64,
}

#[cfg(target_os = "linux")]
impl LinuxHardeningPlan {
    fn from_request(request: &RunRequest) -> Result<Self, SandboxError> {
        let mut read_only_paths = Vec::new();
        let mut writable_paths = Vec::new();

        for path in &request.policy.filesystem_readonly {
            read_only_paths.push(normalize_path(&request.working_dir, path));
        }
        for path in &request.policy.filesystem_writable {
            writable_paths.push(normalize_path(&request.working_dir, path));
        }

        for path in default_secure_readonly_paths() {
            read_only_paths.push(path);
        }

        let executable_path = match &request.command {
            CommandPlan::Direct { argv } => {
                Some(resolve_executable_path(&argv[0], &request.working_dir)?)
            }
            CommandPlan::Shell { .. } => Some(shell_binary_path()),
        };

        Ok(Self {
            working_dir: request.working_dir.clone(),
            read_only_paths,
            writable_paths,
            executable_path,
            max_cpu: request.policy.max_cpu.max(1),
            max_ram_bytes: request.policy.max_ram_bytes,
            max_disk_bytes: request.policy.max_disk_bytes,
            timeout_secs: request.policy.timeout.as_secs().max(1),
        })
    }
}

#[cfg(target_os = "linux")]
fn normalize_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

#[cfg(target_os = "linux")]
fn default_secure_readonly_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/sbin"),
        PathBuf::from("/usr/sbin"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/lib64"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/usr/share"),
        PathBuf::from("/dev"),
        PathBuf::from("/etc/ld.so.cache"),
        PathBuf::from("/etc/nsswitch.conf"),
        PathBuf::from("/etc/hosts"),
        PathBuf::from("/etc/resolv.conf"),
    ]
}

#[cfg(target_os = "linux")]
fn shell_binary_path() -> PathBuf {
    PathBuf::from("/bin/sh")
}

#[cfg(target_os = "windows")]
fn windows_shell_binary() -> PathBuf {
    std::env::var_os("ComSpec")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cmd.exe"))
}

#[cfg(target_os = "linux")]
fn bubblewrap_binary() -> Option<PathBuf> {
    find_in_path("bwrap")
}

#[cfg(target_os = "linux")]
fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&path_var) {
        let candidate = entry.join(binary);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn ensure_existing_target(path: &Path, working_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        working_dir.join(path)
    }
}

#[cfg(target_os = "linux")]
fn configure_launcher_hardening(
    command: &mut Command,
    request: &RunRequest,
) -> Result<(), SandboxError> {
    use std::os::unix::process::CommandExt;

    let max_cpu = request.policy.max_cpu.max(1);
    let max_ram_bytes = request.policy.max_ram_bytes;
    let max_disk_bytes = request.policy.max_disk_bytes;
    let timeout_secs = request.policy.timeout.as_secs().max(1);

    unsafe {
        command.pre_exec(move || {
            set_process_group()?;
            set_dumpable(false)?;
            set_umask();
            set_limit(libc::RLIMIT_CPU, timeout_secs, timeout_secs)?;
            set_limit(libc::RLIMIT_AS, max_ram_bytes, max_ram_bytes)?;
            set_limit(libc::RLIMIT_FSIZE, max_disk_bytes, max_disk_bytes)?;
            set_limit(libc::RLIMIT_NOFILE, 256, 256)?;
            set_limit(
                libc::RLIMIT_NPROC,
                max_cpu.saturating_mul(64) as u64,
                max_cpu.saturating_mul(64) as u64,
            )?;
            Ok(())
        });
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn set_process_group() -> io::Result<()> {
    let rc = unsafe { libc::setpgid(0, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn attempt_namespace_isolation() -> io::Result<()> {
    const CLONE_NEWUSER: libc::c_int = 0x10000000;
    const CLONE_NEWNS: libc::c_int = 0x00020000;
    const CLONE_NEWNET: libc::c_int = 0x40000000;
    const CLONE_NEWUTS: libc::c_int = 0x04000000;
    const CLONE_NEWIPC: libc::c_int = 0x08000000;

    let _ = unsafe { libc::unshare(CLONE_NEWUSER) };
    if let Err(error) = map_user_namespace() {
        if error.kind() != io::ErrorKind::PermissionDenied
            && error.kind() != io::ErrorKind::Unsupported
        {
            let _ = error;
        }
    }

    let _ = unsafe { libc::unshare(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC) };
    let _ = make_mounts_private();
    Ok(())
}

#[cfg(target_os = "linux")]
fn map_user_namespace() -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let setgroups = Path::new("/proc/self/setgroups");
    if setgroups.exists() {
        write_text(setgroups, "deny")?;
    }
    write_text(Path::new("/proc/self/uid_map"), &format!("0 {} 1", uid))?;
    write_text(Path::new("/proc/self/gid_map"), &format!("0 {} 1", gid))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn make_mounts_private() -> io::Result<()> {
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            b"/\0".as_ptr() as *const libc::c_char,
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_dumpable(value: bool) -> io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, value as libc::c_ulong, 0, 0, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_no_new_privs() -> io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_umask() {
    unsafe {
        libc::umask(0o077);
    }
}

#[cfg(target_os = "linux")]
fn set_resource_limits(plan: &LinuxHardeningPlan) -> io::Result<()> {
    set_limit(libc::RLIMIT_CPU, plan.timeout_secs, plan.timeout_secs)?;
    set_limit(libc::RLIMIT_AS, plan.max_ram_bytes, plan.max_ram_bytes)?;
    set_limit(libc::RLIMIT_FSIZE, plan.max_disk_bytes, plan.max_disk_bytes)?;
    set_limit(libc::RLIMIT_NOFILE, 256, 256)?;
    set_limit(
        libc::RLIMIT_NPROC,
        plan.max_cpu.saturating_mul(64) as u64,
        plan.max_cpu.saturating_mul(64) as u64,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_limit(resource: libc::__rlimit_resource_t, soft: u64, hard: u64) -> io::Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };

    let rc = unsafe { libc::setrlimit(resource, &rlimit) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_landlock(plan: &LinuxHardeningPlan) -> io::Result<()> {
    let version = landlock_version()?;
    if version == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Landlock is not available on this kernel",
        ));
    }

    let handled_access = landlock_access_mask(version);
    let ruleset_fd = create_landlock_ruleset(handled_access)?;

    for path in &plan.read_only_paths {
        if let Some(target) = landlock_target_path(path) {
            add_landlock_rule(ruleset_fd, &target, landlock_readonly_access(version))?;
        }
    }
    for path in &plan.writable_paths {
        if let Some(target) = landlock_target_path(path) {
            add_landlock_rule(ruleset_fd, &target, handled_access)?;
        }
    }
    if let Some(executable) = &plan.executable_path {
        if let Some(target) = landlock_target_path(executable) {
            add_landlock_rule(ruleset_fd, &target, landlock_readonly_access(version))?;
        }
    }

    restrict_self(ruleset_fd)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn landlock_target_path(path: &Path) -> Option<PathBuf> {
    if path.exists() {
        Some(path.to_path_buf())
    } else {
        path.parent().map(|parent| parent.to_path_buf())
    }
}

#[cfg(target_os = "linux")]
fn landlock_version() -> io::Result<u32> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1u32,
        )
    };
    if ret < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOSYS) {
            return Ok(0);
        }
        return Err(error);
    }
    Ok(ret as u32)
}

#[cfg(target_os = "linux")]
fn landlock_access_mask(version: u32) -> u64 {
    let mut access = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    if version >= 2 {
        access |= LANDLOCK_ACCESS_FS_REFER;
    }
    if version >= 3 {
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if version >= 4 {
        access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }

    access
}

#[cfg(target_os = "linux")]
fn landlock_readonly_access(version: u32) -> u64 {
    let mut access =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    if version >= 2 {
        access |= LANDLOCK_ACCESS_FS_REFER;
    }
    access
}

#[cfg(target_os = "linux")]
fn create_landlock_ruleset(handled_access: u64) -> io::Result<libc::c_int> {
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_access,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd as libc::c_int)
}

#[cfg(target_os = "linux")]
fn add_landlock_rule(ruleset_fd: libc::c_int, path: &Path, allowed_access: u64) -> io::Result<()> {
    let file = fs::File::open(path)?;
    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: file.as_raw_fd(),
        reserved: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const LandlockPathBeneathAttr,
            0u32,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn restrict_self(ruleset_fd: libc::c_int) -> io::Result<()> {
    let ret = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_seccomp_filter_hermetic() -> io::Result<()> {
    use libc::{sock_filter, sock_fprog};

    let mut program = Vec::new();
    program.push(stmt(
        libc::BPF_LD + libc::BPF_W + libc::BPF_ABS,
        seccomp_data_offset_arch() as u32,
    ));
    program.push(jump(
        libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K,
        audit_arch()?,
        1,
        0,
    ));
    program.push(stmt(
        libc::BPF_RET + libc::BPF_K,
        libc::SECCOMP_RET_KILL_PROCESS,
    ));
    program.push(stmt(
        libc::BPF_LD + libc::BPF_W + libc::BPF_ABS,
        seccomp_data_offset_nr() as u32,
    ));

    for syscall in denied_syscalls() {
        program.push(jump(
            libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K,
            syscall as u32,
            0,
            1,
        ));
        program.push(stmt(
            libc::BPF_RET + libc::BPF_K,
            libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));
    }

    program.push(stmt(libc::BPF_RET + libc::BPF_K, libc::SECCOMP_RET_ALLOW));

    let mut prog = sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr() as *mut sock_filter,
    };

    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut prog as *mut sock_fprog,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_seccomp_filter_allowlist() -> io::Result<libc::c_int> {
    use libc::{sock_filter, sock_fprog};

    let mut program = Vec::new();
    program.push(stmt(
        libc::BPF_LD + libc::BPF_W + libc::BPF_ABS,
        seccomp_data_offset_arch() as u32,
    ));
    program.push(jump(
        libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K,
        audit_arch()?,
        1,
        0,
    ));
    program.push(stmt(
        libc::BPF_RET + libc::BPF_K,
        libc::SECCOMP_RET_KILL_PROCESS,
    ));
    program.push(stmt(
        libc::BPF_LD + libc::BPF_W + libc::BPF_ABS,
        seccomp_data_offset_nr() as u32,
    ));

    for syscall in user_notif_syscalls() {
        program.push(jump(
            libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K,
            syscall as u32,
            0,
            1,
        ));
        program.push(stmt(
            libc::BPF_RET + libc::BPF_K,
            libc::SECCOMP_RET_USER_NOTIF,
        ));
    }

    for syscall in denied_syscalls() {
        program.push(jump(
            libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K,
            syscall as u32,
            0,
            1,
        ));
        program.push(stmt(
            libc::BPF_RET + libc::BPF_K,
            libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));
    }

    program.push(stmt(libc::BPF_RET + libc::BPF_K, libc::SECCOMP_RET_ALLOW));

    let mut prog = sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr() as *mut sock_filter,
    };

    let listener = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &mut prog as *mut sock_fprog,
        )
    };
    if listener < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(listener as libc::c_int)
}

#[cfg(target_os = "linux")]
fn denied_syscalls() -> &'static [libc::c_long] {
    &[
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_shutdown,
        libc::SYS_unshare,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_clone3,
    ]
}

#[cfg(target_os = "linux")]
fn user_notif_syscalls() -> &'static [libc::c_long] {
    &[
        libc::SYS_socket,
        libc::SYS_bind,
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
    ]
}

#[cfg(target_os = "linux")]
fn audit_arch() -> io::Result<u32> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(0xC000_003E)
    }

    #[cfg(target_arch = "aarch64")]
    {
        Ok(0xC000_00B7)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported linux architecture for seccomp filter",
        ))
    }
}

#[cfg(target_os = "linux")]
fn seccomp_data_offset_arch() -> usize {
    4
}

#[cfg(target_os = "linux")]
fn seccomp_data_offset_nr() -> usize {
    0
}

#[cfg(target_os = "linux")]
fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(target_os = "linux")]
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(target_os = "linux")]
fn apply_cgroup_limits(pid: u32, request: &RunRequest) -> io::Result<()> {
    let base = Path::new("/sys/fs/cgroup");
    if !base.exists() {
        return Ok(());
    }

    let group_name = format!("microbox-{}", pid);
    let group_dir = base.join(group_name);
    if fs::create_dir_all(&group_dir).is_err() {
        return Ok(());
    }

    let _ = write_text(
        &group_dir.join("memory.max"),
        &request.policy.max_ram_bytes.to_string(),
    );

    let cpu_quota = request.policy.max_cpu.max(1).saturating_mul(100_000);
    let _ = write_text(&group_dir.join("cpu.max"), &format!("{} 100000", cpu_quota));

    let pids_max = request.policy.max_cpu.max(1).saturating_mul(64).to_string();
    let _ = write_text(&group_dir.join("pids.max"), &pids_max);

    write_text(&group_dir.join("cgroup.procs"), &pid.to_string())?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct LinuxNetworkPolicy {
    allowed_addrs: HashSet<SocketAddr>,
}

#[cfg(target_os = "linux")]
struct NetworkSupervisorHandle {
    stop: Arc<AtomicBool>,
    join: thread::JoinHandle<()>,
}

#[cfg(target_os = "linux")]
fn resolve_network_allowlist(entries: &[String]) -> Result<LinuxNetworkPolicy, SandboxError> {
    let mut allowed_addrs = HashSet::new();

    for entry in entries {
        let resolved = entry.to_socket_addrs().map_err(|error| {
            SandboxError::LaunchFailed(format!("invalid allow_net entry `{entry}`: {error}"))
        })?;

        let mut had_any = false;
        for addr in resolved {
            had_any = true;
            allowed_addrs.insert(addr);
        }

        if !had_any {
            return Err(SandboxError::LaunchFailed(format!(
                "invalid allow_net entry `{entry}`: no socket addresses resolved"
            )));
        }
    }

    Ok(LinuxNetworkPolicy { allowed_addrs })
}

#[cfg(target_os = "linux")]
fn spawn_network_supervisor(
    listener_fd: libc::c_int,
    policy: LinuxNetworkPolicy,
) -> Result<NetworkSupervisorHandle, SandboxError> {
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let join = thread::spawn(move || {
        supervise_network_allowlist(listener_fd, policy, worker_stop);
    });

    Ok(NetworkSupervisorHandle { stop, join })
}

#[cfg(target_os = "linux")]
fn supervise_network_allowlist(
    listener_fd: libc::c_int,
    policy: LinuxNetworkPolicy,
    stop: Arc<AtomicBool>,
) {
    let mut pollfd = libc::pollfd {
        fd: listener_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    while !stop.load(Ordering::SeqCst) {
        let rc = unsafe { libc::poll(&mut pollfd, 1, 100) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if rc == 0 {
            continue;
        }
        if pollfd.revents & libc::POLLIN == 0 {
            continue;
        }

        let mut notif = std::mem::MaybeUninit::<libc::seccomp_notif>::zeroed();
        let recv_rc =
            unsafe { libc::ioctl(listener_fd, seccomp_ioctl_notif_recv(), notif.as_mut_ptr()) };
        if recv_rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                break;
            }
            continue;
        }
        let notif = unsafe { notif.assume_init() };

        let mut resp = libc::seccomp_notif_resp {
            id: notif.id,
            val: 0,
            error: 0,
            flags: 0,
        };

        let decision = match notif.data.nr as libc::c_long {
            libc::SYS_socket => allow_socket_syscall(&notif, &policy),
            libc::SYS_bind => allow_bind_syscall(&notif, &policy),
            libc::SYS_connect => allow_destination_syscall(&notif, &policy),
            libc::SYS_sendto => allow_sendto_syscall(&notif, &policy),
            libc::SYS_sendmsg => allow_sendmsg_syscall(&notif, &policy),
            _ => true,
        };

        if decision {
            resp.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;
        } else {
            resp.error = libc::EACCES;
        }

        let send_rc = unsafe {
            libc::ioctl(
                listener_fd,
                seccomp_ioctl_notif_send(),
                &mut resp as *mut libc::seccomp_notif_resp,
            )
        };
        if send_rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
    }

    let _ = close_fd(listener_fd);
}

#[cfg(target_os = "linux")]
fn send_listener_fd(sock_fd: libc::c_int, listener_fd: libc::c_int) -> io::Result<()> {
    let data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let mut control = [0u8; 64];
    let mut msg = libc::msghdr {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: control.len(),
        msg_flags: 0,
    };

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to prepare seccomp listener fd transfer",
            ));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _);
        let data_ptr = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
        *data_ptr = listener_fd;
        msg.msg_controllen = (*cmsg).cmsg_len;

        let rc = libc::sendmsg(sock_fd, &msg, 0);
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn receive_listener_fd(sock: &std::os::unix::net::UnixStream) -> Result<libc::c_int, SandboxError> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut libc::c_void,
        iov_len: byte.len(),
    };
    let mut control = [0u8; 64];
    let mut msg = libc::msghdr {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: control.len(),
        msg_flags: 0,
    };

    let rc = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
    if rc < 0 {
        return Err(SandboxError::LaunchFailed(format!(
            "failed to receive seccomp listener fd: {}",
            io::Error::last_os_error()
        )));
    }

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;
                return Ok(*data_ptr);
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Err(SandboxError::LaunchFailed(
        "seccomp listener fd transfer did not include SCM_RIGHTS".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn close_fd(fd: libc::c_int) -> io::Result<()> {
    let rc = unsafe { libc::close(fd) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn seccomp_ioctl_notif_recv() -> libc::c_ulong {
    seccomp_iowr(
        0,
        std::mem::size_of::<libc::seccomp_notif>() as libc::c_ulong,
    )
}

#[cfg(target_os = "linux")]
fn seccomp_ioctl_notif_send() -> libc::c_ulong {
    seccomp_iowr(
        1,
        std::mem::size_of::<libc::seccomp_notif_resp>() as libc::c_ulong,
    )
}

#[cfg(target_os = "linux")]
fn seccomp_iowr(nr: libc::c_ulong, size: libc::c_ulong) -> libc::c_ulong {
    const IOC_NRBITS: libc::c_ulong = 8;
    const IOC_TYPEBITS: libc::c_ulong = 8;
    const IOC_SIZEBITS: libc::c_ulong = 14;
    const IOC_NRSHIFT: libc::c_ulong = 0;
    const IOC_TYPESHIFT: libc::c_ulong = IOC_NRSHIFT + IOC_NRBITS;
    const IOC_SIZESHIFT: libc::c_ulong = IOC_TYPESHIFT + IOC_TYPEBITS;
    const IOC_DIRSHIFT: libc::c_ulong = IOC_SIZESHIFT + IOC_SIZEBITS;
    const IOC_WRITE: libc::c_ulong = 1;
    const IOC_READ: libc::c_ulong = 2;

    (IOC_READ | IOC_WRITE) << IOC_DIRSHIFT
        | (b'!' as libc::c_ulong) << IOC_TYPESHIFT
        | nr << IOC_NRSHIFT
        | size << IOC_SIZESHIFT
}

#[cfg(target_os = "linux")]
fn allow_socket_syscall(notif: &libc::seccomp_notif, _policy: &LinuxNetworkPolicy) -> bool {
    let domain = notif.data.args[0] as libc::c_int;
    let ty = notif.data.args[1] as libc::c_int;

    socket_params_allowed(domain, ty)
}

#[cfg(target_os = "linux")]
fn allow_bind_syscall(notif: &libc::seccomp_notif, _policy: &LinuxNetworkPolicy) -> bool {
    match sockaddr_from_notif(notif) {
        Some(addr) => network_addr_is_loopback(addr),
        None => true,
    }
}

#[cfg(target_os = "linux")]
fn allow_destination_syscall(notif: &libc::seccomp_notif, policy: &LinuxNetworkPolicy) -> bool {
    match sockaddr_from_notif(notif) {
        Some(addr) => network_addr_allowed(policy, addr),
        None => true,
    }
}

#[cfg(target_os = "linux")]
fn allow_sendto_syscall(notif: &libc::seccomp_notif, policy: &LinuxNetworkPolicy) -> bool {
    let dest = notif.data.args[4] as *const libc::sockaddr;
    if dest.is_null() {
        return true;
    }
    sockaddr_from_ptr(notif.pid, dest, notif.data.args[5] as usize)
        .map(|addr| network_addr_allowed(policy, addr))
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn allow_sendmsg_syscall(notif: &libc::seccomp_notif, policy: &LinuxNetworkPolicy) -> bool {
    let msg_ptr = notif.data.args[1] as *const libc::msghdr;
    if msg_ptr.is_null() {
        return true;
    }

    let msg = match read_remote_value::<libc::msghdr>(notif.pid, msg_ptr) {
        Ok(msg) => msg,
        Err(_) => return false,
    };

    if msg.msg_name.is_null() || msg.msg_namelen == 0 {
        return true;
    }

    sockaddr_from_ptr(
        notif.pid,
        msg.msg_name as *const libc::sockaddr,
        msg.msg_namelen as usize,
    )
    .map(|addr| network_addr_allowed(policy, addr))
    .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn sockaddr_from_notif(notif: &libc::seccomp_notif) -> Option<SocketAddr> {
    let addr_ptr = notif.data.args[1] as *const libc::sockaddr;
    let len = notif.data.args[2] as usize;
    sockaddr_from_ptr(notif.pid, addr_ptr, len)
}

#[cfg(target_os = "linux")]
fn sockaddr_from_ptr(
    pid: libc::pid_t,
    addr_ptr: *const libc::sockaddr,
    len: usize,
) -> Option<SocketAddr> {
    if addr_ptr.is_null() || len < std::mem::size_of::<libc::sa_family_t>() {
        return None;
    }

    let family =
        read_remote_value::<libc::sa_family_t>(pid, addr_ptr as *const libc::sa_family_t).ok()?;
    match family as libc::c_int {
        libc::AF_INET => {
            if len < std::mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            let addr =
                read_remote_value::<libc::sockaddr_in>(pid, addr_ptr as *const libc::sockaddr_in)
                    .ok()?;
            let octets = addr.sin_addr.s_addr.to_be_bytes();
            Some(SocketAddr::from((
                std::net::Ipv4Addr::from(octets),
                u16::from_be(addr.sin_port),
            )))
        }
        libc::AF_INET6 => {
            if len < std::mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            let addr =
                read_remote_value::<libc::sockaddr_in6>(pid, addr_ptr as *const libc::sockaddr_in6)
                    .ok()?;
            Some(SocketAddr::from((
                std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
            )))
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn read_remote_value<T: Copy>(pid: libc::pid_t, remote: *const T) -> io::Result<T> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    let local_iov = libc::iovec {
        iov_base: value.as_mut_ptr() as *mut libc::c_void,
        iov_len: std::mem::size_of::<T>(),
    };
    let remote_iov = libc::iovec {
        iov_base: remote as *mut libc::c_void,
        iov_len: std::mem::size_of::<T>(),
    };
    let rc = unsafe {
        libc::process_vm_readv(
            pid,
            &local_iov as *const libc::iovec,
            1,
            &remote_iov as *const libc::iovec,
            1,
            0,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { value.assume_init() })
}

#[cfg(target_os = "linux")]
fn socket_params_allowed(domain: libc::c_int, ty: libc::c_int) -> bool {
    matches!(domain, libc::AF_UNIX | libc::AF_INET | libc::AF_INET6) && (ty & libc::SOCK_RAW) == 0
}

#[cfg(target_os = "linux")]
fn network_addr_allowed(policy: &LinuxNetworkPolicy, addr: SocketAddr) -> bool {
    policy.allowed_addrs.contains(&addr) || network_addr_is_loopback(addr)
}

#[cfg(target_os = "linux")]
fn network_addr_is_loopback(addr: SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(addr) => addr.ip().is_loopback(),
        SocketAddr::V6(addr) => addr.ip().is_loopback(),
    }
}

#[cfg(target_os = "linux")]
fn write_text(path: &Path, contents: &str) -> io::Result<()> {
    fs::write(path, contents)
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
    reserved: u32,
}

#[cfg(target_os = "linux")]
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(test)]
mod tests {
    use super::*;
    use microbox_policy::{resolve_policy, IsolationLevel, PolicyOverrides};
    use std::path::PathBuf;

    #[test]
    fn auto_backend_is_available() {
        let backend = default_backend();
        assert!(!backend.name().is_empty());
    }

    #[test]
    fn compat_backend_reports_expected_capabilities() {
        let backend = CompatBackend;
        let caps = backend.capabilities();
        assert!(!caps.secure_enforcement);
        assert!(caps.name.contains("compat"));
    }

    #[test]
    fn secure_preference_fails_off_linux() {
        if cfg!(target_os = "linux") {
            return;
        }

        match select_backend(BackendPreference::Secure) {
            Ok(_) => panic!("expected secure backend selection to fail off Linux"),
            Err(err) => assert!(err.to_string().contains("Linux")),
        }
    }

    #[test]
    fn request_can_be_run_through_policy() {
        let policy = resolve_policy(
            &PathBuf::from("."),
            None,
            None,
            PolicyOverrides {
                level: Some(microbox_policy::IsolationLevel::Safe),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(policy.level, IsolationLevel::Safe);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn network_allowlist_resolves_socket_addresses() {
        let policy =
            resolve_network_allowlist(&["127.0.0.1:8080".to_string(), "[::1]:9090".to_string()])
                .unwrap();

        assert!(policy
            .allowed_addrs
            .contains(&"127.0.0.1:8080".parse().unwrap()));
        assert!(policy
            .allowed_addrs
            .contains(&"[::1]:9090".parse().unwrap()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn network_allowlist_rejects_invalid_entries() {
        let err = resolve_network_allowlist(&["127.0.0.1:notaport".to_string()]).unwrap_err();
        assert!(err.to_string().contains("invalid allow_net entry"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_policy_rejects_raw_sockets() {
        assert!(socket_params_allowed(libc::AF_INET, libc::SOCK_STREAM));
        assert!(!socket_params_allowed(libc::AF_INET, libc::SOCK_RAW));
        assert!(!socket_params_allowed(12345, libc::SOCK_STREAM));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn address_policy_allows_loopback_and_explicit_entries() {
        let policy = LinuxNetworkPolicy {
            allowed_addrs: ["10.0.0.1:443".parse().unwrap()].into_iter().collect(),
        };

        assert!(network_addr_allowed(
            &policy,
            "10.0.0.1:443".parse().unwrap()
        ));
        assert!(network_addr_allowed(
            &policy,
            "127.0.0.1:443".parse().unwrap()
        ));
        assert!(!network_addr_allowed(
            &policy,
            "10.0.0.2:443".parse().unwrap()
        ));
    }
}
