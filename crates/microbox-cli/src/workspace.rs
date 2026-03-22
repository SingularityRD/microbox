use crate::{
    args::{
        WorkspaceArgs, WorkspaceCommand, WorkspaceFormat, WorkspaceInitArgs, WorkspaceListArgs,
        WorkspaceRestoreArgs, WorkspaceRunArgs, WorkspaceSnapshotArgs,
    },
    runner::execute_run,
};
use microbox_core::{CommandPlan, ExecutionResult, SandboxError};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSnapshotRecord {
    pub name: String,
    pub created_at_unix: u64,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceRecord {
    pub id: String,
    pub name: String,
    pub source: Option<PathBuf>,
    pub root: PathBuf,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub snapshots: Vec<WorkspaceSnapshotRecord>,
}

#[derive(Debug, Serialize)]
struct WorkspaceListReport {
    home: PathBuf,
    workspaces: Vec<WorkspaceRecord>,
}

#[derive(Debug, Serialize)]
struct WorkspaceActionReport {
    workspace: WorkspaceRecord,
    action: String,
    note: String,
}

#[derive(Debug, Serialize)]
struct WorkspaceRunReport {
    workspace: WorkspaceRecord,
    command: String,
    exit_code: i32,
    timed_out: bool,
    duration_ms: u128,
    stdout: String,
    stderr: String,
    run_record: PathBuf,
}

pub fn run(args: WorkspaceArgs) -> Result<i32, SandboxError> {
    let home = workspace_home(args.home);
    let store = WorkspaceStore::new(home);

    match args.command {
        WorkspaceCommand::Init(inner) => run_init(&store, inner),
        WorkspaceCommand::List(inner) => run_list(&store, inner),
        WorkspaceCommand::Run(inner) => run_workspace_command(&store, inner),
        WorkspaceCommand::Snapshot(inner) => run_snapshot(&store, inner),
        WorkspaceCommand::Restore(inner) => run_restore(&store, inner),
    }
}

fn run_init(store: &WorkspaceStore, args: WorkspaceInitArgs) -> Result<i32, SandboxError> {
    let source = args
        .source
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let workspace = store.create(&args.name, &source)?;
    let rendered = match args.format {
        WorkspaceFormat::Text => {
            render_workspace_record(&workspace, "initialized", "source imported")
        }
        WorkspaceFormat::Json => serde_json::to_string_pretty(&WorkspaceActionReport {
            workspace: workspace.clone(),
            action: "initialized".to_string(),
            note: "source imported".to_string(),
        })
        .map_err(|error| SandboxError::LaunchFailed(error.to_string()))?,
    };

    println!("{rendered}");
    Ok(0)
}

fn run_list(store: &WorkspaceStore, args: WorkspaceListArgs) -> Result<i32, SandboxError> {
    let report = WorkspaceListReport {
        home: store.home.clone(),
        workspaces: store.list()?,
    };

    let rendered = match args.format {
        WorkspaceFormat::Text => render_workspace_list(&report),
        WorkspaceFormat::Json => serde_json::to_string_pretty(&report)
            .map_err(|error| SandboxError::LaunchFailed(error.to_string()))?,
    };

    println!("{rendered}");
    Ok(0)
}

fn run_workspace_command(
    store: &WorkspaceStore,
    args: WorkspaceRunArgs,
) -> Result<i32, SandboxError> {
    let workspace = store.get(&args.name)?;
    let run_args = crate::args::RunArgs {
        policy: args.policy.clone(),
        command: args.command.clone(),
    };
    let command = CommandPlan::from_raw(run_args.command.clone())?;
    let execution = execute_run(run_args, workspace.root.clone())?;
    let run_record = store.record_run(&workspace, &command.display(), &execution)?;
    let refreshed_workspace = store.get(&workspace.id)?;

    let report = WorkspaceRunReport {
        workspace: refreshed_workspace,
        command: command.display(),
        exit_code: execution.exit_code(),
        timed_out: execution.timed_out,
        duration_ms: execution.duration.as_millis(),
        stdout: execution.stdout.clone(),
        stderr: execution.stderr.clone(),
        run_record,
    };

    match args.format {
        WorkspaceFormat::Text => {
            if !execution.stdout.is_empty() {
                print!("{}", execution.stdout);
            }
            if !execution.stderr.is_empty() {
                eprint!("{}", execution.stderr);
            }
            println!(
                "\nworkspace = {}\ncommand = {}\nexit_code = {}\nduration_ms = {}\ntimed_out = {}",
                report.workspace.name,
                report.command,
                report.exit_code,
                report.duration_ms,
                report.timed_out
            );
        }
        WorkspaceFormat::Json => {
            let rendered = serde_json::to_string_pretty(&report)
                .map_err(|error| SandboxError::LaunchFailed(error.to_string()))?;
            println!("{rendered}");
        }
    }

    Ok(report.exit_code)
}

fn run_snapshot(store: &WorkspaceStore, args: WorkspaceSnapshotArgs) -> Result<i32, SandboxError> {
    let workspace = store.get(&args.name)?;
    let updated = store.snapshot(&workspace.id, &args.snapshot)?;
    let note = format!("snapshot {} created", args.snapshot);
    let rendered = match args.format {
        WorkspaceFormat::Text => render_workspace_record(&updated, "snapshot", &note),
        WorkspaceFormat::Json => serde_json::to_string_pretty(&WorkspaceActionReport {
            workspace: updated.clone(),
            action: "snapshot".to_string(),
            note,
        })
        .map_err(|error| SandboxError::LaunchFailed(error.to_string()))?,
    };

    println!("{rendered}");
    Ok(0)
}

fn run_restore(store: &WorkspaceStore, args: WorkspaceRestoreArgs) -> Result<i32, SandboxError> {
    let workspace = store.get(&args.name)?;
    let updated = store.restore(&workspace.id, &args.snapshot)?;
    let note = format!("snapshot {} restored", args.snapshot);
    let rendered = match args.format {
        WorkspaceFormat::Text => render_workspace_record(&updated, "restore", &note),
        WorkspaceFormat::Json => serde_json::to_string_pretty(&WorkspaceActionReport {
            workspace: updated.clone(),
            action: "restore".to_string(),
            note,
        })
        .map_err(|error| SandboxError::LaunchFailed(error.to_string()))?,
    };

    println!("{rendered}");
    Ok(0)
}

fn render_workspace_record(workspace: &WorkspaceRecord, action: &str, note: &str) -> String {
    let mut lines = vec![
        format!("MicroBox workspace {action}"),
        format!("id = {}", workspace.id),
        format!("name = {}", workspace.name),
        format!("root = {}", workspace.root.display()),
        format!(
            "source = {}",
            workspace
                .source
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "-".to_string())
        ),
        format!("created_at_unix = {}", workspace.created_at_unix),
        format!("updated_at_unix = {}", workspace.updated_at_unix),
        format!("snapshot_count = {}", workspace.snapshots.len()),
        format!("note = {}", note),
    ];

    if !workspace.snapshots.is_empty() {
        lines.push("snapshots:".to_string());
        for snapshot in &workspace.snapshots {
            lines.push(format!(
                "  - {} @ {}",
                snapshot.name,
                snapshot.path.display()
            ));
        }
    }

    lines.join("\n")
}

fn render_workspace_list(report: &WorkspaceListReport) -> String {
    let mut lines = vec![
        format!("MicroBox workspaces"),
        format!("home = {}", report.home.display()),
    ];

    if report.workspaces.is_empty() {
        lines.push("no workspaces found".to_string());
        return lines.join("\n");
    }

    for workspace in &report.workspaces {
        lines.push(format!(
            "- {} ({}) snapshots={} root={}",
            workspace.name,
            workspace.id,
            workspace.snapshots.len(),
            workspace.root.display()
        ));
    }

    lines.join("\n")
}

#[derive(Clone)]
struct WorkspaceStore {
    home: PathBuf,
}

impl WorkspaceStore {
    fn new(home: PathBuf) -> Self {
        Self { home }
    }

    fn workspaces_dir(&self) -> PathBuf {
        self.home.join("workspaces")
    }

    fn workspace_dir(&self, id: &str) -> PathBuf {
        self.workspaces_dir().join(id)
    }

    fn workspace_root(&self, id: &str) -> PathBuf {
        self.workspace_dir(id).join("root")
    }

    fn snapshots_dir(&self, id: &str) -> PathBuf {
        self.workspace_dir(id).join("snapshots")
    }

    fn runs_dir(&self, id: &str) -> PathBuf {
        self.workspace_dir(id).join("runs")
    }

    fn metadata_path(&self, id: &str) -> PathBuf {
        self.workspace_dir(id).join("workspace.json")
    }

    fn create(&self, name: &str, source: &Path) -> Result<WorkspaceRecord, SandboxError> {
        if !source.exists() {
            return Err(SandboxError::Io(format!(
                "source directory does not exist: {}",
                source.display()
            )));
        }

        if self.list()?.iter().any(|workspace| workspace.name == name) {
            return Err(SandboxError::Policy(format!(
                "workspace name already exists: {name}"
            )));
        }

        let id = format!("{}-{}", slugify(name), timestamp());
        let dir = self.workspace_dir(&id);
        let root = self.workspace_root(&id);
        let snapshots_dir = self.snapshots_dir(&id);
        let runs_dir = self.runs_dir(&id);

        fs::create_dir_all(&root).map_err(|error| SandboxError::Io(error.to_string()))?;
        fs::create_dir_all(&snapshots_dir).map_err(|error| SandboxError::Io(error.to_string()))?;
        fs::create_dir_all(&runs_dir).map_err(|error| SandboxError::Io(error.to_string()))?;
        copy_dir_contents(source, &root)?;

        let now = timestamp();
        let workspace = WorkspaceRecord {
            id,
            name: name.to_string(),
            source: Some(canonicalize_or_self(source)),
            root,
            created_at_unix: now,
            updated_at_unix: now,
            snapshots: Vec::new(),
        };
        self.save(&workspace)?;
        fs::create_dir_all(&dir).map_err(|error| SandboxError::Io(error.to_string()))?;
        Ok(workspace)
    }

    fn list(&self) -> Result<Vec<WorkspaceRecord>, SandboxError> {
        let mut workspaces = Vec::new();
        let dir = self.workspaces_dir();
        if !dir.exists() {
            return Ok(workspaces);
        }

        for entry in fs::read_dir(&dir).map_err(|error| SandboxError::Io(error.to_string()))? {
            let entry = entry.map_err(|error| SandboxError::Io(error.to_string()))?;
            if !entry.path().is_dir() {
                continue;
            }

            if let Ok(workspace) = self.load(entry.path()) {
                workspaces.push(workspace);
            }
        }

        workspaces.sort_by(|left, right| left.created_at_unix.cmp(&right.created_at_unix));
        Ok(workspaces)
    }

    fn get(&self, name_or_id: &str) -> Result<WorkspaceRecord, SandboxError> {
        let matches: Vec<_> = self
            .list()?
            .into_iter()
            .filter(|workspace| workspace.id == name_or_id || workspace.name == name_or_id)
            .collect();

        match matches.as_slice() {
            [workspace] => Ok(workspace.clone()),
            [] => Err(SandboxError::Policy(format!(
                "workspace not found: {name_or_id}"
            ))),
            _ => Err(SandboxError::Policy(format!(
                "workspace name is ambiguous: {name_or_id}"
            ))),
        }
    }

    fn snapshot(
        &self,
        workspace_id: &str,
        snapshot_name: &str,
    ) -> Result<WorkspaceRecord, SandboxError> {
        let mut workspace = self.load(self.workspace_dir(workspace_id))?;
        if workspace
            .snapshots
            .iter()
            .any(|snapshot| snapshot.name == snapshot_name)
        {
            return Err(SandboxError::Policy(format!(
                "snapshot already exists: {snapshot_name}"
            )));
        }

        let snapshot_path = self.snapshots_dir(workspace_id).join(format!(
            "{}-{}",
            slugify(snapshot_name),
            timestamp()
        ));
        fs::create_dir_all(&snapshot_path).map_err(|error| SandboxError::Io(error.to_string()))?;
        copy_dir_contents(&workspace.root, &snapshot_path)?;
        workspace.snapshots.push(WorkspaceSnapshotRecord {
            name: snapshot_name.to_string(),
            created_at_unix: timestamp(),
            path: snapshot_path,
        });
        workspace.updated_at_unix = timestamp();
        self.save(&workspace)?;
        Ok(workspace)
    }

    fn restore(
        &self,
        workspace_id: &str,
        snapshot_name: &str,
    ) -> Result<WorkspaceRecord, SandboxError> {
        let mut workspace = self.load(self.workspace_dir(workspace_id))?;
        let snapshot = workspace
            .snapshots
            .iter()
            .find(|snapshot| snapshot.name == snapshot_name)
            .cloned()
            .ok_or_else(|| SandboxError::Policy(format!("snapshot not found: {snapshot_name}")))?;

        clear_dir(&workspace.root)?;
        copy_dir_contents(&snapshot.path, &workspace.root)?;
        workspace.updated_at_unix = timestamp();
        self.save(&workspace)?;
        Ok(workspace)
    }

    fn record_run(
        &self,
        workspace: &WorkspaceRecord,
        command: &str,
        execution: &ExecutionResult,
    ) -> Result<PathBuf, SandboxError> {
        let runs_dir = self.runs_dir(&workspace.id);
        fs::create_dir_all(&runs_dir).map_err(|error| SandboxError::Io(error.to_string()))?;
        let run_id = format!("run-{}", timestamp());
        let path = runs_dir.join(format!("{run_id}.json"));
        let record = serde_json::json!({
            "workspace_id": workspace.id,
            "workspace_name": workspace.name,
            "command": command,
            "exit_code": execution.exit_code(),
            "timed_out": execution.timed_out,
            "duration_ms": execution.duration.as_millis(),
            "stdout": execution.stdout,
            "stderr": execution.stderr,
            "created_at_unix": timestamp(),
        });
        let rendered = serde_json::to_string_pretty(&record)
            .map_err(|error| SandboxError::LaunchFailed(error.to_string()))?;
        fs::write(&path, rendered).map_err(|error| SandboxError::Io(error.to_string()))?;
        Ok(path)
    }

    fn save(&self, workspace: &WorkspaceRecord) -> Result<(), SandboxError> {
        let dir = self.workspace_dir(&workspace.id);
        fs::create_dir_all(&dir).map_err(|error| SandboxError::Io(error.to_string()))?;
        let rendered = serde_json::to_string_pretty(workspace)
            .map_err(|error| SandboxError::LaunchFailed(error.to_string()))?;
        fs::write(self.metadata_path(&workspace.id), rendered)
            .map_err(|error| SandboxError::Io(error.to_string()))
    }

    fn load(&self, dir: PathBuf) -> Result<WorkspaceRecord, SandboxError> {
        let path = dir.join("workspace.json");
        let raw = fs::read_to_string(&path).map_err(|error| SandboxError::Io(error.to_string()))?;
        serde_json::from_str(&raw).map_err(|error| SandboxError::LaunchFailed(error.to_string()))
    }
}

fn workspace_home(home: Option<PathBuf>) -> PathBuf {
    home.unwrap_or_else(default_home)
}

fn default_home() -> PathBuf {
    if let Ok(path) = env::var("MICROBOX_HOME") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }

    if let Ok(home) = env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home).join(".microbox");
        }
    }

    if let Ok(profile) = env::var("USERPROFILE") {
        if !profile.trim().is_empty() {
            return PathBuf::from(profile).join(".microbox");
        }
    }

    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".microbox")
}

fn canonicalize_or_self(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn slugify(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut previous_dash = false;

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash {
            output.push('-');
            previous_dash = true;
        }
    }

    output.trim_matches('-').to_string()
}

fn copy_dir_contents(source: &Path, destination: &Path) -> Result<(), SandboxError> {
    fs::create_dir_all(destination).map_err(|error| SandboxError::Io(error.to_string()))?;
    for entry in fs::read_dir(source).map_err(|error| SandboxError::Io(error.to_string()))? {
        let entry = entry.map_err(|error| SandboxError::Io(error.to_string()))?;
        let file_name = entry.file_name();
        if matches!(file_name.to_str(), Some(".microbox" | ".git" | "target")) {
            continue;
        }

        let source_path = entry.path();
        let destination_path = destination.join(&file_name);
        let file_type = entry
            .file_type()
            .map_err(|error| SandboxError::Io(error.to_string()))?;

        if file_type.is_dir() {
            copy_dir_contents(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).map_err(|error| SandboxError::Io(error.to_string()))?;
            }
            fs::copy(&source_path, &destination_path)
                .map_err(|error| SandboxError::Io(error.to_string()))?;
        }
    }

    Ok(())
}

fn clear_dir(path: &Path) -> Result<(), SandboxError> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|error| SandboxError::Io(error.to_string()))?;
        return Ok(());
    }

    for entry in fs::read_dir(path).map_err(|error| SandboxError::Io(error.to_string()))? {
        let entry = entry.map_err(|error| SandboxError::Io(error.to_string()))?;
        let entry_path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| SandboxError::Io(error.to_string()))?;

        if file_type.is_dir() {
            fs::remove_dir_all(&entry_path).map_err(|error| SandboxError::Io(error.to_string()))?;
        } else {
            fs::remove_file(&entry_path).map_err(|error| SandboxError::Io(error.to_string()))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn slugify_normalizes_names() {
        assert_eq!(slugify("Demo Workspace!"), "demo-workspace");
        assert_eq!(slugify("  A__B  "), "a-b");
    }

    #[test]
    fn workspace_lifecycle_roundtrip() {
        let base = env::temp_dir().join(format!("microbox-workspace-test-{}", timestamp()));
        let source = base.join("source");
        let home = base.join("home");
        let root_file = source.join("hello.txt");

        fs::create_dir_all(&source).unwrap();
        fs::write(&root_file, "hello from source").unwrap();

        let store = WorkspaceStore::new(home);
        let workspace = store.create("demo", &source).unwrap();
        assert!(workspace.root.join("hello.txt").exists());

        fs::write(workspace.root.join("hello.txt"), "mutated").unwrap();
        let workspace = store.snapshot(&workspace.id, "snap1").unwrap();
        fs::write(workspace.root.join("hello.txt"), "changed again").unwrap();
        let workspace = store.restore(&workspace.id, "snap1").unwrap();

        let restored = fs::read_to_string(workspace.root.join("hello.txt")).unwrap();
        assert_eq!(restored, "mutated");
        assert_eq!(workspace.snapshots.len(), 1);
        assert_eq!(workspace.snapshots[0].name, "snap1");
    }
}
