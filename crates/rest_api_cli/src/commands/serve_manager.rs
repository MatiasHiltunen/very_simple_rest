use std::env;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use chrono::Utc;
use dialoguer::Confirm;
use rest_macro_core::compiler::{self, default_service_database_url};
use rest_macro_core::database::{
    DatabaseEngine, resolve_database_config, resolve_database_url,
    service_base_dir_from_config_path,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_TIMEOUT,
};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};

const MANAGED_INSTANCE_ID_ENV: &str = "VSR_MANAGED_INSTANCE_ID";
const MANAGED_INSTANCE_MODE_ENV: &str = "VSR_MANAGED_INSTANCE_MODE";
const MANAGED_MODE_BACKGROUND: &str = "background";
const MANAGED_MODE_FOREGROUND: &str = "foreground";
const MANAGED_PARENT_WATCH_DISABLED_ENV: &str = "VSR_MANAGED_DISABLE_PARENT_WATCH";
const PROCESS_SYNCHRONIZE_RIGHT: u32 = 0x0010_0000;
#[cfg(windows)]
const DETACHED_PROCESS_FLAG: u32 = 0x0000_0008;
#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP_FLAG: u32 = 0x0000_0200;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServeInstanceMode {
    Foreground,
    Background,
}

impl ServeInstanceMode {
    fn as_env_value(self) -> &'static str {
        match self {
            Self::Foreground => MANAGED_MODE_FOREGROUND,
            Self::Background => MANAGED_MODE_BACKGROUND,
        }
    }

    fn as_label(self) -> &'static str {
        match self {
            Self::Foreground => "foreground",
            Self::Background => "background",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServeInstanceContext {
    pub id: String,
    pub mode: ServeInstanceMode,
}

impl ServeInstanceContext {
    pub fn should_watch_parent(&self) -> bool {
        self.mode == ServeInstanceMode::Foreground
            && env::var_os(MANAGED_PARENT_WATCH_DISABLED_ENV).is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServeCommandFlavor {
    TopLevel,
    GeneratedServer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ServeInstanceState {
    Starting,
    Running,
}

impl ServeInstanceState {
    fn as_label(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServeInstanceRecord {
    pub id: String,
    pub pid: u32,
    pub mode: ServeInstanceMode,
    state: ServeInstanceState,
    pub module_name: String,
    pub input_path: String,
    pub working_dir: String,
    pub bind_addr: String,
    pub scheme: String,
    pub include_builtin_auth: bool,
    pub started_at: String,
    pub stdout_log: Option<String>,
    pub stderr_log: Option<String>,
}

impl ServeInstanceRecord {
    fn matches_input(&self, input: &Path) -> bool {
        self.input_path == canonicalize_path_for_match(input).display().to_string()
    }
}

#[derive(Default, Serialize, Deserialize)]
struct ServeInstanceRegistry {
    instances: Vec<ServeInstanceRecord>,
}

pub struct BackgroundServeSpawn {
    pub instance_id: String,
    pub pid: u32,
    pub bind_addr: String,
    pub scheme: String,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
}

pub struct ServeStatusReport {
    pub instances: Vec<ServeInstanceRecord>,
    pub pruned_stale: usize,
}

pub struct KillReport {
    pub killed: Vec<ServeInstanceRecord>,
    pub pruned_stale: usize,
}

pub struct ResetReport {
    pub deleted_paths: Vec<PathBuf>,
}

pub fn managed_context_from_env() -> Option<ServeInstanceContext> {
    let id = env::var(MANAGED_INSTANCE_ID_ENV).ok()?;
    let mode = match env::var(MANAGED_INSTANCE_MODE_ENV).ok()?.as_str() {
        MANAGED_MODE_BACKGROUND => ServeInstanceMode::Background,
        _ => ServeInstanceMode::Foreground,
    };
    Some(ServeInstanceContext { id, mode })
}

pub fn new_foreground_context() -> ServeInstanceContext {
    ServeInstanceContext {
        id: Uuid::new_v4().to_string(),
        mode: ServeInstanceMode::Foreground,
    }
}

pub fn register_running_instance(
    context: &ServeInstanceContext,
    input: &Path,
    bind_addr: &str,
    module_name: &str,
    tls_enabled: bool,
    include_builtin_auth: bool,
) -> anyhow::Result<()> {
    let (stdout_log, stderr_log) = if context.mode == ServeInstanceMode::Background {
        let logs = background_log_paths(&context.id)?;
        (
            Some(logs.stdout.display().to_string()),
            Some(logs.stderr.display().to_string()),
        )
    } else {
        (None, None)
    };
    upsert_instance(ServeInstanceRecord {
        id: context.id.clone(),
        pid: std::process::id(),
        mode: context.mode,
        state: ServeInstanceState::Running,
        module_name: module_name.to_owned(),
        input_path: canonicalize_path_for_match(input).display().to_string(),
        working_dir: env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .display()
            .to_string(),
        bind_addr: bind_addr.to_owned(),
        scheme: if tls_enabled {
            "https".to_owned()
        } else {
            "http".to_owned()
        },
        include_builtin_auth,
        started_at: Utc::now().to_rfc3339(),
        stdout_log,
        stderr_log,
    })
}

pub fn unregister_instance(id: &str) -> anyhow::Result<()> {
    update_registry(|registry| {
        registry.instances.retain(|instance| instance.id != id);
        Ok(())
    })
}

pub fn spawn_background_serve(
    current_exe: &Path,
    input: &Path,
    bind_addr: Option<&str>,
    include_builtin_auth: bool,
    flavor: ServeCommandFlavor,
) -> anyhow::Result<BackgroundServeSpawn> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service config {}", input.display()))?;
    let instance_id = Uuid::new_v4().to_string();
    let log_paths = background_log_paths(&instance_id)?;
    let resolved_bind_addr = bind_addr
        .map(ToOwned::to_owned)
        .or_else(|| env::var("BIND_ADDR").ok())
        .unwrap_or_else(|| default_bind_addr_from_tls(service.tls.is_enabled()).to_owned());
    let mut command = Command::new(current_exe);
    command.current_dir(env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    match flavor {
        ServeCommandFlavor::TopLevel => {
            command.arg("serve").arg(canonicalize_path_for_match(input));
        }
        ServeCommandFlavor::GeneratedServer => {
            command
                .arg("server")
                .arg("serve")
                .arg("--input")
                .arg(canonicalize_path_for_match(input));
        }
    }
    command.arg("--bind-addr").arg(&resolved_bind_addr);
    if !include_builtin_auth {
        command.arg("--without-auth");
    }
    command
        .env(MANAGED_INSTANCE_ID_ENV, &instance_id)
        .env(
            MANAGED_INSTANCE_MODE_ENV,
            ServeInstanceMode::Background.as_env_value(),
        )
        .env(MANAGED_PARENT_WATCH_DISABLED_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            fs::File::create(&log_paths.stdout)
                .with_context(|| format!("failed to create {}", log_paths.stdout.display()))?,
        ))
        .stderr(Stdio::from(
            fs::File::create(&log_paths.stderr)
                .with_context(|| format!("failed to create {}", log_paths.stderr.display()))?,
        ));
    #[cfg(windows)]
    {
        clear_standard_handle_inheritance()?;
        command.creation_flags(DETACHED_PROCESS_FLAG | CREATE_NEW_PROCESS_GROUP_FLAG);
    }

    let child_pid = spawn_background_process(&mut command).with_context(|| {
        format!(
            "failed to start background `vsr serve` for {}",
            input.display()
        )
    })?;

    let starting = ServeInstanceRecord {
        id: instance_id.clone(),
        pid: child_pid,
        mode: ServeInstanceMode::Background,
        state: ServeInstanceState::Starting,
        module_name: service.module_ident.to_string(),
        input_path: canonicalize_path_for_match(input).display().to_string(),
        working_dir: env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .display()
            .to_string(),
        bind_addr: resolved_bind_addr.clone(),
        scheme: if service.tls.is_enabled() {
            "https".to_owned()
        } else {
            "http".to_owned()
        },
        include_builtin_auth,
        started_at: Utc::now().to_rfc3339(),
        stdout_log: Some(log_paths.stdout.display().to_string()),
        stderr_log: Some(log_paths.stderr.display().to_string()),
    };
    upsert_instance(starting)?;

    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if !process_is_running(child_pid).context("failed to poll background serve child")? {
            let _ = unregister_instance(&instance_id);
            bail!(
                "background serve exited before becoming ready. Logs:\n- {}\n- {}",
                log_paths.stdout.display(),
                log_paths.stderr.display()
            );
        }

        if let Some(instance) = load_registry()?
            .instances
            .into_iter()
            .find(|instance| instance.id == instance_id)
            && instance.state == ServeInstanceState::Running
        {
            break;
        }

        thread::sleep(Duration::from_millis(150));
    }

    Ok(BackgroundServeSpawn {
        instance_id,
        pid: child_pid,
        bind_addr: resolved_bind_addr,
        scheme: if service.tls.is_enabled() {
            "https".to_owned()
        } else {
            "http".to_owned()
        },
        stdout_log: log_paths.stdout,
        stderr_log: log_paths.stderr,
    })
}

pub fn status_instances(input: Option<&Path>, all: bool) -> anyhow::Result<ServeStatusReport> {
    let mut registry = load_registry()?;
    let pruned_stale = prune_stale_instances(&mut registry)?;
    let instances = filtered_instances(&registry.instances, input, all);
    save_registry(&registry)?;
    Ok(ServeStatusReport {
        instances,
        pruned_stale,
    })
}

pub fn print_status(report: &ServeStatusReport) {
    if report.instances.is_empty() {
        if report.pruned_stale > 0 {
            println!(
                "No tracked serve instances. Pruned {} stale registry entr{}.",
                report.pruned_stale,
                if report.pruned_stale == 1 { "y" } else { "ies" }
            );
        } else {
            println!("No tracked serve instances.");
        }
        return;
    }

    for instance in &report.instances {
        println!(
            "[{}] {} pid={} {}://{} ({})",
            instance.mode.as_label(),
            instance.module_name,
            instance.pid,
            instance.scheme,
            instance.bind_addr,
            instance.state.as_label()
        );
        println!("  id: {}", instance.id);
        println!("  input: {}", instance.input_path);
        println!("  started: {}", instance.started_at);
        if let Some(stdout_log) = &instance.stdout_log {
            println!("  stdout: {}", stdout_log);
        }
        if let Some(stderr_log) = &instance.stderr_log {
            println!("  stderr: {}", stderr_log);
        }
    }

    if report.pruned_stale > 0 {
        println!(
            "Pruned {} stale registry entr{}.",
            report.pruned_stale,
            if report.pruned_stale == 1 { "y" } else { "ies" }
        );
    }
}

pub fn kill_instances(
    input: Option<&Path>,
    id: Option<&str>,
    all: bool,
    force: bool,
) -> anyhow::Result<KillReport> {
    let mut registry = load_registry()?;
    let pruned_stale = prune_stale_instances(&mut registry)?;
    let matches = filtered_instances_by_selector(&registry.instances, input, id, all)?;

    if matches.is_empty() {
        bail!("No tracked serve instances matched the requested target");
    }

    let mut killed = Vec::new();
    for instance in &matches {
        terminate_process(instance.pid, force).with_context(|| {
            format!(
                "failed to stop serve instance {} (pid {})",
                instance.id, instance.pid
            )
        })?;
        wait_for_process_exit(instance.pid, Duration::from_secs(5)).with_context(|| {
            format!(
                "serve instance {} (pid {}) did not stop in time; try again with --force",
                instance.id, instance.pid
            )
        })?;
        killed.push(instance.clone());
    }

    registry
        .instances
        .retain(|instance| !matches.iter().any(|matched| matched.id == instance.id));
    save_registry(&registry)?;

    Ok(KillReport {
        killed,
        pruned_stale,
    })
}

pub fn print_kill_report(report: &KillReport) {
    for instance in &report.killed {
        println!(
            "Stopped {} instance {} (pid {}) for {}",
            instance.mode.as_label(),
            instance.id,
            instance.pid,
            instance.input_path
        );
    }

    if report.pruned_stale > 0 {
        println!(
            "Pruned {} stale registry entr{}.",
            report.pruned_stale,
            if report.pruned_stale == 1 { "y" } else { "ies" }
        );
    }
}

pub fn print_reset_report(report: &ResetReport) {
    if report.deleted_paths.is_empty() {
        return;
    }

    println!(
        "Deleted {} path{}:",
        report.deleted_paths.len(),
        if report.deleted_paths.len() == 1 {
            ""
        } else {
            "s"
        }
    );
    for path in &report.deleted_paths {
        println!("  {}", path.display());
    }
}

pub fn reset_local_state(
    input: &Path,
    accept_permanent_data_loss: bool,
) -> anyhow::Result<ResetReport> {
    let input = canonicalize_path_for_match(input);
    let status = status_instances(Some(&input), false)?;
    if !status.instances.is_empty() {
        let ids = status
            .instances
            .iter()
            .map(|instance| format!("{} (pid {})", instance.id, instance.pid))
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "Refusing to reset while tracked serve instances are still running for {}: {}. Stop them first with `vsr kill --input {}`.",
            input.display(),
            ids,
            input.display()
        );
    }

    let targets = local_reset_targets(&input)?;
    if targets.is_empty() {
        println!("Nothing to reset for {}.", input.display());
        return Ok(ResetReport {
            deleted_paths: Vec::new(),
        });
    }

    println!(
        "This will permanently delete local development data for {}.",
        input.display()
    );
    println!("Suggested backup first:");
    println!(
        "  vsr backup snapshot --input {} --output <backup-dir>",
        input.display()
    );
    println!("Paths queued for deletion:");
    for target in &targets {
        println!("  {}", target.display());
    }

    if !accept_permanent_data_loss {
        let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        if !interactive {
            bail!("reset requires interactive confirmation or --accept-permanent-data-loss");
        }

        let confirmed = Confirm::new()
            .with_prompt(
                "Permanently delete the listed local database and var paths for this service?",
            )
            .default(false)
            .interact()
            .unwrap_or(false);
        if !confirmed {
            bail!("reset cancelled");
        }
    }

    let mut deleted_paths = Vec::new();
    for target in targets {
        if !target.exists() {
            continue;
        }
        if target.is_dir() {
            fs::remove_dir_all(&target)
                .with_context(|| format!("failed to remove directory {}", target.display()))?;
        } else {
            fs::remove_file(&target)
                .with_context(|| format!("failed to remove file {}", target.display()))?;
        }
        deleted_paths.push(target);
    }

    Ok(ResetReport { deleted_paths })
}

fn load_registry() -> anyhow::Result<ServeInstanceRegistry> {
    let path = registry_path()?;
    if !path.exists() {
        return Ok(ServeInstanceRegistry::default());
    }

    let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let registry = serde_json::from_slice::<ServeInstanceRegistry>(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(registry)
}

fn save_registry(registry: &ServeInstanceRegistry) -> anyhow::Result<()> {
    let path = registry_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let temp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        Uuid::new_v4().simple()
    ));
    let encoded = serde_json::to_vec_pretty(registry).context("failed to serialize registry")?;
    fs::write(&temp_path, encoded)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("failed to replace {}", path.display()))?;
    }
    fs::rename(&temp_path, &path)
        .with_context(|| format!("failed to move registry into {}", path.display()))?;
    Ok(())
}

fn update_registry(
    mut update: impl FnMut(&mut ServeInstanceRegistry) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut registry = load_registry()?;
    let _ = prune_stale_instances(&mut registry)?;
    update(&mut registry)?;
    save_registry(&registry)
}

fn upsert_instance(instance: ServeInstanceRecord) -> anyhow::Result<()> {
    update_registry(|registry| {
        if let Some(existing) = registry
            .instances
            .iter_mut()
            .find(|existing| existing.id == instance.id)
        {
            *existing = instance.clone();
        } else {
            registry.instances.push(instance.clone());
        }
        Ok(())
    })
}

fn prune_stale_instances(registry: &mut ServeInstanceRegistry) -> anyhow::Result<usize> {
    let before = registry.instances.len();
    registry
        .instances
        .retain(|instance| process_is_running(instance.pid).unwrap_or(false));
    Ok(before - registry.instances.len())
}

fn filtered_instances(
    instances: &[ServeInstanceRecord],
    input: Option<&Path>,
    all: bool,
) -> Vec<ServeInstanceRecord> {
    if all {
        return instances.to_vec();
    }
    if let Some(input) = input {
        return instances
            .iter()
            .filter(|instance| instance.matches_input(input))
            .cloned()
            .collect();
    }
    instances.to_vec()
}

fn filtered_instances_by_selector(
    instances: &[ServeInstanceRecord],
    input: Option<&Path>,
    id: Option<&str>,
    all: bool,
) -> anyhow::Result<Vec<ServeInstanceRecord>> {
    if let Some(id) = id {
        return Ok(instances
            .iter()
            .filter(|instance| instance.id == id)
            .cloned()
            .collect());
    }

    if all {
        return Ok(instances.to_vec());
    }

    let Some(input) = input else {
        bail!("kill requires --id, --all, or a service input/config to target");
    };
    Ok(instances
        .iter()
        .filter(|instance| instance.matches_input(input))
        .cloned()
        .collect())
}

fn registry_root() -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(path) = env::var_os("LOCALAPPDATA") {
            return Ok(PathBuf::from(path).join("vsr").join("serve"));
        }
        if let Some(path) = env::var_os("APPDATA") {
            return Ok(PathBuf::from(path).join("vsr").join("serve"));
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(path) = env::var_os("XDG_STATE_HOME") {
            return Ok(PathBuf::from(path).join("vsr").join("serve"));
        }
        if let Some(home) = env::var_os("HOME") {
            return Ok(PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("vsr")
                .join("serve"));
        }
    }

    Ok(env::temp_dir().join("vsr").join("serve"))
}

fn registry_path() -> anyhow::Result<PathBuf> {
    Ok(registry_root()?.join("instances.json"))
}

struct BackgroundLogPaths {
    stdout: PathBuf,
    stderr: PathBuf,
}

fn background_log_paths(instance_id: &str) -> anyhow::Result<BackgroundLogPaths> {
    let logs_dir = registry_root()?.join("logs");
    fs::create_dir_all(&logs_dir)
        .with_context(|| format!("failed to create {}", logs_dir.display()))?;
    Ok(BackgroundLogPaths {
        stdout: logs_dir.join(format!("{instance_id}.stdout.log")),
        stderr: logs_dir.join(format!("{instance_id}.stderr.log")),
    })
}

fn default_bind_addr_from_tls(tls_enabled: bool) -> &'static str {
    if tls_enabled {
        "127.0.0.1:8443"
    } else {
        "127.0.0.1:8080"
    }
}

fn canonicalize_path_for_match(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn local_reset_targets(input: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let service = compiler::load_service_from_path(input)
        .map_err(|error| anyhow!(error.to_string()))
        .with_context(|| format!("failed to load service config {}", input.display()))?;
    let base_dir = service_base_dir_from_config_path(input);
    let base_dir = canonicalize_existing_or_logical(&base_dir)?;
    let mut targets = vec![base_dir.join("var")];

    let database_target = match &resolve_database_config(&service.database, &base_dir).engine {
        DatabaseEngine::TursoLocal(engine) => Some(PathBuf::from(&engine.path)),
        DatabaseEngine::Sqlx => sqlite_path_from_database_url(&resolve_database_url(
            &default_service_database_url(&service),
            &base_dir,
        ))?,
    };

    let Some(database_target) = database_target else {
        bail!(
            "reset currently supports only local SQLite/TursoLocal service databases, not external SQL backends"
        );
    };

    if database_target != Path::new(":memory:") {
        let database_target = canonicalize_existing_or_logical(&database_target)?;
        if !path_is_within(&base_dir, &database_target) {
            bail!(
                "reset refuses to delete database files outside the service directory: {}",
                database_target.display()
            );
        }
        targets.push(database_target.clone());
        targets.push(PathBuf::from(format!("{}-wal", database_target.display())));
        targets.push(PathBuf::from(format!("{}-shm", database_target.display())));
        targets.push(PathBuf::from(format!(
            "{}-journal",
            database_target.display()
        )));
    }

    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn sqlite_path_from_database_url(database_url: &str) -> anyhow::Result<Option<PathBuf>> {
    let Some(path) = database_url.strip_prefix("sqlite:") else {
        return Ok(None);
    };
    if path == ":memory:" {
        return Ok(None);
    }
    let path = path.split('?').next().unwrap_or(path);
    Ok(Some(PathBuf::from(path)))
}

fn canonicalize_existing_or_logical(path: &Path) -> anyhow::Result<PathBuf> {
    if path.exists() {
        path.canonicalize()
            .with_context(|| format!("failed to resolve {}", path.display()))
    } else if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path))
    }
}

fn path_is_within(base_dir: &Path, candidate: &Path) -> bool {
    candidate.starts_with(base_dir)
}

fn terminate_process(pid: u32, force: bool) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        if force {
            run_taskkill(pid, true)?;
            return Ok(());
        }

        if let Err(error) = run_taskkill(pid, false) {
            log::warn!(
                "graceful taskkill for pid {} failed: {error}; retrying with /F",
                pid
            );
            run_taskkill(pid, true)?;
        }

        Ok(())
    }

    #[cfg(not(windows))]
    {
        let signal = if force { "-KILL" } else { "-TERM" };
        let status = Command::new("kill")
            .args([signal, &pid.to_string()])
            .status()
            .context("failed to invoke kill")?;
        if !status.success() {
            bail!("kill exited with status {status}");
        }
        Ok(())
    }
}

fn process_is_running(pid: u32) -> anyhow::Result<bool> {
    #[cfg(windows)]
    {
        unsafe {
            let handle = OpenProcess(PROCESS_SYNCHRONIZE_RIGHT, 0, pid);
            if handle.is_null() {
                return Ok(false);
            }
            let wait = WaitForSingleObject(handle, 0);
            let _ = CloseHandle(handle);
            Ok(wait == WAIT_TIMEOUT)
        }
    }

    #[cfg(not(windows))]
    {
        let status = Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to invoke kill -0")?;
        Ok(status.success())
    }
}

fn spawn_background_process(command: &mut Command) -> anyhow::Result<u32> {
    #[cfg(windows)]
    {
        let child = command
            .spawn()
            .context("failed to spawn background serve child")?;
        Ok(child.id())
    }

    #[cfg(not(windows))]
    {
        let child = command
            .spawn()
            .context("failed to spawn background serve child")?;
        Ok(child.id())
    }
}

#[cfg(windows)]
fn clear_standard_handle_inheritance() -> anyhow::Result<()> {
    unsafe {
        for std_handle in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let handle = GetStdHandle(std_handle);
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                continue;
            }
            if SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) == 0 {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(6) | Some(87) => continue,
                    _ => {
                        return Err(error).with_context(|| {
                            format!(
                                "failed to clear handle inheritance for standard handle {std_handle}"
                            )
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
fn run_taskkill(pid: u32, force: bool) -> anyhow::Result<()> {
    let mut command = Command::new("taskkill");
    command.args(["/PID", &pid.to_string(), "/T"]);
    if force {
        command.arg("/F");
    }
    let output = command.output().context("failed to invoke taskkill")?;
    if !output.status.success() {
        if !process_is_running(pid).unwrap_or(false) {
            return Ok(());
        }
        bail!(
            "taskkill exited with status {}.\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn wait_for_process_exit(pid: u32, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !process_is_running(pid)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    bail!("process {pid} is still running")
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_path_for_match, path_is_within, sqlite_path_from_database_url};
    use std::path::{Path, PathBuf};

    #[test]
    fn parses_sqlite_path_from_database_url() {
        let path = sqlite_path_from_database_url("sqlite:var/data/app.db?mode=rwc")
            .expect("sqlite path should parse")
            .expect("sqlite path should be present");
        assert_eq!(path, PathBuf::from("var/data/app.db"));
    }

    #[test]
    fn ignores_non_sqlite_database_urls() {
        assert!(
            sqlite_path_from_database_url("postgres://localhost/app")
                .expect("postgres URL should parse")
                .is_none()
        );
    }

    #[test]
    fn path_within_checks_prefix() {
        let base = canonicalize_path_for_match(Path::new("."));
        assert!(path_is_within(&base, &base.join("var/data/app.db")));
        assert!(!path_is_within(&base, Path::new("C:/tmp/elsewhere.db")));
    }
}
