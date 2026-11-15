//! Host-side MCP adapter for a single, explicitly scoped marsh workspace.
//!
//! The adapter exposes typed marsh product operations. It intentionally has no
//! generic host-process, SBX, Docker, environment, or filesystem passthrough.

pub mod acp_export;
pub mod broker;
mod exec_identity;
pub mod export;
mod host_paths;
mod supervise;

use supervise::{
    CapturedOutput, merge_output, process_group_exists, read_bounded_stream, run_bounded,
    run_bounded_cancel, terminate_pipeline_process_group,
};

use exec_identity::{DirectoryIdentity, ExecutableIdentity};

pub use acp_export::{AcpDeclaration, AcpExportMcp};

pub use host_paths::*;

pub use export::{
    ArgBinding, ExecutionOutcome, ExportBundle, ExportConfig, ExportExecutionData, ExportMcp,
    ResultFormat, StdinBinding, ToolBindings, ToolDeclaration, WorkspaceIdentity,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rmcp::{
    ServerHandler,
    handler::server::wrapper::{Json, Parameters},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::{
        Mutex, OwnedMutexGuard, OwnedRwLockWriteGuard, OwnedSemaphorePermit, RwLock, Semaphore,
        watch,
    },
};
use uuid::Uuid;

const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const MAX_TIMEOUT_MS: u64 = 900_000;
/// How long a session's (or the server's) shutdown waits for its operations'
/// cleanup to become terminal.
pub const SESSION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CAPTURE_BYTES: usize = 262_144;
const MAX_COMMAND_BYTES: usize = 65_536;
pub(crate) const MAX_OPERATIONS: usize = 4;
const MAX_RETAINED_OPERATIONS: usize = 128;
const MAX_DEVELOPMENT_SCOPES: usize = 16;
const MAX_RETAINED_SCOPES: usize = 128;
const MAX_SCOPE_REMOVAL_ENTRIES: usize = 100_000;
const MAX_SCOPE_REMOVAL_DEPTH: usize = 64;
const SCOPE_LIFECYCLE_TIMEOUT: Duration = Duration::from_mins(10);
const MAX_WORKSPACE_BINDING_BYTES: u64 = 16_384;
pub(crate) const RELAY_ENV: [&str; 5] = [
    "MARSH_DAEMON_SOCKET",
    "MARSH_DAEMON_TOKEN",
    "MARSH_SESSION_ID",
    "MARSH_HOME_BACKING",
    "MARSH_RELAY_TOKEN",
];
/// Copies the allowlisted host environment, including the stock SBX instance
/// selectors, into an `env_clear`ed host command, and strips relay secrets.
pub(crate) fn forward_host_environment(command: &mut std::process::Command) {
    for name in INHERITED_ENV
        .into_iter()
        .chain(marsh_runtime::STOCK_SBX_SELECTORS)
    {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    // These are denied even if the inherited allowlist grows in the future.
    for name in RELAY_ENV {
        command.env_remove(name);
    }
}

/// The whole environment of a host child of this server: fixed identity and
/// `PATH`, then the [`forward_host_environment`] allowlist.
pub(crate) fn apply_host_environment(
    command: &mut std::process::Command,
    config: &HostConfig,
    home: &Path,
) {
    command
        .env_clear()
        .env("MARSH_HOME", home)
        .env("MARSH_SBX", &config.sbx)
        .env("USER", &config.username)
        .env("LOGNAME", &config.username)
        .env("PATH", fixed_minimal_path());
    forward_host_environment(command);
}

/// Settings the resident daemon reads from its own environment and that only
/// tune it (numbers and switches): the per-job and launch limits
/// (`marsh_daemon::limits::LIMITS`) and these. A daemon an export starts keeps
/// serving later CLI sessions, so it needs the user's tuning. Not here:
/// anything that names an image, an executable or a directory
/// (`MARSH_SHELL_IMAGE`, `MARSH_KIT_IMAGE_CACHE`, `MARSH_GUEST_ARTIFACTS`,
/// `MARSH_SKILLS_HOME`...), and credentials, proxies, `SSH_AUTH_SOCK` and
/// `DOCKER_*`, which the daemon never reads (it runs `sbx` with a cleared
/// environment of its own).
pub(crate) const DAEMON_KNOBS: [&str; 8] = [
    "MARSH_AUTO_UPDATE",
    "MARSH_OPEN_URLS",
    "MARSH_VM_IDLE_SECONDS",
    "MARSH_SERVICES_IDLE_SECONDS",
    "MARSH_SERVICES_STOP_WAIT_SECONDS",
    "MARSH_SERVICES_POOL_BYTES",
    "MARSH_SERVICES_POOL_RESERVE_BYTES",
    "MARSH_CLOUD_DETACHED_RETENTION",
];

/// The environment of the resident daemon an export starts: that of the host
/// `marsh` children (`apply_host_environment`), plus the [`DAEMON_KNOBS`] and
/// limit variables that `lookup` (the gateway's environment) has.
pub(crate) fn daemon_environment(
    config: &HostConfig,
    lookup: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    let mut probe = std::process::Command::new("daemon-environment");
    apply_host_environment(&mut probe, config, &config.home);
    let mut environment = probe
        .get_envs()
        .filter_map(|(name, value)| Some((name.to_owned(), value?.to_owned())))
        .collect::<Vec<_>>();
    let limits = marsh_daemon::limits::LIMITS
        .iter()
        .map(|spec| spec.variable);
    for name in DAEMON_KNOBS.into_iter().chain(limits) {
        if let Some(value) = lookup(name) {
            environment.push((name.into(), value));
        }
    }
    environment
}

/// The resident daemon this server starts gets [`daemon_environment`], not the
/// gateway's own.
pub(crate) fn start_daemon(
    config: &HostConfig,
) -> Result<marsh_daemon::Client, marsh_daemon::DaemonError> {
    marsh_daemon::Client::ensure_running_with_environment(
        &config.home,
        &config.marshd,
        &config.sbx,
        &daemon_environment(config, &|name| env::var_os(name)),
    )
}

pub(crate) const INHERITED_ENV: [&str; 13] = [
    "HOME",
    // The host state root: every host-side write follows the caller's
    // override, including the daemon this server starts.
    "MARSH_CONTROL_HOME",
    // Stock SBX resolves its approved credential bindings here, host-side only.
    "XDG_CONFIG_HOME",
    "TMPDIR",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "COLORTERM",
    "NO_COLOR",
    "CARGO_HOME",
    "RUSTUP_HOME",
];

/// Validated, immutable host MCP scope.
#[derive(Clone, Debug)]
pub struct HostConfig {
    username: String,
    workspace: PathBuf,
    home: PathBuf,
    home_identity: DirectoryIdentity,
    generated_scope_root: Option<PathBuf>,
    scope_root_identity: Option<DirectoryIdentity>,
    _scope_root_lease: Option<Arc<ScopeRootLease>>,
    marsh: PathBuf,
    marshd: PathBuf,
    sbx: PathBuf,
    make: PathBuf,
    marsh_identity: ExecutableIdentity,
    marshd_identity: ExecutableIdentity,
    sbx_identity: ExecutableIdentity,
    full_sbx_control_enabled: bool,
    persisted_scopes: BTreeMap<String, DevelopmentScope>,
    preserved_registry_records: BTreeMap<String, Value>,
    registry_diagnostics: Vec<String>,
}

#[derive(Debug, Default)]
struct LoadedScopeRegistry {
    scopes: BTreeMap<String, DevelopmentScope>,
    preserved_records: BTreeMap<String, Value>,
    diagnostics: Vec<String>,
}

#[derive(Debug)]
struct ScopeRootLease {
    file: fs::File,
}

impl Drop for ScopeRootLease {
    fn drop(&mut self) {
        // Closing the descriptor also releases flock, but perform the unlock
        // explicitly so an immediate successor never depends on close timing
        // or platform-specific descriptor lifetime details.
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceBinding {
    version: u32,
    canonical_workspace: PathBuf,
    device: u64,
    inode: u64,
}

impl HostConfig {
    /// Build a scope from explicit paths. The workspace and executable must
    /// exist. The selected home is created owner-only when absent and is
    /// rejected if it is not owned by this user or accessible by group/other.
    ///
    /// # Errors
    /// Returns an error when a path is relative, missing, has the wrong type,
    /// is not safely owned, or has unsafe permissions.
    pub fn new(
        workspace: &Path,
        home: &Path,
        marsh: &Path,
        sbx: &Path,
        full_sbx_control_enabled: bool,
    ) -> Result<Self, String> {
        for (label, path) in [
            ("workspace", workspace),
            ("home", home),
            ("marsh executable", marsh),
            ("sbx executable", sbx),
        ] {
            if !path.is_absolute() {
                return Err(format!("{label} must be an absolute path"));
            }
        }
        Self::new_inner(workspace, home, None, marsh, sbx, full_sbx_control_enabled)
    }

    /// Build a multi-scope server rooted at one private development directory.
    ///
    /// # Errors
    /// Returns an error when paths overlap, permissions are unsafe, executable
    /// trust anchors change, or the persisted scope registry is invalid.
    pub fn new_with_scope_root(
        workspace: &Path,
        home: &Path,
        scope_root: &Path,
        marsh: &Path,
        sbx: &Path,
        full_sbx_control_enabled: bool,
    ) -> Result<Self, String> {
        Self::new_inner(
            workspace,
            home,
            Some(scope_root),
            marsh,
            sbx,
            full_sbx_control_enabled,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn new_inner(
        workspace: &Path,
        home: &Path,
        scope_root: Option<&Path>,
        marsh: &Path,
        sbx: &Path,
        full_sbx_control_enabled: bool,
    ) -> Result<Self, String> {
        let username = effective_username()?;
        for (label, path) in [
            ("workspace", workspace),
            ("home", home),
            ("marsh executable", marsh),
            ("sbx executable", sbx),
        ] {
            if !path.is_absolute() {
                return Err(format!("{label} must be an absolute path"));
            }
        }
        let workspace = canonical_directory(workspace, "workspace")?;
        if let Some(scope_root) = scope_root {
            if !scope_root.is_absolute() {
                return Err("development scope root must be an absolute path".into());
            }
            let unresolved_root = resolve_without_creation(scope_root)?;
            if is_at_or_beneath(&unresolved_root, &workspace)
                || is_at_or_beneath(&workspace, &unresolved_root)
            {
                return Err("development scope root and workspace must not overlap".into());
            }
            let guest_home = guest_writable_marsh_home()?;
            if is_at_or_beneath(&unresolved_root, &guest_home) {
                return Err(format!(
                    "development scope root must be outside the guest-writable marsh home: {}",
                    guest_home.display()
                ));
            }
        }
        let generated_scope_root = scope_root.map(prepare_scope_root).transpose()?;
        let scope_root_identity = generated_scope_root
            .as_ref()
            .map(|root| DirectoryIdentity::capture(root))
            .transpose()?;
        if let Some(root) = &generated_scope_root {
            let guest_home = guest_writable_marsh_home()?;
            if is_at_or_beneath(root, &guest_home) {
                return Err(format!(
                    "development scope root must be outside the guest-writable marsh home: {}",
                    guest_home.display()
                ));
            }
        }
        if let Some(root) = &generated_scope_root
            && (is_at_or_beneath(root, &workspace) || is_at_or_beneath(&workspace, root))
        {
            return Err("development scope root and workspace must not overlap".into());
        }
        let scope_root_lease = generated_scope_root
            .as_ref()
            .map(|root| acquire_scope_root_lease(root))
            .transpose()?;
        if let Some(root) = &generated_scope_root {
            establish_workspace_binding(root, &workspace)?;
            reap_stale_scope_registry_temps(root)?;
        }
        let mut loaded_registry = generated_scope_root
            .as_ref()
            .map(|root| load_scope_registry(root))
            .transpose()?
            .unwrap_or_default();
        let home = if generated_scope_root.is_some() {
            resolve_without_creation(home)?
        } else {
            home.to_path_buf()
        };
        if home.starts_with(&workspace) {
            return Err(format!(
                "MCP home must be outside the workspace: {}",
                workspace.display()
            ));
        }
        if let Some(root) = &generated_scope_root
            && (home.parent() != Some(root)
                || home.file_name().and_then(|name| name.to_str()) != Some("default"))
        {
            return Err("multi-scope default home must be <scope-root>/default".into());
        }
        let persisted_default = loaded_registry.scopes.get("default");
        let (home, home_identity) = if let Some(scope) = persisted_default {
            // Registry reconciliation already verified the exact persisted
            // identity or isolated the record as Failed. Never recreate or
            // recapture a persisted default home during restart.
            (home.clone(), scope.home_identity.clone())
        } else {
            // Resolve an existing home before checking its ownership/mode.
            // This catches both an ancestor home and a symlink to an ancestor.
            if home.exists() {
                let resolved_home = canonical_directory(&home, "home")?;
                if is_at_or_beneath(&resolved_home, &workspace)
                    || is_at_or_beneath(&workspace, &resolved_home)
                {
                    return Err(format!(
                        "MCP home and workspace must not overlap in either direction: home={}, workspace={}",
                        resolved_home.display(),
                        workspace.display()
                    ));
                }
            }
            let home = prepare_home(&home)?;
            let identity = DirectoryIdentity::capture(&home)?;
            (home, identity)
        };
        if is_at_or_beneath(&home, &workspace) || is_at_or_beneath(&workspace, &home) {
            return Err(format!(
                "MCP home and workspace must not overlap in either direction: home={}, workspace={}",
                home.display(),
                workspace.display()
            ));
        }
        let marsh = canonical_file(marsh, "marsh executable")?;
        let marshd_candidate = marsh
            .parent()
            .ok_or_else(|| "marsh executable has no parent directory".to_string())?
            .join("marshd");
        let marshd = canonical_file(&marshd_candidate, "sibling marshd executable")?;
        let sbx = canonical_external_executable(sbx, "sbx executable")?;
        for (label, executable) in [
            ("marsh", &marsh),
            ("sibling marshd", &marshd),
            ("sbx", &sbx),
        ] {
            if is_at_or_beneath(executable, &workspace) || is_at_or_beneath(executable, &home) {
                return Err(format!(
                    "{label} executable must be installed outside the workspace and selected home; refusing {}",
                    executable.display()
                ));
            }
            if generated_scope_root
                .as_ref()
                .is_some_and(|root| is_at_or_beneath(executable, root))
            {
                return Err(format!(
                    "{label} executable must be installed outside the development scope root; refusing {}",
                    executable.display()
                ));
            }
        }
        let marsh_identity = ExecutableIdentity::capture(&marsh)?;
        let daemon_identity = ExecutableIdentity::capture(&marshd)?;
        let sbx_identity = ExecutableIdentity::capture_external(&sbx)?;
        let make = canonical_file(Path::new("/usr/bin/make"), "make executable")?;
        if let Some(root) = &generated_scope_root
            && !loaded_registry.scopes.contains_key("default")
        {
            loaded_registry.scopes.insert(
                "default".to_owned(),
                DevelopmentScope {
                    home: home.clone(),
                    home_identity: home_identity.clone(),
                    state: ScopeState::Ready,
                    created_unix_ms: now_ms(),
                    last_operation_id: None,
                    diagnostic: None,
                },
            );
            persist_scope_registry(
                root,
                &loaded_registry.scopes,
                &loaded_registry.preserved_records,
            )?;
        }
        Ok(Self {
            username,
            workspace,
            home,
            home_identity,
            generated_scope_root,
            scope_root_identity,
            _scope_root_lease: scope_root_lease,
            marsh,
            marshd,
            sbx,
            make,
            marsh_identity,
            marshd_identity: daemon_identity,
            sbx_identity,
            full_sbx_control_enabled,
            persisted_scopes: loaded_registry.scopes,
            preserved_registry_records: loaded_registry.preserved_records,
            registry_diagnostics: loaded_registry.diagnostics,
        })
    }

    /// Canonical workspace path.
    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Canonical selected-home path.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Canonical marsh executable path.
    #[must_use]
    pub fn marsh(&self) -> &Path {
        &self.marsh
    }

    /// Canonical sibling marshd executable path.
    #[must_use]
    pub fn marshd(&self) -> &Path {
        &self.marshd
    }

    /// Canonical sbx executable path.
    #[must_use]
    pub fn sbx(&self) -> &Path {
        &self.sbx
    }

    /// Resolved username.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Revalidate the configured host executables.
    ///
    /// # Errors
    /// Returns an error if any executable has been modified, moved, or replaced.
    pub fn validate_host_executables(&self) -> Result<(), String> {
        for (label, path, expected) in [
            ("marsh", &self.marsh, &self.marsh_identity),
            ("sibling marshd", &self.marshd, &self.marshd_identity),
        ] {
            let current = ExecutableIdentity::capture(path)?;
            if &current != expected {
                return Err(format!(
                    "configured {label} executable changed after MCP startup; restart marsh-mcp after reinstalling {}",
                    path.display()
                ));
            }
        }
        let current_sbx = ExecutableIdentity::capture_external(&self.sbx)?;
        if current_sbx != self.sbx_identity {
            return Err(format!(
                "configured sbx executable changed after MCP startup; restart marsh-mcp after reinstalling {}",
                self.sbx.display()
            ));
        }
        Ok(())
    }

    fn validate_scope_root(&self) -> Result<(), String> {
        match (&self.generated_scope_root, &self.scope_root_identity) {
            (Some(root), Some(expected)) if &DirectoryIdentity::capture(root)? == expected => {
                Ok(())
            }
            (None, None) => Ok(()),
            (Some(root), Some(_)) => Err(format!(
                "development scope root changed after MCP startup: {}",
                root.display()
            )),
            _ => Err("development scope root identity is inconsistent".into()),
        }
    }

    fn persist_scopes(&self, scopes: &BTreeMap<String, DevelopmentScope>) -> Result<(), String> {
        let root = self.generated_scope_root.as_ref().ok_or_else(|| {
            "managed scope registry is unavailable in legacy --home mode".to_owned()
        })?;
        persist_scope_registry(root, scopes, &self.preserved_registry_records)
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ToolResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ToolResponse {
    fn success(data: Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    fn failure(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultGetRequest {
    /// Durable result cursor, full job UUID, or unique UUID prefix.
    selector: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionRequest {
    /// `all` or a comma-separated list of lowercase Kit names.
    #[serde(default = "default_selection")]
    selection: String,
}

fn default_selection() -> String {
    "all".into()
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShellRunRequest {
    /// Shell program evaluated by marsh inside the project shell VM.
    command: String,
    /// Wall-clock limit in milliseconds (10..=900000).
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualifyRequest {
    /// Fixed qualification gate: `source`, `smoke`, `full`, or `perf`.
    gate: String,
    /// Wall-clock limit in milliseconds (10..=900000).
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
    /// Operation identifier returned by a mutating or long-running tool.
    operation_id: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeRequest {
    /// Opaque scope identifier returned by `scope_start`, or `default`.
    scope_id: String,
}

#[derive(Clone, Debug, Default, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct EmptyRequest {}

impl<'de> Deserialize<'de> for EmptyRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EmptyVisitor;

        impl<'de> serde::de::Visitor<'de> for EmptyVisitor {
            type Value = EmptyRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an empty object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                if map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("this tool accepts no properties"));
                }
                Ok(EmptyRequest {})
            }
        }

        deserializer.deserialize_map(EmptyVisitor)
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeRunRequest {
    /// Opaque scope identifier returned by `scope_start`, or `default`.
    scope_id: String,
    /// Shell program evaluated by marsh inside this scope's project shell VM.
    command: String,
    /// Wall-clock limit in milliseconds (10..=900000).
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeResultGetRequest {
    /// Opaque scope identifier returned by `scope_start`, or `default`.
    scope_id: String,
    /// Durable result cursor, full job UUID, or unique UUID prefix.
    selector: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeSelectionRequest {
    /// Opaque scope identifier returned by `scope_start`, or `default`.
    scope_id: String,
    /// `all` or a comma-separated list of lowercase Kit names.
    #[serde(default = "default_selection")]
    selection: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct OperationView {
    operation_id: String,
    scope_id: String,
    kind: String,
    state: OperationState,
    started_unix_ms: u128,
    finished_unix_ms: Option<u128>,
    exit_code: Option<i32>,
    stdout_bytes: usize,
    stderr_bytes: usize,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationState {
    Queued,
    Running,
    Succeeded,
    Failed,
    CancellationUncertain,
}

#[derive(Debug)]
struct Operation {
    id: String,
    owner_session: String,
    scope_id: String,
    kind: String,
    state: OperationState,
    started_unix_ms: u128,
    finished_unix_ms: Option<u128>,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    cancel: Option<watch::Sender<bool>>,
}

impl Operation {
    fn view(&self) -> OperationView {
        OperationView {
            operation_id: self.id.clone(),
            scope_id: self.scope_id.clone(),
            kind: self.kind.clone(),
            state: self.state,
            started_unix_ms: self.started_unix_ms,
            finished_unix_ms: self.finished_unix_ms,
            exit_code: self.exit_code,
            stdout_bytes: self.stdout.len(),
            stderr_bytes: self.stderr.len(),
            stdout_truncated: self.stdout_truncated,
            stderr_truncated: self.stderr_truncated,
        }
    }
}

#[derive(Clone, Debug)]
struct CommandSpec {
    executable: PathBuf,
    arguments: Vec<String>,
    timeout: Duration,
    home: PathBuf,
    home_identity: DirectoryIdentity,
}

impl CommandSpec {
    fn validate_home(&self) -> Result<(), String> {
        let current = DirectoryIdentity::capture(&self.home)?;
        if current != self.home_identity {
            return Err(format!(
                "development scope home changed before operation start: {}",
                self.home.display()
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScopeState {
    Starting,
    Ready,
    Resetting,
    Stopping,
    Removing,
    Stopped,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DevelopmentScope {
    #[serde(skip)]
    home: PathBuf,
    #[serde(default)]
    home_identity: DirectoryIdentity,
    state: ScopeState,
    created_unix_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    diagnostic: Option<String>,
}

impl DevelopmentScope {
    fn validate_home(&self) -> Result<(), String> {
        let current = DirectoryIdentity::capture(&self.home)?;
        if current != self.home_identity {
            return Err(format!(
                "development scope home changed after MCP startup: {}",
                self.home.display()
            ));
        }
        Ok(())
    }
}

/// Host-side MCP tool server.
#[derive(Clone, Debug)]
pub struct HostMcp {
    config: Arc<HostConfig>,
    session_id: String,
    operations: Arc<Mutex<BTreeMap<String, Operation>>>,
    permits: Arc<Semaphore>,
    lifecycles: Arc<Mutex<BTreeMap<String, Arc<Mutex<()>>>>>,
    scope_access: Arc<Mutex<BTreeMap<String, Arc<RwLock<()>>>>>,
    scopes: Arc<Mutex<BTreeMap<String, DevelopmentScope>>>,
}

impl HostMcp {
    /// Create a scoped MCP server.
    #[must_use]
    pub fn new(config: HostConfig) -> Self {
        let mut scopes = config.persisted_scopes.clone();
        scopes
            .entry("default".to_owned())
            .or_insert_with(|| DevelopmentScope {
                home: config.home.clone(),
                home_identity: config.home_identity.clone(),
                state: ScopeState::Ready,
                created_unix_ms: now_ms(),
                last_operation_id: None,
                diagnostic: None,
            });
        Self {
            config: Arc::new(config),
            session_id: Uuid::new_v4().to_string(),
            operations: Arc::new(Mutex::new(BTreeMap::new())),
            permits: Arc::new(Semaphore::new(MAX_OPERATIONS)),
            lifecycles: Arc::new(Mutex::new(BTreeMap::new())),
            scope_access: Arc::new(Mutex::new(BTreeMap::new())),
            scopes: Arc::new(Mutex::new(scopes)),
        }
    }

    /// Create a transport-local view over the same host state.
    ///
    /// Operations created through the returned handler are visible and
    /// cancellable only through that handler. Shared scope and capacity state
    /// remains process-wide.
    #[must_use]
    pub fn new_session(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            session_id: Uuid::new_v4().to_string(),
            operations: Arc::clone(&self.operations),
            permits: Arc::clone(&self.permits),
            lifecycles: Arc::clone(&self.lifecycles),
            scope_access: Arc::clone(&self.scope_access),
            scopes: Arc::clone(&self.scopes),
        }
    }

    /// Cancel only work started by this transport session.
    ///
    /// # Errors
    /// Returns an error if session-owned cleanup does not become terminal in
    /// the bounded shutdown interval.
    pub async fn shutdown_session(&self) -> Result<(), String> {
        {
            let operations = self.operations.lock().await;
            for operation in operations.values().filter(|operation| {
                operation.owner_session == self.session_id
                    && matches!(
                        operation.state,
                        OperationState::Queued | OperationState::Running
                    )
            }) {
                let _ = operation.cancel.as_ref().map(|cancel| cancel.send(true));
            }
        }
        let deadline = tokio::time::Instant::now() + SESSION_SHUTDOWN_TIMEOUT;
        loop {
            let complete = self.operations.lock().await.values().all(|operation| {
                operation.owner_session != self.session_id
                    || matches!(
                        operation.state,
                        OperationState::Succeeded
                            | OperationState::Failed
                            | OperationState::CancellationUncertain
                    )
            });
            if complete {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("MCP session shutdown timed out waiting for operation cleanup".into());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Request cancellation for every queued/running operation and wait for
    /// their operation tasks to record a terminal state.
    ///
    /// # Errors
    /// Returns an error if operation cleanup does not reach a terminal state
    /// within the bounded shutdown interval.
    pub async fn shutdown_all(&self) -> Result<(), String> {
        {
            let operations = self.operations.lock().await;
            for operation in operations.values() {
                if matches!(
                    operation.state,
                    OperationState::Queued | OperationState::Running
                ) {
                    let _ = operation.cancel.as_ref().map(|cancel| cancel.send(true));
                }
            }
        }
        let deadline = tokio::time::Instant::now() + SESSION_SHUTDOWN_TIMEOUT;
        loop {
            let complete = self.operations.lock().await.values().all(|operation| {
                matches!(
                    operation.state,
                    OperationState::Succeeded
                        | OperationState::Failed
                        | OperationState::CancellationUncertain
                )
            });
            if complete {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("MCP shutdown timed out waiting for operation cleanup".into());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn run_json_in(
        &self,
        scope_id: &str,
        scope: &DevelopmentScope,
        arguments: &[&str],
        timeout: Duration,
    ) -> ToolResponse {
        if let Err(error) = self.config.validate_scope_root() {
            return ToolResponse::failure(error);
        }
        let access = Arc::clone(
            self.scope_access
                .lock()
                .await
                .entry(scope_id.to_owned())
                .or_insert_with(|| Arc::new(RwLock::new(()))),
        );
        let Ok(_admission) = access.try_read_owned() else {
            return ToolResponse::failure(
                "this development scope is changing lifecycle; retry after it completes",
            );
        };
        let Ok(_permit) = self.permits.try_acquire() else {
            return ToolResponse::failure(
                "MCP operation capacity is busy; retry after an active operation completes",
            );
        };
        let spec = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: arguments.iter().map(ToString::to_string).collect(),
            timeout,
            home: scope.home.clone(),
            home_identity: scope.home_identity.clone(),
        };
        match run_bounded(self.config.as_ref(), &spec).await {
            Ok(output) if output.exit_code == Some(0) => {
                match serde_json::from_slice(&output.stdout) {
                    Ok(value) => ToolResponse::success(value),
                    Err(error) => {
                        ToolResponse::failure(format!("marsh returned invalid JSON: {error}"))
                    }
                }
            }
            Ok(output) => ToolResponse::failure(command_failure("marsh", &output)),
            Err(error) => ToolResponse::failure(error),
        }
    }

    async fn run_stopped_results_in(
        &self,
        scope_id: &str,
        scope: &DevelopmentScope,
        arguments: &[&str],
    ) -> ToolResponse {
        if let Err(error) = self.config.validate_scope_root() {
            return ToolResponse::failure(error);
        }
        let access = Arc::clone(
            self.scope_access
                .lock()
                .await
                .entry(scope_id.to_owned())
                .or_insert_with(|| Arc::new(RwLock::new(()))),
        );
        let Ok(_admission) = access.try_write_owned() else {
            return ToolResponse::failure(
                "this stopped development scope is busy; retry after its active read or lifecycle operation completes",
            );
        };
        {
            let scopes = self.scopes.lock().await;
            let Some(current) = scopes.get(scope_id) else {
                return ToolResponse::failure("unknown development scope");
            };
            if current.state != ScopeState::Stopped
                || current.home != scope.home
                || current.home_identity != scope.home_identity
            {
                return ToolResponse::failure(
                    "development scope changed after receipt-read admission; retry against its current lifecycle state",
                );
            }
            if let Err(error) = current.validate_home() {
                return ToolResponse::failure(error);
            }
        }
        let Ok(_permit) = self.permits.try_acquire() else {
            return ToolResponse::failure(
                "MCP operation capacity is busy; retry after an active operation completes",
            );
        };
        let read = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: arguments.iter().map(ToString::to_string).collect(),
            timeout: Duration::from_secs(20),
            home: scope.home.clone(),
            home_identity: scope.home_identity.clone(),
        };
        let stop = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec!["stop".into(), "--json".into()],
            timeout: SCOPE_LIFECYCLE_TIMEOUT,
            home: scope.home.clone(),
            home_identity: scope.home_identity.clone(),
        };
        let read_result = run_bounded(self.config.as_ref(), &read).await;
        let stop_result = run_bounded(self.config.as_ref(), &stop).await;
        if !stop_result
            .as_ref()
            .is_ok_and(|output| output.exit_code == Some(0))
        {
            let diagnostic = match &stop_result {
                Ok(output) => command_failure("marsh stop", output),
                Err(error) => error.clone(),
            };
            let mut scopes = self.scopes.lock().await;
            if let Some(registered) = scopes.get_mut(scope_id) {
                registered.state = ScopeState::Failed;
                registered.diagnostic = Some(bounded_diagnostic(&format!(
                    "stopped receipt read could not prove daemon shutdown: {diagnostic}"
                )));
            }
            let persistence = self.config.persist_scopes(&scopes);
            return ToolResponse::failure(match persistence {
                Ok(()) => format!(
                    "stopped receipt read could not prove daemon shutdown; scope marked failed: {diagnostic}"
                ),
                Err(error) => format!(
                    "stopped receipt read could not prove daemon shutdown ({diagnostic}) and failed to persist the failed state: {error}"
                ),
            });
        }
        match read_result {
            Ok(output) if output.exit_code == Some(0) => {
                match serde_json::from_slice(&output.stdout) {
                    Ok(value) => ToolResponse::success(value),
                    Err(error) => {
                        ToolResponse::failure(format!("marsh returned invalid JSON: {error}"))
                    }
                }
            }
            Ok(output) => ToolResponse::failure(command_failure("marsh", &output)),
            Err(error) => ToolResponse::failure(error),
        }
    }

    async fn run_json(&self, arguments: &[&str], timeout: Duration) -> ToolResponse {
        let scope = match self.active_scope("default").await {
            Ok(scope) => scope,
            Err(error) => return ToolResponse::failure(error),
        };
        self.run_json_in("default", &scope, arguments, timeout)
            .await
    }

    async fn readable_results_scope(&self, scope_id: &str) -> Result<DevelopmentScope, String> {
        self.config.validate_scope_root()?;
        validate_scope_id(scope_id)?;
        let scopes = self.scopes.lock().await;
        let scope = scopes
            .get(scope_id)
            .ok_or_else(|| "unknown development scope".to_owned())?;
        if !matches!(scope.state, ScopeState::Ready | ScopeState::Stopped) {
            return Err(format!(
                "development scope results are unavailable while state={}",
                serde_json::to_value(scope.state)
                    .unwrap_or(Value::String("unknown".into()))
                    .as_str()
                    .unwrap_or("unknown")
            ));
        }
        scope.validate_home()?;
        Ok(scope.clone())
    }

    async fn active_scope(&self, scope_id: &str) -> Result<DevelopmentScope, String> {
        self.config.validate_scope_root()?;
        validate_scope_id(scope_id)?;
        let scopes = self.scopes.lock().await;
        let scope = scopes
            .get(scope_id)
            .ok_or_else(|| "unknown development scope".to_owned())?;
        if scope.state != ScopeState::Ready {
            return Err(format!(
                "development scope is not ready (state={})",
                serde_json::to_value(scope.state)
                    .unwrap_or(Value::String("unknown".into()))
                    .as_str()
                    .unwrap_or("unknown")
            ));
        }
        if let Err(error) = scope.validate_home() {
            return Err(format!(
                "development scope home identity cannot be verified; automatic reset and removal are refused without claiming the possibly live runtime is absent. Restore the exact original directory entry, or stop marsh-mcp, independently prove and remove the exact runtime with stock SBX, archive this development-control root, and restart with a new empty --scope-root. No replacement path was modified: {error}"
            ));
        }
        Ok(scope.clone())
    }

    async fn resettable_scope(&self, scope_id: &str) -> Result<DevelopmentScope, String> {
        self.config.validate_scope_root()?;
        validate_scope_id(scope_id)?;
        let scopes = self.scopes.lock().await;
        let scope = scopes
            .get(scope_id)
            .ok_or_else(|| "unknown development scope".to_owned())?;
        if matches!(
            scope.state,
            ScopeState::Starting
                | ScopeState::Resetting
                | ScopeState::Stopping
                | ScopeState::Removing
        ) {
            return Err("development scope already has a lifecycle transition in progress".into());
        }
        if let Err(error) = scope.validate_home() {
            return Err(format!(
                "development scope home identity cannot be verified; automatic reset and removal are refused without claiming the possibly live runtime is absent. Restore the exact original directory entry, or stop marsh-mcp, independently prove and remove the exact runtime with stock SBX, archive this development-control root, and restart with a new empty --scope-root. No replacement path was modified: {error}"
            ));
        }
        Ok(scope.clone())
    }

    #[allow(clippy::too_many_lines)]
    async fn start_operation(
        &self,
        scope_id: &str,
        kind: &str,
        spec: CommandSpec,
        followups: Vec<CommandSpec>,
        exclusive_lifecycle: bool,
    ) -> ToolResponse {
        if let Err(error) = self.config.validate_scope_root() {
            return ToolResponse::failure(error);
        }
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return ToolResponse::failure(
                "MCP operation capacity is busy; retry after an active operation completes",
            );
        };
        let lifecycle = Arc::clone(
            self.lifecycles
                .lock()
                .await
                .entry(scope_id.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        );
        let Ok(admission) = lifecycle.try_lock_owned() else {
            return ToolResponse::failure(
                "this development scope is busy; retry after its active lifecycle operation completes",
            );
        };
        let scope_access_guard = if matches!(kind, "scope_reset" | "scope_stop") {
            let access = Arc::clone(
                self.scope_access
                    .lock()
                    .await
                    .entry(scope_id.to_owned())
                    .or_insert_with(|| Arc::new(RwLock::new(()))),
            );
            let Ok(guard) = access.try_write_owned() else {
                return ToolResponse::failure(
                    "development scope has an active read and cannot change lifecycle",
                );
            };
            Some(guard)
        } else {
            None
        };
        let id = Uuid::new_v4().to_string();
        let previous_scope = {
            let mut scopes = self.scopes.lock().await;
            let Some(previous_scope) = scopes.get(scope_id).cloned() else {
                return ToolResponse::failure("unknown development scope");
            };
            if let Err(error) = previous_scope.validate_home() {
                return ToolResponse::failure(error);
            }
            let previous = previous_scope.state;
            let requested = match kind {
                "scope_start" if previous == ScopeState::Starting => Some(ScopeState::Starting),
                "scope_reset"
                    if matches!(
                        previous,
                        ScopeState::Ready | ScopeState::Stopped | ScopeState::Failed
                    ) =>
                {
                    Some(ScopeState::Resetting)
                }
                "scope_stop" if previous == ScopeState::Ready => Some(ScopeState::Stopping),
                "scope_start" | "scope_reset" | "scope_stop" => {
                    return ToolResponse::failure(
                        "development scope state rejects this lifecycle operation",
                    );
                }
                _ if previous == ScopeState::Ready => None,
                _ => return ToolResponse::failure("development scope is not ready"),
            };
            if kind == "scope_reset"
                && scope_id != "default"
                && previous == ScopeState::Stopped
                && live_generated_scope_count(&scopes) >= MAX_DEVELOPMENT_SCOPES
            {
                return ToolResponse::failure(format!(
                    "development scope limit ({MAX_DEVELOPMENT_SCOPES}) reached; stop another live scope before resetting this one"
                ));
            }
            if matches!(kind, "scope_reset" | "scope_stop")
                && self.operations.lock().await.values().any(|operation| {
                    operation.scope_id == scope_id
                        && matches!(
                            operation.state,
                            OperationState::Queued | OperationState::Running
                        )
                })
            {
                return ToolResponse::failure(
                    "development scope has active MCP work; wait or cancel it before changing lifecycle",
                );
            }
            if let Some(state) = requested {
                let scope = scopes.get_mut(scope_id).expect("scope exists");
                scope.state = state;
                scope.last_operation_id = Some(id.clone());
                scope.diagnostic = None;
                if self.config.generated_scope_root.is_some()
                    && let Err(error) = self.config.persist_scopes(&scopes)
                {
                    scopes.insert(scope_id.to_owned(), previous_scope.clone());
                    return ToolResponse::failure(error);
                }
            }
            previous_scope
        };
        let (cancel, cancel_rx) = watch::channel(false);
        let operation = Operation {
            id: id.clone(),
            owner_session: self.session_id.clone(),
            scope_id: scope_id.to_owned(),
            kind: kind.into(),
            state: OperationState::Queued,
            started_unix_ms: now_ms(),
            finished_unix_ms: None,
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            cancel: Some(cancel),
        };
        {
            let mut operations = self.operations.lock().await;
            while operations.len() >= MAX_RETAINED_OPERATIONS {
                let oldest_terminal = operations
                    .values()
                    .filter(|operation| {
                        matches!(
                            operation.state,
                            OperationState::Succeeded
                                | OperationState::Failed
                                | OperationState::CancellationUncertain
                        )
                    })
                    .min_by_key(|operation| operation.started_unix_ms)
                    .map(|operation| operation.id.clone());
                let Some(oldest_terminal) = oldest_terminal else {
                    drop(operations);
                    let mut scopes = self.scopes.lock().await;
                    scopes.insert(scope_id.to_owned(), previous_scope.clone());
                    if self.config.generated_scope_root.is_some()
                        && let Err(error) = self.config.persist_scopes(&scopes)
                    {
                        return ToolResponse::failure(format!(
                            "operation retention limit reached and scope-state rollback failed: {error}"
                        ));
                    }
                    return ToolResponse::failure(format!(
                        "operation retention limit ({MAX_RETAINED_OPERATIONS}) reached"
                    ));
                };
                operations.remove(&oldest_terminal);
            }
            operations.insert(id.clone(), operation);
        }
        let lifecycle_guard = exclusive_lifecycle.then_some(admission);

        let config = Arc::clone(&self.config);
        let operations = Arc::clone(&self.operations);
        let scopes = Arc::clone(&self.scopes);
        let task_id = id.clone();
        let task_scope_id = scope_id.to_owned();
        let scope_transition = match kind {
            "scope_start" | "scope_reset" => Some((ScopeState::Ready, ScopeState::Failed)),
            "scope_stop" => Some((ScopeState::Stopped, ScopeState::Failed)),
            _ => None,
        };
        let scope_root = config.generated_scope_root.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _lifecycle_guard = lifecycle_guard;
            let _scope_access_guard = scope_access_guard;
            set_running(&operations, &task_id).await;
            let mut result = run_bounded_cancel(&config, &spec, cancel_rx.clone()).await;
            for next in followups {
                if !result
                    .as_ref()
                    .is_ok_and(|output| output.exit_code == Some(0))
                {
                    break;
                }
                result = match run_bounded_cancel(&config, &next, cancel_rx.clone()).await {
                    Ok(next_output) => Ok(merge_output(result.expect("checked Ok"), &next_output)),
                    Err(error) => Err(error),
                };
            }
            if let Some((success, failure)) = scope_transition {
                let mut registered = scopes.lock().await;
                if let Some(scope) = registered.get_mut(&task_scope_id) {
                    let succeeded = result
                        .as_ref()
                        .is_ok_and(|output| output.exit_code == Some(0));
                    scope.state = if succeeded { success } else { failure };
                    scope.diagnostic = (!succeeded).then(|| lifecycle_diagnostic(&result));
                }
                if scope_root.is_some()
                    && let Err(error) = config.persist_scopes(&registered)
                {
                    if let Some(scope) = registered.get_mut(&task_scope_id) {
                        scope.state = ScopeState::Failed;
                        scope.diagnostic = Some(bounded_diagnostic(&error));
                    }
                    result = Err(error);
                }
            }
            finish_operation(&operations, &task_id, result).await;
        });
        ToolResponse::success(json!({"operation_id": id, "state": "queued"}))
    }

    async fn insert_removal_operation(&self, id: &str, scope_id: &str) -> Result<(), String> {
        let mut operations = self.operations.lock().await;
        while operations.len() >= MAX_RETAINED_OPERATIONS {
            let oldest_terminal = operations
                .values()
                .filter(|operation| {
                    matches!(
                        operation.state,
                        OperationState::Succeeded
                            | OperationState::Failed
                            | OperationState::CancellationUncertain
                    )
                })
                .min_by_key(|operation| operation.started_unix_ms)
                .map(|operation| operation.id.clone());
            let Some(oldest_terminal) = oldest_terminal else {
                return Err(format!(
                    "operation retention limit ({MAX_RETAINED_OPERATIONS}) reached"
                ));
            };
            operations.remove(&oldest_terminal);
        }
        operations.insert(
            id.to_owned(),
            Operation {
                id: id.to_owned(),
                owner_session: self.session_id.clone(),
                scope_id: scope_id.to_owned(),
                kind: "scope_remove".into(),
                state: OperationState::Queued,
                started_unix_ms: now_ms(),
                finished_unix_ms: None,
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                cancel: None,
            },
        );
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn start_scope_removal(&self, scope_id: &str) -> ToolResponse {
        if let Err(error) = self.config.validate_scope_root() {
            return ToolResponse::failure(error);
        }
        let Some(root) = self.config.generated_scope_root.clone() else {
            return ToolResponse::failure("scope_remove is unavailable in legacy --home mode");
        };
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return ToolResponse::failure(
                "MCP operation capacity is busy; retry after an active operation completes",
            );
        };
        let lifecycle = Arc::clone(
            self.lifecycles
                .lock()
                .await
                .entry(scope_id.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        );
        let lifecycle_entry = Arc::clone(&lifecycle);
        let Ok(admission) = lifecycle.try_lock_owned() else {
            return ToolResponse::failure(
                "this development scope is busy; retry after its active lifecycle operation completes",
            );
        };
        let access = Arc::clone(
            self.scope_access
                .lock()
                .await
                .entry(scope_id.to_owned())
                .or_insert_with(|| Arc::new(RwLock::new(()))),
        );
        let access_entry = Arc::clone(&access);
        let Ok(access_admission) = access.try_write_owned() else {
            return ToolResponse::failure(
                "development scope has an active read and cannot be removed",
            );
        };
        let id = Uuid::new_v4().to_string();
        let scope = {
            let mut scopes = self.scopes.lock().await;
            let Some(scope) = scopes.get(scope_id).cloned() else {
                return ToolResponse::failure("unknown development scope");
            };
            if !matches!(scope.state, ScopeState::Stopped | ScopeState::Removing) {
                return ToolResponse::failure(
                    "only a generated stopped or removing development scope can be removed",
                );
            }
            if scope.home.parent() != Some(root.as_path())
                || scope.home.file_name().and_then(|name| name.to_str()) != Some(scope_id)
            {
                return ToolResponse::failure(
                    "development scope home is not the exact derived child of its fixed root",
                );
            }
            if scope.home.exists() {
                if let Err(error) = scope.validate_home() {
                    return ToolResponse::failure(error);
                }
            } else if scope.state != ScopeState::Removing {
                return ToolResponse::failure("stopped development scope home is missing");
            }
            if self.operations.lock().await.values().any(|operation| {
                operation.scope_id == scope_id
                    && matches!(
                        operation.state,
                        OperationState::Queued | OperationState::Running
                    )
            }) {
                return ToolResponse::failure(
                    "development scope has active MCP work and cannot be removed",
                );
            }

            if let Err(error) = self.insert_removal_operation(&id, scope_id).await {
                return ToolResponse::failure(error);
            }
            let registered = scopes.get_mut(scope_id).expect("scope exists");
            registered.state = ScopeState::Removing;
            registered.last_operation_id = Some(id.clone());
            registered.diagnostic = None;
            if let Err(error) = self.config.persist_scopes(&scopes) {
                self.operations.lock().await.remove(&id);
                scopes.insert(scope_id.to_owned(), scope.clone());
                return ToolResponse::failure(error);
            }
            scope
        };

        tokio::spawn(run_scope_removal_task(
            permit,
            admission,
            access_admission,
            Arc::clone(&self.scopes),
            Arc::clone(&self.operations),
            Arc::clone(&self.lifecycles),
            Arc::clone(&self.scope_access),
            root,
            self.config.preserved_registry_records.clone(),
            scope,
            id.clone(),
            scope_id.to_owned(),
            lifecycle_entry,
            access_entry,
        ));
        ToolResponse::success(json!({"operation_id": id, "state": "queued"}))
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_scope_removal_task(
    _permit: OwnedSemaphorePermit,
    admission: OwnedMutexGuard<()>,
    _access_admission: OwnedRwLockWriteGuard<()>,
    scopes: Arc<Mutex<BTreeMap<String, DevelopmentScope>>>,
    operations: Arc<Mutex<BTreeMap<String, Operation>>>,
    lifecycles: Arc<Mutex<BTreeMap<String, Arc<Mutex<()>>>>>,
    scope_access: Arc<Mutex<BTreeMap<String, Arc<RwLock<()>>>>>,
    root: PathBuf,
    preserved_registry_records: BTreeMap<String, Value>,
    scope: DevelopmentScope,
    task_id: String,
    task_scope_id: String,
    lifecycle_entry: Arc<Mutex<()>>,
    access_entry: Arc<RwLock<()>>,
) {
    set_running(&operations, &task_id).await;
    let removed = remove_exact_scope_home(&scope.home, &scope.home_identity);
    let mut result = match removed {
        Ok(()) => Ok(CapturedOutput {
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        }),
        Err(error) => Err(error),
    };
    let mut registered = scopes.lock().await;
    if result.is_ok() {
        let removed_scope = registered.remove(&task_scope_id);
        if let Err(error) = persist_scope_registry(&root, &registered, &preserved_registry_records)
        {
            if let Some(scope) = removed_scope {
                registered.insert(task_scope_id.clone(), scope);
            }
            result = Err(error);
        }
    } else if let Some(registered_scope) = registered.get_mut(&task_scope_id) {
        registered_scope.diagnostic = Some(lifecycle_diagnostic(&result));
        let _ = persist_scope_registry(&root, &registered, &preserved_registry_records);
    }
    let succeeded = result.is_ok();
    drop(registered);
    finish_operation(&operations, &task_id, result).await;
    drop(admission);
    if succeeded {
        let mut registered_lifecycles = lifecycles.lock().await;
        if registered_lifecycles
            .get(&task_scope_id)
            .is_some_and(|current| Arc::ptr_eq(current, &lifecycle_entry))
        {
            registered_lifecycles.remove(&task_scope_id);
        }
        let mut registered_access = scope_access.lock().await;
        if registered_access
            .get(&task_scope_id)
            .is_some_and(|current| Arc::ptr_eq(current, &access_entry))
        {
            registered_access.remove(&task_scope_id);
        }
    }
}

fn remove_exact_scope_home(home: &Path, expected: &DirectoryIdentity) -> Result<(), String> {
    remove_exact_scope_home_with_limits(
        home,
        expected,
        MAX_SCOPE_REMOVAL_ENTRIES,
        MAX_SCOPE_REMOVAL_DEPTH,
    )
}

#[allow(clippy::too_many_lines)]
fn remove_exact_scope_home_with_limits(
    home: &Path,
    expected: &DirectoryIdentity,
    max_entries: usize,
    max_depth: usize,
) -> Result<(), String> {
    match fs::symlink_metadata(home) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot inspect development scope home: {error}")),
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err("development scope home is no longer a directory".into());
        }
        Ok(_) => {}
    }
    let current = DirectoryIdentity::capture(home)?;
    if &current != expected {
        return Err("development scope home identity changed before removal".into());
    }
    let mut pending = vec![(home.to_path_buf(), 0_usize)];
    let mut leaves = Vec::new();
    let mut directories = Vec::new();
    let expected_uid = rustix::process::geteuid().as_raw();
    let mut entry_count = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        if depth > max_depth {
            return Err(format!(
                "development scope home removal exceeds the bounded depth limit ({max_depth})"
            ));
        }
        directories.push(directory.clone());
        let entries = fs::read_dir(&directory).map_err(|error| {
            format!(
                "cannot inspect development scope directory {} before removal: {error}",
                directory.display()
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "cannot inspect development scope directory entry {}: {error}",
                    directory.display()
                )
            })?;
            entry_count = entry_count.saturating_add(1);
            if entry_count > max_entries {
                return Err(format!(
                    "development scope home removal exceeds the bounded entry limit ({max_entries})"
                ));
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                format!(
                    "cannot inspect development scope entry {}: {error}",
                    path.display()
                )
            })?;
            if metadata.uid() != expected_uid {
                return Err(format!(
                    "development scope entry has unexpected owner: {}",
                    path.display()
                ));
            }
            if metadata.file_type().is_dir() {
                pending.push((path, depth.saturating_add(1)));
            } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                leaves.push((path, metadata.file_type().is_symlink()));
            } else {
                return Err(format!(
                    "development scope home contains an unsupported special entry: {}",
                    path.display()
                ));
            }
        }
    }
    // The complete no-follow preflight above bounds the work before mutation.
    // A same-user replacement during deletion fails closed on the repeated
    // file-type check and leaves the durable Removing record retryable.
    for (path, expected_symlink) in leaves {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "cannot revalidate development scope file {}: {error}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() != expected_symlink
            || (!expected_symlink && !metadata.file_type().is_file())
            || metadata.uid() != expected_uid
        {
            return Err(format!(
                "development scope file changed during bounded removal: {}",
                path.display()
            ));
        }
        fs::remove_file(&path).map_err(|error| {
            format!(
                "cannot remove development scope file {}: {error}",
                path.display()
            )
        })?;
    }
    for path in directories.into_iter().rev() {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "cannot revalidate development scope directory {}: {error}",
                path.display()
            )
        })?;
        if !metadata.file_type().is_dir() || metadata.uid() != expected_uid {
            return Err(format!(
                "development scope directory changed during bounded removal: {}",
                path.display()
            ));
        }
        fs::remove_dir(&path).map_err(|error| {
            format!(
                "cannot remove development scope directory {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn live_generated_scope_count(scopes: &BTreeMap<String, DevelopmentScope>) -> usize {
    scopes
        .iter()
        .filter(|(scope_id, scope)| {
            scope_id.as_str() != "default"
                && matches!(
                    scope.state,
                    ScopeState::Starting
                        | ScopeState::Ready
                        | ScopeState::Resetting
                        | ScopeState::Stopping
                        | ScopeState::Failed
                )
        })
        .count()
}

fn bounded_diagnostic(message: &str) -> String {
    const MAX_DIAGNOSTIC_BYTES: usize = 4096;
    if message.len() <= MAX_DIAGNOSTIC_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_DIAGNOSTIC_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_owned()
}

fn lifecycle_diagnostic(result: &Result<CapturedOutput, String>) -> String {
    match result {
        Err(error) => bounded_diagnostic(error),
        Ok(output) => {
            let bytes = if output.stderr.is_empty() {
                &output.stdout
            } else {
                &output.stderr
            };
            if bytes.is_empty() {
                format!(
                    "scope lifecycle command failed with exit code {}",
                    output
                        .exit_code
                        .map_or_else(|| "unknown".into(), |code| code.to_string())
                )
            } else {
                bounded_diagnostic(&String::from_utf8_lossy(bytes))
            }
        }
    }
}

#[tool_router]
impl HostMcp {
    #[tool(
        description = "Inspect the fixed MCP workspace/home/executable scope without exposing credentials or daemon relay authority."
    )]
    async fn doctor(&self, Parameters(_request): Parameters<EmptyRequest>) -> Json<ToolResponse> {
        Json(ToolResponse::success(json!({
            "schema": "marsh.mcp.doctor/v1",
            "workspace": self.config.workspace,
            "home": self.config.home,
            "generated_scope_root": self.config.generated_scope_root,
            "marsh": self.config.marsh,
            "marshd": self.config.marshd,
            "sbx": self.config.sbx,
            "max_concurrent_operations": MAX_OPERATIONS,
            "max_retained_operations": MAX_RETAINED_OPERATIONS,
            "max_live_generated_scopes": MAX_DEVELOPMENT_SCOPES,
            "max_retained_generated_scopes": MAX_RETAINED_SCOPES,
            "max_capture_bytes_per_stream": MAX_CAPTURE_BYTES,
            "full_sbx_control_enabled": self.config.full_sbx_control_enabled,
            "managed_scope_persistence": self.config.generated_scope_root.is_some(),
            "workspace_write_isolation": "shared",
            "registry_diagnostics": self.config.registry_diagnostics,
            "relay_environment_forwarded": false
        })))
    }

    #[tool(
        description = "Return typed marsh daemon, project-shell, and Kit-worker status for this selected home."
    )]
    async fn status(&self, Parameters(_request): Parameters<EmptyRequest>) -> Json<ToolResponse> {
        Json(
            self.run_json(&["status", "--json"], Duration::from_secs(20))
                .await,
        )
    }

    #[tool(
        description = "List durable structural marsh result receipts newest first; captured prompts and output are not included."
    )]
    async fn results_list(
        &self,
        Parameters(_request): Parameters<EmptyRequest>,
    ) -> Json<ToolResponse> {
        Json(
            self.run_json(&["results", "--json"], Duration::from_secs(20))
                .await,
        )
    }

    #[tool(
        description = "Get one durable structural result by cursor, full job UUID, or unique UUID prefix."
    )]
    async fn result_get(
        &self,
        Parameters(request): Parameters<ResultGetRequest>,
    ) -> Json<ToolResponse> {
        if let Err(error) = validate_selector(&request.selector) {
            return Json(ToolResponse::failure(error));
        }
        Json(
            self.run_json(
                &["results", "show", &request.selector, "--json"],
                Duration::from_secs(20),
            )
            .await,
        )
    }

    #[tool(
        description = "List durable structural result receipts for one exact development scope. Ready and Stopped scopes are supported; reading a Stopped scope may start only its local daemon and never boots its project-shell or Kit VMs."
    )]
    async fn scope_results_list(
        &self,
        Parameters(request): Parameters<ScopeRequest>,
    ) -> Json<ToolResponse> {
        let scope = match self.readable_results_scope(&request.scope_id).await {
            Ok(scope) => scope,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        Json(match scope.state {
            ScopeState::Stopped => {
                self.run_stopped_results_in(&request.scope_id, &scope, &["results", "--json"])
                    .await
            }
            ScopeState::Ready => {
                self.run_json_in(
                    &request.scope_id,
                    &scope,
                    &["results", "--json"],
                    Duration::from_secs(20),
                )
                .await
            }
            _ => unreachable!("readable_results_scope restricts state"),
        })
    }

    #[tool(
        description = "Get one durable structural result from one exact development scope by cursor, full job UUID, or unique UUID prefix. Ready and Stopped scopes are supported without booting a VM."
    )]
    async fn scope_result_get(
        &self,
        Parameters(request): Parameters<ScopeResultGetRequest>,
    ) -> Json<ToolResponse> {
        if let Err(error) = validate_selector(&request.selector) {
            return Json(ToolResponse::failure(error));
        }
        let scope = match self.readable_results_scope(&request.scope_id).await {
            Ok(scope) => scope,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        let arguments = ["results", "show", request.selector.as_str(), "--json"];
        Json(match scope.state {
            ScopeState::Stopped => {
                self.run_stopped_results_in(&request.scope_id, &scope, &arguments)
                    .await
            }
            ScopeState::Ready => {
                self.run_json_in(
                    &request.scope_id,
                    &scope,
                    &arguments,
                    Duration::from_secs(20),
                )
                .await
            }
            _ => unreachable!("readable_results_scope restricts state"),
        })
    }

    #[tool(
        description = "Prewarm `all` or an explicit comma-separated set of configured Kit worker VMs. Returns an operation ID."
    )]
    async fn prewarm(
        &self,
        Parameters(request): Parameters<SelectionRequest>,
    ) -> Json<ToolResponse> {
        let scope = match self.active_scope("default").await {
            Ok(scope) => scope,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        if let Err(error) = validate_selection(&request.selection) {
            return Json(ToolResponse::failure(error));
        }
        let spec = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec![
                "--load".into(),
                request.selection,
                "-c".into(),
                "true".into(),
            ],
            timeout: Duration::from_mins(5),
            home: scope.home,
            home_identity: scope.home_identity,
        };
        Json(
            self.start_operation("default", "prewarm", spec, Vec::new(), true)
                .await,
        )
    }

    #[tool(
        description = "Reset only selected idle marsh-owned Kit worker VMs. Active jobs and unrelated Sandboxes are preserved. Returns an operation ID."
    )]
    async fn workers_reset(
        &self,
        Parameters(request): Parameters<SelectionRequest>,
    ) -> Json<ToolResponse> {
        let scope = match self.active_scope("default").await {
            Ok(scope) => scope,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        if let Err(error) = validate_selection(&request.selection) {
            return Json(ToolResponse::failure(error));
        }
        let spec = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec!["workers".into(), "reset".into(), request.selection],
            timeout: Duration::from_mins(5),
            home: scope.home,
            home_identity: scope.home_identity,
        };
        Json(
            self.start_operation("default", "workers_reset", spec, Vec::new(), true)
                .await,
        )
    }

    #[tool(
        description = "Prewarm `all` or selected configured Kit worker VMs in one exact Ready development scope. Independent read-only inspection remains available while prewarm runs. Returns an operation ID."
    )]
    async fn scope_prewarm(
        &self,
        Parameters(request): Parameters<ScopeSelectionRequest>,
    ) -> Json<ToolResponse> {
        let scope = match self.active_scope(&request.scope_id).await {
            Ok(scope) => scope,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        if let Err(error) = validate_selection(&request.selection) {
            return Json(ToolResponse::failure(error));
        }
        let spec = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec![
                "--load".into(),
                request.selection,
                "-c".into(),
                "true".into(),
            ],
            timeout: Duration::from_mins(5),
            home: scope.home,
            home_identity: scope.home_identity,
        };
        Json(
            self.start_operation(&request.scope_id, "scope_prewarm", spec, Vec::new(), true)
                .await,
        )
    }

    #[tool(
        description = "Reset selected idle Kit worker VMs in one exact Ready development scope. Project shell, peer scopes, and unrelated Sandboxes are preserved. Returns an operation ID."
    )]
    async fn scope_workers_reset(
        &self,
        Parameters(request): Parameters<ScopeSelectionRequest>,
    ) -> Json<ToolResponse> {
        let scope = match self.active_scope(&request.scope_id).await {
            Ok(scope) => scope,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        if let Err(error) = validate_selection(&request.selection) {
            return Json(ToolResponse::failure(error));
        }
        let spec = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec!["workers".into(), "reset".into(), request.selection],
            timeout: Duration::from_mins(5),
            home: scope.home,
            home_identity: scope.home_identity,
        };
        Json(
            self.start_operation(
                &request.scope_id,
                "scope_workers_reset",
                spec,
                Vec::new(),
                true,
            )
            .await,
        )
    }

    #[tool(
        description = "Run a bounded shell program inside the scoped marsh project-shell VM. There is no host-shell, environment, SBX, or Docker passthrough. Returns an operation ID."
    )]
    async fn shell_run(
        &self,
        Parameters(request): Parameters<ShellRunRequest>,
    ) -> Json<ToolResponse> {
        let scope = match self.active_scope("default").await {
            Ok(scope) => scope,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        if request.command.is_empty()
            || request.command.len() > MAX_COMMAND_BYTES
            || request.command.contains('\0')
        {
            return Json(ToolResponse::failure(format!(
                "command must contain 1..={MAX_COMMAND_BYTES} bytes and no NUL"
            )));
        }
        let timeout = match bounded_timeout(request.timeout_ms) {
            Ok(timeout) => timeout,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        let spec = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec!["-c".into(), request.command],
            timeout,
            home: scope.home,
            home_identity: scope.home_identity,
        };
        Json(
            self.start_operation("default", "shell_run", spec, Vec::new(), false)
                .await,
        )
    }

    #[tool(
        description = "Create an isolated development scope for this fixed workspace. The server chooses the opaque ID and private home, then boots its project shell. All scopes mount the same canonical project workspace, so concurrent writes are shared and may race. Returns the scope and operation IDs."
    )]
    async fn scope_start(
        &self,
        Parameters(_request): Parameters<EmptyRequest>,
    ) -> Json<ToolResponse> {
        if let Err(error) = self.config.validate_scope_root() {
            return Json(ToolResponse::failure(error));
        }
        let Some(root) = self.config.generated_scope_root.as_ref() else {
            return Json(ToolResponse::failure(
                "scope_start is unavailable in legacy --home mode; start the server with --scope-root or omit both options",
            ));
        };
        let scope_id = Uuid::new_v4().to_string();
        let home = match prepare_scope_home(root, &scope_id) {
            Ok(home) => home,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        let home_identity = match DirectoryIdentity::capture(&home) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = fs::remove_dir(&home);
                return Json(ToolResponse::failure(error));
            }
        };
        {
            let mut scopes = self.scopes.lock().await;
            if live_generated_scope_count(&scopes) >= MAX_DEVELOPMENT_SCOPES {
                let _ = fs::remove_dir(&home);
                return Json(ToolResponse::failure(format!(
                    "development scope limit ({MAX_DEVELOPMENT_SCOPES}) reached; stop and remove an unused scope first"
                )));
            }
            if scopes
                .len()
                .saturating_sub(1)
                .saturating_add(self.config.preserved_registry_records.len())
                >= MAX_RETAINED_SCOPES
            {
                let _ = fs::remove_dir(&home);
                return Json(ToolResponse::failure(format!(
                    "retained development scope limit ({MAX_RETAINED_SCOPES}) reached"
                )));
            }
            scopes.insert(
                scope_id.clone(),
                DevelopmentScope {
                    home: home.clone(),
                    home_identity: home_identity.clone(),
                    state: ScopeState::Starting,
                    created_unix_ms: now_ms(),
                    last_operation_id: None,
                    diagnostic: None,
                },
            );
            if let Err(error) = self.config.persist_scopes(&scopes) {
                scopes.remove(&scope_id);
                let _ = fs::remove_dir(&home);
                return Json(ToolResponse::failure(error));
            }
        }
        let spec = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec!["-c".into(), "true".into()],
            timeout: Duration::from_mins(5),
            home: home.clone(),
            home_identity,
        };
        let mut response = self
            .start_operation(&scope_id, "scope_start", spec, Vec::new(), true)
            .await;
        if response.ok {
            response.data = response.data.map(|mut value| {
                value["scope_id"] = Value::String(scope_id);
                value
            });
        } else {
            let mut scopes = self.scopes.lock().await;
            scopes.remove(&scope_id);
            let _ = self.config.persist_scopes(&scopes);
            let _ = fs::remove_dir(&home);
        }
        Json(response)
    }

    #[tool(
        description = "List managed development scopes by opaque ID, lifecycle state, and creation time. Host paths and runtime identities are never returned."
    )]
    async fn scope_list(
        &self,
        Parameters(_request): Parameters<EmptyRequest>,
    ) -> Json<ToolResponse> {
        if let Err(error) = self.config.validate_scope_root() {
            return Json(ToolResponse::failure(error));
        }
        let scopes = self.scopes.lock().await;
        let entries = scopes
            .iter()
            .map(|(scope_id, scope)| {
                json!({
                    "scope_id": scope_id,
                    "state": scope.state,
                    "created_unix_ms": scope.created_unix_ms
                })
            })
            .collect::<Vec<_>>();
        Json(ToolResponse::success(json!({
            "schema": "marsh.mcp.scope-list/v1",
            "scopes": entries
        })))
    }

    #[tool(
        description = "Queue removal of one generated stopped scope and its private home, or resume an interrupted persisted removal. Default, live, and failed scopes are rejected."
    )]
    async fn scope_remove(
        &self,
        Parameters(request): Parameters<ScopeRequest>,
    ) -> Json<ToolResponse> {
        if let Err(error) = self.config.validate_scope_root() {
            return Json(ToolResponse::failure(error));
        }
        if request.scope_id == "default" {
            return Json(ToolResponse::failure(
                "the default development scope cannot be removed",
            ));
        }
        if let Err(error) = validate_scope_id(&request.scope_id) {
            return Json(ToolResponse::failure(error));
        }
        Json(self.start_scope_removal(&request.scope_id).await)
    }

    #[tool(
        description = "Run a bounded shell program in one exact isolated development scope. Returns an operation ID."
    )]
    async fn scope_run(
        &self,
        Parameters(request): Parameters<ScopeRunRequest>,
    ) -> Json<ToolResponse> {
        let scope = match self.active_scope(&request.scope_id).await {
            Ok(scope) => scope,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        if request.command.is_empty()
            || request.command.len() > MAX_COMMAND_BYTES
            || request.command.contains('\0')
        {
            return Json(ToolResponse::failure(format!(
                "command must contain 1..={MAX_COMMAND_BYTES} bytes and no NUL"
            )));
        }
        let timeout = match bounded_timeout(request.timeout_ms) {
            Ok(timeout) => timeout,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        let spec = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec!["-c".into(), request.command],
            timeout,
            home: scope.home,
            home_identity: scope.home_identity,
        };
        Json(
            self.start_operation(&request.scope_id, "scope_run", spec, Vec::new(), false)
                .await,
        )
    }

    #[tool(
        description = "Inspect one exact isolated development scope and its marsh runtime state."
    )]
    async fn scope_status(
        &self,
        Parameters(request): Parameters<ScopeRequest>,
    ) -> Json<ToolResponse> {
        if let Err(error) = validate_scope_id(&request.scope_id) {
            return Json(ToolResponse::failure(error));
        }
        let scope = {
            let scopes = self.scopes.lock().await;
            scopes.get(&request.scope_id).cloned()
        };
        let Some(scope) = scope else {
            return Json(ToolResponse::failure("unknown development scope"));
        };
        if scope.state != ScopeState::Failed {
            if scope.home.exists() {
                if let Err(error) = scope.validate_home() {
                    return Json(ToolResponse::failure(error));
                }
            } else if scope.state != ScopeState::Removing {
                return Json(ToolResponse::failure("development scope home is missing"));
            }
        }
        if scope.state != ScopeState::Ready {
            let runtime_state = match scope.state {
                ScopeState::Stopped => "absent",
                ScopeState::Failed => "unknown",
                ScopeState::Starting
                | ScopeState::Resetting
                | ScopeState::Stopping
                | ScopeState::Removing => "transitioning",
                ScopeState::Ready => unreachable!(),
            };
            return Json(ToolResponse::success(json!({
                "schema": "marsh.mcp.scope-status/v1",
                "scope_id": request.scope_id,
                "state": scope.state,
                "runtime_state": runtime_state,
                "created_unix_ms": scope.created_unix_ms,
                "last_operation_id": scope.last_operation_id,
                "diagnostic": scope.diagnostic,
                "runtime": null
            })));
        }
        let runtime = self
            .run_json_in(
                &request.scope_id,
                &scope,
                &["status", "--json"],
                Duration::from_secs(20),
            )
            .await;
        Json(if runtime.ok {
            ToolResponse::success(json!({
                "schema": "marsh.mcp.scope-status/v1",
                "scope_id": request.scope_id,
                "state": scope.state,
                "runtime_state": "ready",
                "created_unix_ms": scope.created_unix_ms,
                "last_operation_id": scope.last_operation_id,
                "diagnostic": scope.diagnostic,
                "runtime": runtime.data
            }))
        } else {
            runtime
        })
    }

    #[tool(
        description = "Reset one exact idle development scope, preserving its home and structural results, then recreate its project shell. Refuses active work. Returns an operation ID."
    )]
    async fn scope_reset(
        &self,
        Parameters(request): Parameters<ScopeRequest>,
    ) -> Json<ToolResponse> {
        let scope = match self.resettable_scope(&request.scope_id).await {
            Ok(scope) => scope,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        let boot = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec!["-c".into(), "true".into()],
            timeout: Duration::from_mins(5),
            home: scope.home.clone(),
            home_identity: scope.home_identity.clone(),
        };
        let cleanup = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec!["reset".into(), "--json".into()],
            timeout: SCOPE_LIFECYCLE_TIMEOUT,
            home: scope.home,
            home_identity: scope.home_identity,
        };
        let (spec, followups) = match scope.state {
            ScopeState::Stopped => (boot, Vec::new()),
            ScopeState::Ready | ScopeState::Failed => (boot.clone(), vec![cleanup, boot]),
            _ => unreachable!("resettable_scope rejects transitional states"),
        };
        Json(
            self.start_operation(&request.scope_id, "scope_reset", spec, followups, true)
                .await,
        )
    }

    #[tool(
        description = "Stop one exact idle development scope without deleting its home or results. It first boots or validates that scope's daemon, then sends the exact typed stop control to remove its project shell and Kit VMs and stop the daemon. Refuses active work. Returns an operation ID."
    )]
    async fn scope_stop(
        &self,
        Parameters(request): Parameters<ScopeRequest>,
    ) -> Json<ToolResponse> {
        let scope = match self.active_scope(&request.scope_id).await {
            Ok(scope) => scope,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        let boot = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec!["-c".into(), "true".into()],
            timeout: Duration::from_mins(5),
            home: scope.home.clone(),
            home_identity: scope.home_identity.clone(),
        };
        let stop = CommandSpec {
            executable: self.config.marsh.clone(),
            arguments: vec!["stop".into(), "--json".into()],
            timeout: SCOPE_LIFECYCLE_TIMEOUT,
            home: scope.home,
            home_identity: scope.home_identity,
        };
        Json(
            self.start_operation(&request.scope_id, "scope_stop", boot, vec![stop], true)
                .await,
        )
    }

    #[tool(
        description = "Use the full-SBX-control capability to start one fixed repository qualification gate: source, smoke, full, or perf. Arbitrary make targets, variables, and host commands are rejected. Returns an operation ID."
    )]
    async fn qualify(&self, Parameters(request): Parameters<QualifyRequest>) -> Json<ToolResponse> {
        if !self.config.full_sbx_control_enabled {
            return Json(ToolResponse::failure(
                "full SBX control is disabled; restart marsh-mcp with --allow-full-sbx-control to enable fixed repository gates",
            ));
        }
        let scope = match self.active_scope("default").await {
            Ok(scope) => scope,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        let target = match request.gate.as_str() {
            "source" => "test",
            "smoke" => "acceptance-smoke",
            "full" => "acceptance",
            "perf" => "perf",
            _ => {
                return Json(ToolResponse::failure(
                    "gate must be one of: source, smoke, full, perf",
                ));
            }
        };
        let timeout = match bounded_timeout(request.timeout_ms.or(Some(MAX_TIMEOUT_MS))) {
            Ok(timeout) => timeout,
            Err(error) => return Json(ToolResponse::failure(error)),
        };
        let spec = CommandSpec {
            executable: self.config.make.clone(),
            arguments: vec![target.into()],
            timeout,
            home: scope.home,
            home_identity: scope.home_identity,
        };
        Json(
            self.start_operation(
                "default",
                &format!("qualify:{target}"),
                spec,
                Vec::new(),
                true,
            )
            .await,
        )
    }

    #[tool(description = "Inspect state and bounded output sizes for an MCP-started operation.")]
    async fn operation_get(
        &self,
        Parameters(request): Parameters<OperationRequest>,
    ) -> Json<ToolResponse> {
        if let Err(error) = validate_operation_id(&request.operation_id) {
            return Json(ToolResponse::failure(error));
        }
        let operations = self.operations.lock().await;
        Json(match operations.get(&request.operation_id) {
            Some(operation) if operation.owner_session == self.session_id => ToolResponse::success(
                serde_json::to_value(operation.view()).expect("operation view serializes"),
            ),
            Some(_) => ToolResponse::failure("unknown operation ID for this MCP session"),
            None => ToolResponse::failure("unknown operation ID"),
        })
    }

    #[tool(
        description = "Read bounded stdout and stderr for an MCP-started operation. Output is available after it reaches a terminal state."
    )]
    async fn operation_output(
        &self,
        Parameters(request): Parameters<OperationRequest>,
    ) -> Json<ToolResponse> {
        if let Err(error) = validate_operation_id(&request.operation_id) {
            return Json(ToolResponse::failure(error));
        }
        let operations = self.operations.lock().await;
        Json(match operations.get(&request.operation_id) {
            Some(operation) if operation.owner_session != self.session_id => {
                ToolResponse::failure("unknown operation ID for this MCP session")
            }
            Some(operation)
                if matches!(
                    operation.state,
                    OperationState::Queued | OperationState::Running
                ) =>
            {
                ToolResponse::failure("operation output is available after completion")
            }
            Some(operation) => ToolResponse::success(json!({
                "operation": operation.view(),
                "stdout": encoded_stream(&operation.stdout),
                "stderr": encoded_stream(&operation.stderr)
            })),
            None => ToolResponse::failure("unknown operation ID"),
        })
    }

    #[tool(
        description = "Cancel one queued or running MCP-started operation. The child process is killed on cancellation."
    )]
    async fn operation_cancel(
        &self,
        Parameters(request): Parameters<OperationRequest>,
    ) -> Json<ToolResponse> {
        if let Err(error) = validate_operation_id(&request.operation_id) {
            return Json(ToolResponse::failure(error));
        }
        let mut operations = self.operations.lock().await;
        let Some(operation) = operations.get_mut(&request.operation_id) else {
            return Json(ToolResponse::failure("unknown operation ID"));
        };
        if operation.owner_session != self.session_id {
            return Json(ToolResponse::failure(
                "unknown operation ID for this MCP session",
            ));
        }
        if matches!(
            operation.state,
            OperationState::Succeeded
                | OperationState::Failed
                | OperationState::CancellationUncertain
        ) {
            return Json(ToolResponse::success(
                json!({"operation": operation.view(), "cancelled": false}),
            ));
        }
        let signalled = operation
            .cancel
            .as_ref()
            .is_some_and(|cancel| cancel.send(true).is_ok());
        Json(ToolResponse::success(json!({
            "operation_id": request.operation_id,
            "cancel_requested": signalled
        })))
    }
}

// `ServerHandler` declares these methods async; some bodies have nothing to await.
#[allow(unknown_lints, clippy::unused_async_trait_impl)]
#[tool_handler(
    name = "marsh-host",
    version = "0.1.0",
    instructions = "Typed control of one canonical marsh workspace and selected home. Tools never expose raw host shell, Docker, SBX, arbitrary executables, environment injection, or daemon credentials."
)]
impl ServerHandler for HostMcp {}

async fn set_running(operations: &Mutex<BTreeMap<String, Operation>>, id: &str) {
    if let Some(operation) = operations.lock().await.get_mut(id) {
        operation.state = OperationState::Running;
    }
}

async fn finish_operation(
    operations: &Mutex<BTreeMap<String, Operation>>,
    id: &str,
    result: Result<CapturedOutput, String>,
) {
    let mut operations = operations.lock().await;
    let Some(operation) = operations.get_mut(id) else {
        return;
    };
    operation.finished_unix_ms = Some(now_ms());
    operation.cancel = None;
    match result {
        Ok(output) => {
            operation.exit_code = output.exit_code;
            operation.state = if output.exit_code == Some(0) {
                OperationState::Succeeded
            } else {
                OperationState::Failed
            };
            operation.stdout = output.stdout;
            operation.stderr = output.stderr;
            operation.stdout_truncated = output.stdout_truncated;
            operation.stderr_truncated = output.stderr_truncated;
        }
        Err(error) if error.starts_with("operation cancellation requested") => {
            operation.state = OperationState::CancellationUncertain;
            operation.stderr = error.into_bytes();
        }
        Err(error) => {
            operation.state = OperationState::Failed;
            operation.stderr = error.into_bytes();
        }
    }
}

fn command_failure(name: &str, output: &CapturedOutput) -> String {
    let detail = String::from_utf8_lossy(&output.stderr);
    format!(
        "{name} exited with {}: {}",
        output
            .exit_code
            .map_or_else(|| "signal".into(), |code| code.to_string()),
        detail.trim()
    )
}

fn encoded_stream(bytes: &[u8]) -> Value {
    json!({
        "byte_length": bytes.len(),
        "sha256": marsh_contracts::process::hex(&Sha256::digest(bytes)),
        "base64": BASE64.encode(bytes)
    })
}

fn bounded_timeout(value: Option<u64>) -> Result<Duration, String> {
    let milliseconds = value.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(10..=MAX_TIMEOUT_MS).contains(&milliseconds) {
        return Err(format!(
            "timeout_ms must be between 10 and {MAX_TIMEOUT_MS}"
        ));
    }
    Ok(Duration::from_millis(milliseconds))
}

fn validate_selection(selection: &str) -> Result<(), String> {
    if selection == "all" {
        return Ok(());
    }
    let kits: Vec<_> = selection.split(',').collect();
    if selection.is_empty()
        || selection.len() > 1024
        || kits.len() > 16
        || kits.into_iter().any(|kit| {
            kit.is_empty()
                || kit.len() > 64
                || !kit
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err("selection must be `all` or comma-separated lowercase Kit names".into());
    }
    Ok(())
}

fn validate_operation_id(operation_id: &str) -> Result<(), String> {
    if operation_id.len() > 128 || Uuid::parse_str(operation_id).is_err() {
        return Err("operation_id must be a UUID no longer than 128 bytes".into());
    }
    Ok(())
}

fn validate_scope_id(scope_id: &str) -> Result<(), String> {
    if scope_id == "default"
        || Uuid::parse_str(scope_id).is_ok_and(|parsed| parsed.to_string() == scope_id)
    {
        return Ok(());
    }
    Err("scope_id must be `default` or the canonical lowercase UUID returned by scope_start".into())
}

fn validate_selector(selector: &str) -> Result<(), String> {
    if selector.is_empty()
        || selector.len() > 64
        || !selector
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err("selector must be a cursor, UUID, or UUID prefix".into());
    }
    Ok(())
}

fn prepare_home(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("home must be an absolute path".into());
    }
    let product_root = mcp_product_root(path);
    if let Some(product_root) = product_root {
        let host_home = product_root.parent();
        for directory in path
            .ancestors()
            .take_while(|directory| Some(*directory) != host_home)
        {
            match fs::symlink_metadata(directory) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(format!(
                        "MCP control directory must not be a symlink: {}",
                        directory.display()
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("cannot inspect MCP control directory: {error}")),
            }
        }
        if fs::symlink_metadata(product_root).is_ok() {
            validate_mcp_product_root(product_root)?;
        }
    }
    if !path.exists() {
        let resolved = resolve_without_creation(path)?;
        let mut missing = Vec::new();
        let mut current = resolved.as_path();
        while !current.exists() {
            missing.push(current.to_path_buf());
            current = current
                .parent()
                .ok_or_else(|| format!("cannot find MCP home parent: {}", path.display()))?;
        }
        for directory in missing.into_iter().rev() {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|error| {
                    format!("cannot create MCP home {}: {error}", directory.display())
                })?;
        }
    }
    if let Some(product_root) = product_root {
        validate_mcp_product_root(product_root)?;
    }
    let canonical = canonical_directory(path, "home")?;
    let metadata = canonical
        .metadata()
        .map_err(|error| format!("cannot inspect MCP home: {error}"))?;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err("MCP home must be owned by the current user".into());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("MCP home must not be accessible by group or other users".into());
    }
    Ok(canonical)
}

fn validate_mcp_product_root(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect MCP product directory {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(format!(
            "MCP product directory must be a real, current-user-owned mode 0700 directory: {}; inspect it and repair its permissions before retrying",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn prepare_scope_root(path: &Path) -> Result<PathBuf, String> {
    prepare_home(path).map_err(|error| format!("invalid development scope root: {error}"))
}

fn acquire_scope_root_lease(root: &Path) -> Result<Arc<ScopeRootLease>, String> {
    let path = root.join("control.lock");
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    let mut file = options
        .open(&path)
        .map_err(|error| format!("cannot open development-control lease: {error}"))?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect development-control lease: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("development-control lease must be an owner-only regular file".into());
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |error| {
            format!(
                "development scope root is already controlled by another marsh-mcp process: {error}"
            )
        },
    )?;
    file.set_len(0)
        .and_then(|()| writeln!(file, "{}", std::process::id()))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot publish development-control lease owner: {error}"))?;
    Ok(Arc::new(ScopeRootLease { file }))
}

fn workspace_binding(workspace: &Path) -> Result<WorkspaceBinding, String> {
    let metadata = fs::symlink_metadata(workspace).map_err(|error| {
        format!(
            "cannot inspect canonical MCP workspace {}: {error}",
            workspace.display()
        )
    })?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "canonical MCP workspace is no longer a directory: {}",
            workspace.display()
        ));
    }
    Ok(WorkspaceBinding {
        version: 1,
        canonical_workspace: workspace.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn establish_workspace_binding(root: &Path, workspace: &Path) -> Result<(), String> {
    let path = root.join("workspace.json");
    let expected = workspace_binding(workspace)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(format!(
                    "development workspace binding must be an owner-only regular file: {}",
                    path.display()
                ));
            }
            if metadata.len() > MAX_WORKSPACE_BINDING_BYTES {
                return Err(format!(
                    "development workspace binding exceeds its size limit: {}",
                    path.display()
                ));
            }
            let bytes = fs::read(&path).map_err(|error| {
                format!(
                    "cannot read development workspace binding {}: {error}",
                    path.display()
                )
            })?;
            let actual: WorkspaceBinding = serde_json::from_slice(&bytes).map_err(|error| {
                format!(
                    "cannot decode development workspace binding {}: {error}",
                    path.display()
                )
            })?;
            if actual != expected {
                return Err(format!(
                    "development scope root is bound to a different canonical workspace identity: root={}, bound={}, requested={}",
                    root.display(),
                    actual.canonical_workspace.display(),
                    expected.canonical_workspace.display()
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut unexpected = Vec::new();
            for entry in fs::read_dir(root).map_err(|error| {
                format!(
                    "cannot inspect unbound development scope root {}: {error}",
                    root.display()
                )
            })? {
                let entry = entry.map_err(|error| {
                    format!(
                        "cannot inspect unbound development scope root {}: {error}",
                        root.display()
                    )
                })?;
                if entry.file_name() != "control.lock" {
                    unexpected.push(entry.file_name());
                }
            }
            if !unexpected.is_empty() {
                return Err(format!(
                    "development scope root has existing state but no workspace binding; refusing unsafe automatic migration: {} (select a new empty --scope-root or repair it explicitly)",
                    root.display()
                ));
            }
            let bytes = serde_json::to_vec_pretty(&expected)
                .map_err(|error| format!("cannot encode development workspace binding: {error}"))?;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            let mut file = options.open(&path).map_err(|error| {
                format!(
                    "cannot create development workspace binding {}: {error}",
                    path.display()
                )
            })?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| {
                    format!(
                        "cannot publish development workspace binding {}: {error}",
                        path.display()
                    )
                })?;
            fs::File::open(root)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    format!(
                        "cannot sync development workspace binding {}: {error}",
                        path.display()
                    )
                })
        }
        Err(error) => Err(format!(
            "cannot inspect development workspace binding {}: {error}",
            path.display()
        )),
    }
}

fn reap_stale_scope_registry_temps(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|error| {
        format!(
            "cannot inspect development scope root for stale registry files {}: {error}",
            root.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "cannot inspect development scope root for stale registry files {}: {error}",
                root.display()
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_suffix(".tmp") else {
            continue;
        };
        if !stem.starts_with(".scopes-") {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "cannot inspect stale scope registry {}: {error}",
                path.display()
            )
        })?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(format!(
                "stale scope registry must be an owner-only regular file before removal: {}",
                path.display()
            ));
        }
        fs::remove_file(&path).map_err(|error| {
            format!(
                "cannot remove stale scope registry {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn prepare_scope_home(root: &Path, scope_id: &str) -> Result<PathBuf, String> {
    validate_scope_id(scope_id)?;
    if scope_id == "default" {
        return Err("generated development scope ID cannot be `default`".into());
    }
    let candidate = root.join(scope_id);
    match fs::symlink_metadata(&candidate) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("development scope home must not be a symlink".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!("cannot inspect development scope home: {error}"));
        }
    }
    let home = prepare_home(&candidate)?;
    if home.parent() != Some(root) {
        return Err("development scope home escaped its fixed private root".into());
    }
    Ok(home)
}

fn load_scope_registry(root: &Path) -> Result<LoadedScopeRegistry, String> {
    let path = root.join("scopes.json");
    if !path.exists() {
        return Ok(LoadedScopeRegistry::default());
    }
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        format!(
            "cannot inspect development scope registry {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "development scope registry must be an owner-only regular file: {}",
            path.display()
        ));
    }
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "cannot read development scope registry {}: {error}",
            path.display()
        )
    })?;
    let records: BTreeMap<String, Value> = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "cannot decode development scope registry {}: {error}",
            path.display()
        )
    })?;
    if records.len() > MAX_RETAINED_SCOPES.saturating_add(1) {
        return Err(format!(
            "development scope registry exceeds its scope limit: {}",
            path.display()
        ));
    }
    let mut scopes = BTreeMap::new();
    let mut preserved_records = BTreeMap::new();
    let mut diagnostics = Vec::new();
    for (scope_id, record) in records {
        if scope_id != "default"
            && !Uuid::parse_str(&scope_id).is_ok_and(|parsed| parsed.to_string() == scope_id)
        {
            preserved_records.insert(scope_id, record);
            diagnostics.push(
                "a persisted scope record has an invalid or noncanonical ID; it was preserved but is unavailable until an operator repairs the owner-only registry"
                    .to_owned(),
            );
            continue;
        }
        let scope = serde_json::from_value::<DevelopmentScope>(record).unwrap_or_else(|error| {
            DevelopmentScope {
                home: PathBuf::new(),
                home_identity: DirectoryIdentity::default(),
                state: ScopeState::Failed,
                created_unix_ms: now_ms(),
                last_operation_id: None,
                diagnostic: Some(bounded_diagnostic(&format!(
                    "persisted scope record is malformed and was isolated: {error}"
                ))),
            }
        });
        scopes.insert(
            scope_id.clone(),
            reconcile_persisted_scope(root, &scope_id, scope),
        );
    }
    Ok(LoadedScopeRegistry {
        scopes,
        preserved_records,
        diagnostics,
    })
}

fn reconcile_persisted_scope(
    root: &Path,
    scope_id: &str,
    mut scope: DevelopmentScope,
) -> DevelopmentScope {
    let candidate = root.join(scope_id);
    if scope.state == ScopeState::Removing {
        scope.home.clone_from(&candidate);
        if scope_id == "default" {
            scope.state = ScopeState::Failed;
            if let Ok(identity) = DirectoryIdentity::capture(&candidate) {
                scope.home_identity = identity;
            }
            scope.diagnostic = Some(bounded_diagnostic(
                "persisted default scope cannot be removing and was isolated",
            ));
        } else if let Some(error) = invalid_removing_home(&candidate, &scope.home_identity) {
            scope.state = ScopeState::Failed;
            scope.diagnostic = Some(bounded_diagnostic(&format!(
                "persisted removing scope record was isolated: {error}"
            )));
        }
    } else {
        scope.home.clone_from(&candidate);
        let verification = fs::symlink_metadata(&candidate)
            .map_err(|error| format!("cannot inspect persisted scope home: {error}"))
            .and_then(|metadata| {
                if !metadata.file_type().is_dir() {
                    return Err("persisted scope home is no longer a directory".to_owned());
                }
                DirectoryIdentity::capture(&candidate)
            })
            .and_then(|current| {
                if current == scope.home_identity {
                    Ok(())
                } else {
                    Err("persisted scope home identity changed after restart".to_owned())
                }
            });
        if let Err(error) = verification {
            scope.state = ScopeState::Failed;
            let prior = scope
                .diagnostic
                .take()
                .map(|diagnostic| format!("{diagnostic}; "))
                .unwrap_or_default();
            scope.diagnostic = Some(bounded_diagnostic(&format!(
                "{prior}persisted scope home could not be verified safely and was isolated: {error}"
            )));
        }
    }
    if matches!(
        scope.state,
        ScopeState::Starting | ScopeState::Resetting | ScopeState::Stopping
    ) {
        scope.state = ScopeState::Failed;
        scope.diagnostic =
            Some("MCP process exited while a scope lifecycle transition was in progress".into());
    }
    scope
}

fn invalid_removing_home(home: &Path, expected: &DirectoryIdentity) -> Option<String> {
    match fs::symlink_metadata(home) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => Some(format!(
            "cannot inspect persisted removing scope home: {error}"
        )),
        Ok(metadata) if !metadata.file_type().is_dir() => {
            Some("persisted removing scope home is no longer a directory".to_owned())
        }
        Ok(_) => match DirectoryIdentity::capture(home) {
            Ok(current) if &current == expected => None,
            Ok(_) => {
                Some("persisted removing scope home identity changed after restart".to_owned())
            }
            Err(error) => Some(error),
        },
    }
}

fn persist_scope_registry(
    root: &Path,
    scopes: &BTreeMap<String, DevelopmentScope>,
    preserved_records: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let mut records = preserved_records.clone();
    for (scope_id, scope) in scopes {
        let value = serde_json::to_value(scope)
            .map_err(|error| format!("cannot encode development scope record: {error}"))?;
        records.insert(scope_id.clone(), value);
    }
    let bytes = serde_json::to_vec_pretty(&records)
        .map_err(|error| format!("cannot encode development scope registry: {error}"))?;
    let temporary = root.join(format!(".scopes-{}.tmp", Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("cannot create development scope registry: {error}"))?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("cannot write development scope registry: {error}"));
    }
    fs::rename(&temporary, root.join("scopes.json")).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        format!("cannot publish development scope registry: {error}")
    })?;
    fs::File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync development scope registry: {error}"))
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests;
