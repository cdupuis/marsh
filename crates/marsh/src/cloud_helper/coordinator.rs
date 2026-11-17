//! A detached run's coordinator (`docs/design/cloud-detach.md` s6): with
//! `marsh config cloud-delegate on`, the supervisor serves the workload's
//! registered-command links itself, in place of the laptop. It installs the
//! stock `sbx` CLI (a pinned release, checked by SHA-256), signs it in as
//! root with the access token the laptop uploaded into a root-only file,
//! and runs each call through the same crossing the laptop uses
//! (`marsh_daemon::cloud_call`): an agent sandbox from the Kit, the run's
//! current files copied in, streams relayed, the changes written back.
//!
//! The workload (`marsh-run`, no sudo) can only ask: the Kits the laptop
//! resolved for this run, at most `max_children` agent sandboxes, each
//! with what remains of the run's time limit. Every agent sandbox is in
//! the ownership record under the root-owned state directory and is
//! deleted when its call returns; leftovers are deleted before `done`.

use super::{INSTALLED, PATH, TRUSTED_ENV, state_path};
use marsh_contracts::cloud::{CloudRequest, DelegateKit, DelegatePlan, LinkRequest, run_frame};
use marsh_daemon::cloud_call::{self, Caller, STEP_TIMEOUT};
use marsh_daemon::process::JobControl;
use marsh_sbx::cloud::{CloudSandboxId, CloudSbx};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

/// The stock CLI the coordinator runs: a pinned Docker Sandboxes release.
const SBX_RELEASE: &str = "https://github.com/docker/sbx-releases/releases/download/v0.49.2/DockerSandboxes-linux-arm64.tar.gz";
const SBX_RELEASE_SHA256: &str = "53c5250c480b8ef671d89413d824af62e08575c3b0051570dc5efa9f48a94eb6";
/// The uploaded Docker ID and access token (root, 0600).
pub(super) const DELEGATE_FILE: &str = "delegate";
/// Left in place of [`DELEGATE_FILE`] once the token has been used to sign in.
pub(super) const DELEGATE_USED: &str = "delegate-used";
/// One JSON line per finished agent call.
pub(super) const CALLS_FILE: &str = "children.jsonl";
/// The coordinator's sandbox ownership record (`cloud-ownership.json`).
pub(super) const CHILDREN_DIR: &str = "children";
const MAX_TOKEN: usize = 4096;
const DISPLAY_ARGS: usize = 8;
const DISPLAY_ARG_CHARS: usize = 64;

/// The token is only taken before the workload exists.
fn not_started(state: &Path) -> io::Result<()> {
    if state.join("started").exists() {
        return Err(io::Error::other("the run has already started"));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn not_started_for_test(state: &Path) -> io::Result<()> {
    not_started(state)
}

/// `--internal-cloud delegate`, as root before the run starts: keep the
/// Docker ID and token from stdin (`ID\nTOKEN\n`) in a root-only file.
/// Nothing is echoed.
pub(super) fn store_delegate() -> io::Result<()> {
    store_delegate_from(
        super::privileged(),
        super::state_dir,
        &mut io::stdin().lock(),
    )
}

fn store_delegate_from(
    privileged: bool,
    state_dir: impl FnOnce() -> io::Result<PathBuf>,
    stdin: &mut dyn io::Read,
) -> io::Result<()> {
    if !privileged {
        return Err(io::Error::other(
            "agent calls from a detached run need the marsh cloud shell (a Kit sandbox has no root to keep the token from the workload)",
        ));
    }
    let state = state_dir()?;
    not_started(&state)?;
    let mut input = Vec::new();
    stdin.take(MAX_TOKEN as u64 + 256).read_to_end(&mut input)?;
    let (account, token) = parse_delegate(&input)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid delegate input"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(state.join(DELEGATE_FILE))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(format!("{account}\n{token}\n").as_bytes())?;
    input.fill(0);
    file.sync_all()
}

/// The token's life in `start`, in one place: the workload user is looked at
/// first (the image is the caller's, and the token's only guard is that the
/// workload cannot become root), then the token is read and handed to
/// `sign_in`; the file is deleted and the copies zeroed on every way out,
/// success or not.
fn use_token<T>(
    state: &Path,
    probe: impl FnOnce() -> io::Result<Isolation>,
    sign_in: impl FnOnce(&str, &str) -> io::Result<T>,
) -> io::Result<T> {
    let result = (|| {
        if let Some(problem) = isolation_problem(&probe()?) {
            return Err(io::Error::other(format!(
                "cloud-delegate: refused: {problem}; delegation needs an image where the workload user has no sudo, no extra groups and no Docker socket access (the default image does)"
            )));
        }
        let mut delegate = fs::read(state.join(DELEGATE_FILE)).map_err(|_| {
            io::Error::other("cloud-delegate: no access token was uploaded for this run")
        })?;
        let parsed = parse_delegate(&delegate);
        delegate.fill(0);
        let (account, token) = parsed
            .ok_or_else(|| io::Error::other("cloud-delegate: the uploaded token is unreadable"))?;
        let signed_in = sign_in(&account, &token);
        token.into_bytes().fill(0);
        signed_in
    })();
    // The PAT is not needed again, and a failed start needs it no more:
    // do not leave it on the sandbox disk, which a stopped run keeps for days.
    let forgotten = forget_delegate(state);
    let value = result?;
    forgotten?;
    Ok(value)
}

/// Delete the uploaded token after sign-in, leaving a marker that one was used.
fn forget_delegate(state: &Path) -> io::Result<()> {
    // The token first: a marker that cannot be written must not leave it.
    let removed = discard_token_file(state);
    let marker = File::create(state.join(DELEGATE_USED)).and_then(|file| file.sync_all());
    removed.and(marker)
}

/// Overwrite and unlink the uploaded token file (a plain unlink leaves the
/// bytes on the disk). No marker; a missing file is fine.
pub(super) fn discard_token_file(state: &Path) -> io::Result<()> {
    let path = state.join(DELEGATE_FILE);
    if let Ok(metadata) = fs::metadata(&path)
        && let Ok(mut file) = OpenOptions::new().write(true).open(&path)
    {
        let _ = file.write_all(&vec![0; usize::try_from(metadata.len()).unwrap_or(0)]);
        let _ = file.sync_all();
    }
    match fs::remove_file(&path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// The guard `supervise` holds (privileged helpers only: a Kit sandbox has no
/// token file).
pub(super) fn token_guard(state: &Path, privileged: bool) -> Option<TokenGuard> {
    privileged.then(|| TokenGuard(state.to_owned()))
}

/// Removes the token file when it goes out of scope: a start that fails or
/// never needs the token (no coordinator is started) must not leave it.
pub(super) struct TokenGuard(pub(super) PathBuf);

impl Drop for TokenGuard {
    fn drop(&mut self) {
        let _ = discard_token_file(&self.0);
    }
}

/// What the workload user can do, as seen from root.
struct Isolation {
    user: String,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    /// What `sudo -n -l -U USER` printed.
    sudo: String,
    /// Owner, group and mode of `/var/run/docker.sock`, if it exists.
    docker_socket: Option<(u32, u32, u32)>,
    /// The workload user can open the socket (checked as that user, so ACLs
    /// count; `false` when this helper is not root and cannot become it).
    socket_access: bool,
}

/// Why the workload user could reach the token, if it could.
fn isolation_problem(facts: &Isolation) -> Option<String> {
    let user = &facts.user;
    if facts.uid == 0 || facts.gid == 0 {
        return Some(format!("{user} is root or in root's group"));
    }
    if facts.groups.iter().any(|group| *group != facts.gid) {
        return Some(format!("{user} belongs to groups besides its own"));
    }
    if !facts.sudo.contains("is not allowed to run sudo") {
        return Some(format!("{user} may run sudo"));
    }
    if facts.socket_access
        || facts.docker_socket.is_some_and(|(owner, group, mode)| {
            mode & 0o006 != 0 || owner == facts.uid || (mode & 0o060 != 0 && group == facts.gid)
        })
    {
        return Some(format!("{user} can reach /var/run/docker.sock"));
    }
    None
}

/// Run a probe command with a clean environment; a missing program says so.
fn probe_command(program: &str, args: &[&str]) -> io::Result<std::process::Output> {
    Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", PATH)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            io::Error::other(format!(
                "cannot run `{program}` to check the workload user ({error}); delegation needs an image with `sudo` and `id`"
            ))
        })
}

/// Whether `uid`/`gid` (no other groups: the workload has none) can open
/// `path` for reading or writing, asked of the kernel by a child that runs as
/// that user, so ACLs and every other rule count. `Ok(false)` only when the
/// check ran and said no (exit 1, the one answer `test` gives for that); any
/// other end (exit 2, 127, a signal) is "cannot tell" and counts as reachable.
/// Needs root, or the user's own ids. The check trusts the image's own `test`.
fn reachable_as(path: &Path, uid: u32, gid: u32) -> io::Result<bool> {
    reachable_with("test", path, uid, gid)
}

fn reachable_with(program: &str, path: &Path, uid: u32, gid: u32) -> io::Result<bool> {
    let path = path.to_string_lossy().into_owned();
    Command::new(program)
        .args(["-r", &path, "-o", "-w", &path])
        .env_clear()
        .env("PATH", PATH)
        .stdin(Stdio::null())
        .uid(uid)
        .gid(gid)
        .status()
        .map(|status| status.code() != Some(1))
}

/// Whether the workload user may reach the socket: it exists, and either the
/// check says so or it cannot be made (fail closed). Not root: the check
/// cannot run as the workload user, and the mode-bit rules stand alone.
fn socket_access(exists: bool, root: bool, check: impl FnOnce() -> io::Result<bool>) -> bool {
    exists && root && check().unwrap_or(true)
}

fn probe_isolation(user: &nix::unistd::User) -> io::Result<Isolation> {
    use std::os::unix::fs::MetadataExt as _;
    let listed = probe_command("id", &["-G", &user.name])?;
    if !listed.status.success() {
        return Err(io::Error::other("cannot list the workload user's groups"));
    }
    let groups = String::from_utf8_lossy(&listed.stdout)
        .split_whitespace()
        .map(|group| {
            group
                .parse::<u32>()
                .map_err(|_| io::Error::other("cannot read the workload user's groups"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let listing = probe_command("sudo", &["-n", "-l", "-U", &user.name])?;
    let mut sudo = String::from_utf8_lossy(&listing.stdout).into_owned();
    sudo.push_str(&String::from_utf8_lossy(&listing.stderr));
    let socket = Path::new("/var/run/docker.sock");
    let docker_socket = fs::metadata(socket)
        .ok()
        .map(|metadata| (metadata.uid(), metadata.gid(), metadata.mode()));
    // Fail closed: a socket that exists and cannot be asked about is reachable.
    let socket_access = socket_access(docker_socket.is_some(), super::privileged(), || {
        reachable_as(socket, user.uid.as_raw(), user.gid.as_raw())
    });
    Ok(Isolation {
        user: user.name.clone(),
        uid: user.uid.as_raw(),
        gid: user.gid.as_raw(),
        groups,
        sudo,
        docker_socket,
        socket_access,
    })
}

/// `ID\nTOKEN\n` with a plausible Docker ID and a token of printable,
/// non-space ASCII.
fn parse_delegate(input: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(input).ok()?;
    let mut lines = text.lines();
    let account = lines.next()?.trim();
    let token = lines.next()?.trim();
    let valid_account = !account.is_empty()
        && account.len() <= 64
        && account
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    let valid_token = !token.is_empty()
        && token.len() <= MAX_TOKEN
        && token.bytes().all(|b| b.is_ascii_graphic());
    (valid_account && valid_token).then(|| (account.to_owned(), token.to_owned()))
}

/// The trusted network settings the stock CLI needs in the sandbox.
fn trusted_environment() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    TRUSTED_ENV
        .iter()
        .filter_map(|name| Some(((*name).into(), std::env::var_os(name)?)))
        .collect()
}

fn private_directory(path: &Path) -> io::Result<PathBuf> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || std::os::unix::fs::MetadataExt::uid(&metadata) != 0 {
        return Err(io::Error::other(format!(
            "{} is not a private directory",
            path.display()
        )));
    }
    path.canonicalize()
}

/// The stock CLI warns into every call's output when the sandbox has no
/// machine ID (the cloud image's is empty): give the sandbox a random one.
fn ensure_machine_id() {
    let path = Path::new("/etc/machine-id");
    if fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
        return;
    }
    let mut id = [0_u8; 16];
    if File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut id))
        .is_err()
    {
        return;
    }
    let _ = fs::write(path, format!("{}\n", marsh_daemon::cloud_call::hex(&id)));
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o444));
}

/// Download the pinned stock CLI, check its digest, and keep only `sbx`.
fn install_sbx(state: &Path) -> io::Result<PathBuf> {
    ensure_machine_id();
    let directory = private_directory(&state.join("sbx"))?;
    let program = directory.join("sbx");
    if program.exists() {
        return Ok(program);
    }
    let archive = directory.join("release.tar.gz");
    let status = Command::new("/usr/bin/curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(&archive)
        .arg(SBX_RELEASE)
        .env_clear()
        .env("PATH", PATH)
        .envs(trusted_environment())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(
            "could not download the Docker Sandboxes CLI",
        ));
    }
    let mut hasher = Sha256::new();
    let mut file = File::open(&archive)?;
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    if marsh_daemon::cloud_call::hex(&hasher.finalize()) != SBX_RELEASE_SHA256 {
        let _ = fs::remove_file(&archive);
        return Err(io::Error::other(
            "the downloaded Docker Sandboxes CLI does not match its pinned SHA-256",
        ));
    }
    let status = Command::new("/usr/bin/tar")
        .arg("-xzf")
        .arg(&archive)
        .arg("-C")
        .arg(&directory)
        .args(["--strip-components=1", "docker-sbx/sbx"])
        .env_clear()
        .env("PATH", PATH)
        .status()?;
    let _ = fs::remove_file(&archive);
    if !status.success() {
        return Err(io::Error::other(
            "could not unpack the Docker Sandboxes CLI",
        ));
    }
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700))?;
    Ok(program)
}

/// The stock CLI fetches a Kit from Docker Hub with its sign-in, so the
/// token must be able to pull each Kit's repository (Docker access tokens
/// with only "Allow Cloud Sandboxes access" cannot). Ask Docker Hub's
/// token service for each one now, so such a token refuses the run at
/// start. The credentials go to curl on stdin, never on its command line.
/// Network failures do not refuse here (a call reports them).
fn check_hub_access(plan: &DelegatePlan, account: &str, token: &str) -> io::Result<()> {
    for (name, kit) in &plan.kits {
        let Some(repository) = hub_repository(&kit.kit) else {
            continue;
        };
        let url = format!(
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull"
        );
        let mut child = Command::new("/usr/bin/curl")
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "-K",
                "-",
                &url,
            ])
            .env_clear()
            .env("PATH", PATH)
            .envs(trusted_environment())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = writeln!(stdin, "user = \"{account}:{token}\"");
        }
        let output = child.wait_with_output()?;
        if matches!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "401" | "403"
        ) {
            return Err(io::Error::other(format!(
                "cloud-delegate: the access token cannot pull {name}'s Kit ({repository}) from Docker Hub; \
                 create one with \"Public Repo Read-only\" (or \"Read-only\", for private Kits) access as well as \
                 \"Allow Cloud Sandboxes access\", and store it again in your Keychain"
            )));
        }
    }
    Ok(())
}

/// `NAMESPACE/REPO` of a Docker Hub reference, else `None`.
fn hub_repository(reference: &str) -> Option<String> {
    let name = reference.split('@').next()?;
    let name = name.split(':').next()?;
    let path = name
        .strip_prefix("docker.io/")
        .or_else(|| name.strip_prefix("registry-1.docker.io/"))
        .or_else(|| name.strip_prefix("index.docker.io/"))?;
    let valid = !path.is_empty()
        && path.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'/' | b'.' | b'_' | b'-')
        });
    valid.then(|| {
        if path.contains('/') {
            path.to_owned()
        } else {
            format!("library/{path}")
        }
    })
}

/// Sign the stock CLI in as root with the uploaded token (stdin only).
fn sign_in(program: &Path, home: &Path, account: &str, token: &str) -> io::Result<()> {
    let mut child = Command::new(program)
        .args(["login", "--username", account, "--password-stdin"])
        .env_clear()
        .env("PATH", PATH)
        .env("HOME", home)
        .envs(trusted_environment())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(token.as_bytes())?;
        stdin.write_all(b"\n")?;
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }
    let diagnostic = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| !line.starts_with("WARN"))
        .collect::<Vec<_>>()
        .join(" ")
        .replace(token, "[token]");
    Err(io::Error::other(format!(
        "signing in to Docker Cloud as {account} with the cloud-delegate token failed: {}",
        diagnostic.trim()
    )))
}

/// The helper's own bytes, gzip, and their SHA-256 (what agent sandboxes get).
fn helper_payload() -> io::Result<(Vec<u8>, String)> {
    let bytes = fs::read(INSTALLED)?;
    let digest = cloud_call::hex(&Sha256::digest(&bytes));
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&bytes)?;
    Ok((encoder.finish()?, digest))
}

/// One finished agent call, as the laptop records it in the job's receipt.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(super) struct CallRecord {
    pub kit: String,
    pub args: Vec<String>,
    pub exit: i32,
    pub summary: String,
    pub cause: String,
}

/// Write a finished call to `children.jsonl`, plain (the workload chose its
/// arguments, and the laptop shows this record to its user).
fn append_call_record(state: &Path, record: CallRecord) {
    if let Ok(line) = serde_json::to_string(&record.plain()) {
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(state.join(CALLS_FILE))
            .and_then(|mut file| writeln!(file, "{line}"));
    }
}

impl CallRecord {
    /// Without control or escape characters: the workload chose the
    /// arguments, and the laptop shows this record to its user.
    fn plain(self) -> Self {
        use marsh_sbx::vm_text::plain_text;
        Self {
            kit: plain_text(&self.kit, 64),
            args: self
                .args
                .iter()
                .map(|arg| plain_text(arg, 4 * DISPLAY_ARG_CHARS))
                .collect(),
            exit: self.exit,
            summary: plain_text(&self.summary, 1024),
            cause: plain_text(&self.cause, 1024),
        }
    }
}

/// The finished calls (`children.jsonl`).
pub(super) fn call_records(state: &Path) -> Vec<CallRecord> {
    fs::read_to_string(state.join(CALLS_FILE))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// Agent sandboxes the coordinator still owns: `{name, id, image, agent}`.
pub(super) fn owned_sandboxes(state: &Path) -> Vec<serde_json::Value> {
    let Ok(bytes) = fs::read(state.join(CHILDREN_DIR).join("cloud-ownership.json")) else {
        return Vec::new();
    };
    let Ok(document) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Vec::new();
    };
    document["entries"].as_object().map_or_default(|entries| {
        entries
            .values()
            .map(|entry| {
                serde_json::json!({
                    "name": entry["name"],
                    "id": entry["id"],
                    "image": entry["image"],
                    "agent": entry["agent"],
                })
            })
            .collect()
    })
}

/// The coordinator's guardrails, decided on the laptop (the plan): which
/// Kits, how many agent sandboxes, and how long each may run.
struct Guard {
    plan: DelegatePlan,
    started_at: Instant,
    /// Agent sandboxes admitted so far (refused calls do not count).
    started: Mutex<u32>,
}

impl Guard {
    fn new(plan: DelegatePlan) -> Self {
        Self {
            plan,
            started_at: Instant::now(),
            started: Mutex::new(0),
        }
    }

    /// Admit one call: an allowed Kit (as the laptop resolved it) within the cap.
    fn admit(&self, name: &str) -> Result<DelegateKit, (i32, String)> {
        let Some(kit) = self.plan.kits.get(name) else {
            return Err((
                127,
                format!("marsh: {name}: not available in this detached cloud run\n"),
            ));
        };
        let mut started = self
            .started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *started >= self.plan.max_children {
            return Err((
                125,
                format!(
                    "marsh: {name}: refused: this detached run has started {} agent sandboxes, its limit (MARSH_CLOUD_CHILDREN)\n",
                    self.plan.max_children
                ),
            ));
        }
        *started += 1;
        Ok(kit.clone())
    }

    /// What remains of the run's time limit after `elapsed`, in whole
    /// seconds (as the stock CLI takes it), at least its minimum of one minute.
    fn ttl_after(&self, elapsed: Duration) -> Duration {
        Duration::from_secs(self.plan.ttl_seconds.saturating_sub(elapsed.as_secs()))
            .max(Duration::from_mins(1))
            .min(Duration::from_hours(24))
    }

    fn ttl(&self) -> Duration {
        self.ttl_after(self.started_at.elapsed())
    }
}

/// Taken before a call's changes are written back and held while they are:
/// once the run's end is being recorded (`seal`) nothing more is written, and
/// `seal` waits for a write in progress.
fn write_back_gate(sealed: &Mutex<bool>) -> Result<std::sync::MutexGuard<'_, bool>, String> {
    let sealed = sealed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *sealed {
        return Err("the detached run ended before the call returned".into());
    }
    Ok(sealed)
}

/// The run's end is being recorded: no new calls, and no write-back after the
/// one in progress (`write_back_gate` holds the lock, so this waits for it).
fn seal_state(closing: &AtomicBool, sealed: &Mutex<bool>) {
    closing.store(true, Ordering::Release);
    *sealed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
}

pub(super) struct Coordinator {
    adapter: Arc<CloudSbx>,
    guard: Guard,
    root: String,
    user: nix::unistd::User,
    helper: (Vec<u8>, String),
    mixin: PathBuf,
    results: PathBuf,
    state: PathBuf,
    pending: Mutex<usize>,
    idle: Condvar,
    controls: Mutex<BTreeMap<u32, JobControl>>,
    next: AtomicU32,
    /// The run is ending: no new calls.
    closing: AtomicBool,
    /// Held while a call writes back; `true` once the run's end is being
    /// recorded: no write-back after that.
    sealed: Mutex<bool>,
}

impl Coordinator {
    /// Install and sign in the stock CLI and open the ownership record.
    /// Fails before the workload starts, so a bad token refuses the run.
    pub(super) fn start(
        request: &CloudRequest,
        plan: DelegatePlan,
        user: nix::unistd::User,
    ) -> io::Result<Arc<Self>> {
        let state = state_path();
        let (program, home) = use_token(
            &state,
            || probe_isolation(&user),
            |account, token| {
                check_hub_access(&plan, account, token)?;
                let program = install_sbx(&state)?;
                let home = private_directory(&state.join("sbx-home"))?;
                sign_in(&program, &home, account, token)?;
                Ok((program, home))
            },
        )?;
        let children = private_directory(&state.join(CHILDREN_DIR))?;
        let runner = Arc::new(
            marsh_runtime::SystemCommandRunner::new(&home)
                .with_stock_environment(trusted_environment()),
        );
        let adapter = Arc::new(
            CloudSbx::open(program, runner, children.clone())
                .map_err(|error| io::Error::other(error.to_string()))?,
        );
        // Proves the sign-in reaches the Sandboxes API before the run starts.
        adapter.inventory().map_err(|error| {
            io::Error::other(format!(
                "cloud-delegate: Docker Cloud refused the token: {}",
                cloud_call::actionable(&error)
            ))
        })?;
        let mixin = private_directory(&state.join("workspace-mixin"))?;
        fs::write(mixin.join("kit.yaml"), cloud_call::WORKSPACE_MIXIN)?;
        let results = private_directory(&children.join("results"))?;
        Ok(Arc::new(Self {
            adapter,
            guard: Guard::new(plan),
            root: String::from_utf8(request.root.clone())
                .map_err(|_| io::Error::other("the workspace path is not UTF-8"))?,
            user,
            helper: helper_payload()?,
            mixin,
            results,
            state,
            pending: Mutex::new(0),
            idle: Condvar::new(),
            controls: Mutex::new(BTreeMap::new()),
            next: AtomicU32::new(1),
            closing: AtomicBool::new(false),
            sealed: Mutex::new(false),
        }))
    }

    /// Serve the command links' socket until the run ends.
    pub(super) fn serve(self: &Arc<Self>, listener: UnixListener) {
        let coordinator = Arc::clone(self);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let coordinator = Arc::clone(&coordinator);
                if coordinator.closing.load(Ordering::Acquire) {
                    refuse(
                        &stream,
                        125,
                        "marsh: agent call refused: the run is ending\n",
                    );
                    continue;
                }
                *coordinator
                    .pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
                std::thread::spawn(move || {
                    coordinator.call(stream);
                    let mut pending = coordinator
                        .pending
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    *pending = pending.saturating_sub(1);
                    coordinator.idle.notify_all();
                });
            }
        });
    }

    /// The workload's leader ended: no write-back from here on (one in
    /// progress finishes first).
    pub(super) fn seal(&self) {
        seal_state(&self.closing, &self.sealed);
    }

    /// Stop calls still running, wait for them, then delete every agent
    /// sandbox still owned. True when none is left.
    pub(super) fn settle(&self) -> bool {
        self.closing.store(true, Ordering::Release);
        let controls = self
            .controls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for control in &controls {
            (control.0)("KILL");
        }
        let deadline = Instant::now() + STEP_TIMEOUT;
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *pending > 0 && Instant::now() < deadline {
            pending = self
                .idle
                .wait_timeout(pending, Duration::from_secs(1))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        drop(pending);
        self.delete_leftovers()
    }

    fn delete_leftovers(&self) -> bool {
        let Ok(records) = self.adapter.reconcile() else {
            return false;
        };
        let mut clean = true;
        for record in records {
            match record.id {
                Some(id) => clean &= self.adapter.retire(&id).is_ok(),
                None => clean = false,
            }
        }
        clean
    }

    /// Admit one call: refused once the run is ending, else as the guard says.
    fn admit(&self, name: &str) -> Result<DelegateKit, (i32, String)> {
        if self.closing.load(Ordering::Acquire) {
            return Err((125, format!("marsh: {name}: refused: the run is ending\n")));
        }
        self.guard.admit(name)
    }

    #[allow(clippy::needless_pass_by_value)] // The call owns its connection until it ends.
    fn call(&self, stream: UnixStream) {
        let Ok(Some((run_frame::DATA, body))) = run_frame::read(&mut &stream) else {
            return;
        };
        let Ok(request) = serde_json::from_slice::<LinkRequest>(&body) else {
            refuse(
                &stream,
                125,
                "marsh: agent call refused: unreadable request\n",
            );
            return;
        };
        let name = request.command.clone();
        let kit = match self.admit(&name) {
            Ok(kit) => kit,
            Err((code, message)) => {
                refuse(&stream, code, &message);
                return;
            }
        };
        let args = request
            .argv
            .iter()
            .take(DISPLAY_ARGS)
            .map(|arg| {
                let arg = String::from_utf8_lossy(arg);
                if arg.chars().count() > DISPLAY_ARG_CHARS {
                    arg.chars().take(DISPLAY_ARG_CHARS - 1).collect::<String>() + "…"
                } else {
                    arg.into_owned()
                }
            })
            .collect::<Vec<String>>();
        let caller: Arc<dyn Caller> = match stream.try_clone() {
            Ok(out) => Arc::new(LinkCaller(Mutex::new(out))),
            Err(_) => return,
        };
        let input = link_input(&stream);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let outcome = self.run(id, &name, &kit, request, input, Arc::clone(&caller));
        self.controls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        append_call_record(
            &self.state,
            CallRecord {
                kit: name,
                args,
                exit: outcome.code,
                summary: outcome.summary,
                cause: outcome.cause,
            },
        );
        let _ = run_frame::write(&mut &stream, run_frame::EXIT, &outcome.code.to_be_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }

    fn run(
        &self,
        id: u32,
        name: &str,
        kit: &DelegateKit,
        request: LinkRequest,
        input: mpsc::Receiver<Option<Vec<u8>>>,
        caller: Arc<dyn Caller>,
    ) -> cloud_call::ChildOutcome {
        let failed = |message: String| {
            caller.diagnostic(format!("marsh: {name}: {message}\n").into_bytes());
            cloud_call::ChildOutcome {
                execution: marsh_daemon::ExecutionOutcome::NotStarted,
                code: 125,
                cause: format!("cloud_setup_failed: {message}"),
                cleanup: marsh_daemon::CleanupState::NotRequired,
                summary: String::new(),
            }
        };
        let Ok(image) = marsh_contracts::OciImage::parse(kit.kit.clone()) else {
            return failed("the run's Kit reference is invalid".into());
        };
        if kit.name.is_empty() || kit.entrypoint.is_empty() {
            return failed("the run's Kit was not resolved".into());
        }
        let manifest = marsh_sbx::cloud::KitManifest {
            name: kit.name.clone(),
            entrypoint: kit.entrypoint.clone(),
        };
        let call = cloud_call::ChildCall {
            adapter: &self.adapter,
            kit: &image,
            manifest,
            mixin: &self.mixin,
            root: &self.root,
            cpus: self.guard.plan.cpus,
            ttl: self.guard.ttl(),
            stop_on_timeout: true,
            helper: &self.helper,
            payload: self.results.join(format!("{id}.delta")),
        };
        let parent = LocalParent {
            coordinator: self,
            id,
        };
        cloud_call::run_child(&call, &parent, name, request, input, caller)
    }

    /// A helper step as the workload user, in a clean environment.
    fn as_workload(&self, op: &str) -> Command {
        let mut command = Command::new(INSTALLED);
        command
            .args(["--internal-cloud", op, &self.root])
            .env_clear()
            .env("PATH", PATH)
            .env("HOME", &self.user.dir)
            .current_dir("/")
            .uid(self.user.uid.as_raw())
            .gid(self.user.gid.as_raw());
        command
    }
}

/// The coordinator's side of one call: the run's own workspace, here.
struct LocalParent<'a> {
    coordinator: &'a Coordinator,
    id: u32,
}

impl cloud_call::ChildParent for LocalParent<'_> {
    fn archive(&self, request: Vec<u8>) -> Result<cloud_call::Archive, String> {
        let mut child = self
            .coordinator
            .as_workload("archive")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&request).map_err(|e| e.to_string())?;
        }
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "archive has no output".to_owned())?;
        let mut stderr = child.stderr.take();
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(stderr) = stderr.as_mut() {
                let _ = stderr.take(64 * 1024).read_to_end(&mut bytes);
            }
            bytes
        });
        Ok(cloud_call::Archive {
            stdout: Box::new(stdout),
            finish: Box::new(move || {
                let status = child.wait().map_err(|e| e.to_string())?;
                let diagnostic =
                    String::from_utf8_lossy(&errors.join().unwrap_or_default()).into_owned();
                if status.success() {
                    Ok(())
                } else {
                    Err(diagnostic.trim().to_owned())
                }
            }),
        })
    }

    fn apply(&self, payload: &Path) -> Result<String, String> {
        let sealed = write_back_gate(&self.coordinator.sealed)?;
        let file = File::open(payload).map_err(|e| e.to_string())?;
        let output = self
            .coordinator
            .as_workload("apply")
            .stdin(Stdio::from(file))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| e.to_string())?;
        drop(sealed);
        cloud_call::apply_report(
            &output.stdout,
            output.status.success(),
            String::from_utf8_lossy(&output.stderr).trim(),
        )
    }

    fn cancelled(&self) -> bool {
        self.coordinator.closing.load(Ordering::Acquire)
    }

    fn running(&self, _id: &CloudSandboxId, control: JobControl) -> Result<(), String> {
        if self.cancelled() {
            return Err("the run is ending".into());
        }
        self.coordinator
            .controls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(self.id, control);
        Ok(())
    }
}

/// The calling link's streams: output frames back over its socket.
struct LinkCaller(Mutex<UnixStream>);

impl LinkCaller {
    fn write(&self, tag: u8, bytes: &[u8]) {
        let mut stream = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for chunk in bytes.chunks(run_frame::MAX_PAYLOAD) {
            if run_frame::write(&mut *stream, tag, chunk).is_err() {
                return;
            }
        }
    }
}

impl Caller for LinkCaller {
    fn deliver(&self, tag: u8, bytes: Vec<u8>) {
        let tag = if tag == run_frame::STDOUT {
            run_frame::STDOUT
        } else {
            run_frame::STDERR
        };
        self.write(tag, &bytes);
    }
    fn forwarded(&self, _len: u64) {}
    fn input_closed(&self) {}
    fn diagnostic(&self, bytes: Vec<u8>) {
        self.write(run_frame::STDERR, &bytes);
    }
}

/// The calling link's stdin frames, as the crossing's input queue.
fn link_input(stream: &UnixStream) -> mpsc::Receiver<Option<Vec<u8>>> {
    let (sender, input) = mpsc::channel();
    if let Ok(mut reader) = stream.try_clone() {
        std::thread::spawn(move || {
            loop {
                match run_frame::read(&mut reader) {
                    Ok(Some((run_frame::DATA, bytes))) => {
                        if sender.send(Some(bytes)).is_err() {
                            return;
                        }
                    }
                    Ok(Some((run_frame::EOF, _)) | None) | Err(_) => break,
                    Ok(Some(_)) => {}
                }
            }
            let _ = sender.send(None);
        });
    }
    input
}

fn refuse(stream: &UnixStream, code: i32, message: &str) {
    let _ = run_frame::write(&mut &*stream, run_frame::STDERR, message.as_bytes());
    let _ = run_frame::write(&mut &*stream, run_frame::EXIT, &code.to_be_bytes());
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real `id` and `sudo -l -U` output of an ordinary account passes the
    /// check (and `agent`, which may run sudo, does not). Where sudo is not
    /// usable without a password the check is skipped.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_probe_reads_real_sudo_and_id_output() {
        let usable = Command::new("sudo")
            .args(["-n", "true"])
            .stdin(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        let Ok(Some(nobody)) = nix::unistd::User::from_name("nobody") else {
            return;
        };
        if !usable {
            return;
        }
        let facts = probe_isolation(&nobody).unwrap();
        assert!(
            facts.sudo.contains("is not allowed to run sudo"),
            "{}",
            facts.sudo
        );
        assert_eq!(facts.groups, [nobody.gid.as_raw()]);
        assert_eq!(
            isolation_problem(&Isolation {
                docker_socket: None,
                ..facts
            }),
            None
        );
    }

    /// What the coordinator writes for a call is already plain.
    #[test]
    fn the_written_call_record_is_plain() {
        let state = tempfile::tempdir().unwrap();
        append_call_record(
            state.path(),
            CallRecord {
                kit: "codex".into(),
                args: vec!["\u{1b}]52;c;AAAA\u{7}go".into()],
                exit: 0,
                summary: "wrote\u{1b}[2J".into(),
                cause: String::new(),
            },
        );
        let raw = fs::read_to_string(state.path().join(CALLS_FILE)).unwrap();
        assert!(
            !raw.contains("\\u001b") && !raw.contains("\\u0007"),
            "{raw}"
        );
        let records = call_records(state.path());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].args, ["]52;c;AAAAgo"]);
    }

    /// `store_delegate`'s own refusals and its file: only privileged, only
    /// before the start, one owner-only file.
    #[test]
    fn the_delegate_is_stored_only_privileged_and_before_the_start() {
        use std::os::unix::fs::PermissionsExt as _;
        let state = tempfile::tempdir().unwrap();
        let dir = || Ok(state.path().to_owned());
        let input = || &b"someone\ndckr_pat_secret\n"[..];
        let unprivileged = store_delegate_from(false, dir, &mut input()).unwrap_err();
        assert!(unprivileged.to_string().contains("no root"));
        assert!(!state.path().join(DELEGATE_FILE).exists());
        fs::write(state.path().join("started"), b"").unwrap();
        let late = store_delegate_from(true, dir, &mut input()).unwrap_err();
        assert!(late.to_string().contains("already started"));
        assert!(!state.path().join(DELEGATE_FILE).exists());
        fs::remove_file(state.path().join("started")).unwrap();
        store_delegate_from(true, dir, &mut input()).unwrap();
        let file = state.path().join(DELEGATE_FILE);
        assert_eq!(fs::read(&file).unwrap(), b"someone\ndckr_pat_secret\n");
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// The wiring of `Coordinator::start`'s token handling: the probe comes
    /// first, the token is read only when it passes, and the file is gone on
    /// every way out.
    #[test]
    fn the_token_is_probed_before_it_is_read_and_deleted_on_every_exit() {
        let state = tempfile::tempdir().unwrap();
        let file = state.path().join(DELEGATE_FILE);
        let write = || fs::write(&file, b"someone\ndckr_pat_secret\n").unwrap();
        let ok = || Ok(facts());
        let unused = |_: &str, _: &str| -> io::Result<()> { panic!("the token was read") };

        // A probe that fails, and one that finds a problem: the token is not
        // read, and the file is deleted.
        write();
        assert!(use_token(state.path(), || Err(io::Error::other("no sudo")), unused).is_err());
        assert!(!file.exists());
        write();
        let refused =
            use_token(state.path(), || Ok(Isolation { uid: 0, ..facts() }), unused).unwrap_err();
        assert!(refused.to_string().contains("refused"), "{refused}");
        assert!(!file.exists());

        // Sign-in fails: the file is deleted anyway.
        write();
        let failed = use_token(state.path(), ok, |_, _| {
            Err::<(), _>(io::Error::other("sign-in failed"))
        })
        .unwrap_err();
        assert!(failed.to_string().contains("sign-in failed"));
        assert!(!file.exists());

        // Success: sign-in saw the account and token, and the file is gone.
        write();
        let seen = use_token(state.path(), ok, |account, token| {
            Ok((account.to_owned(), token.to_owned()))
        })
        .unwrap();
        assert_eq!(seen, ("someone".to_owned(), "dckr_pat_secret".to_owned()));
        assert!(!file.exists());
        assert!(state.path().join(DELEGATE_USED).exists());
    }

    fn stub_test(dir: &Path, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// Only exit 1 from `test` means "cannot open it"; 0 is reachable, and an
    /// abnormal end (2, 127, a signal) is "cannot tell", which counts as reachable.
    #[test]
    fn only_an_exit_of_one_from_the_probe_means_the_socket_is_closed_to_the_user() {
        let dir = tempfile::tempdir().unwrap();
        let (uid, gid) = (
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
        );
        let ask = |body: &str| {
            let stub = stub_test(dir.path(), "stub", body);
            reachable_with(&stub, Path::new("/x"), uid, gid)
        };
        assert!(ask("exit 0").unwrap());
        assert!(!ask("exit 1").unwrap());
        assert!(ask("exit 2").unwrap());
        assert!(ask("exit 127").unwrap());
        assert!(ask("kill -9 $$").unwrap());
        // A probe that cannot be started at all is an error.
        assert!(reachable_with("/no/such/test", Path::new("/x"), uid, gid).is_err());
    }

    /// The default when the probe cannot answer is "reachable", and it is not
    /// asked at all unless the socket exists and the helper is root.
    #[test]
    fn the_socket_probe_fails_closed_and_only_runs_for_root_on_an_existing_socket() {
        let cannot = || -> io::Result<bool> { Err(io::Error::other("no test")) };
        assert!(socket_access(true, true, cannot));
        assert!(!socket_access(true, true, || Ok(false)));
        assert!(socket_access(true, true, || Ok(true)));
        let never = || -> io::Result<bool> { panic!("asked") };
        assert!(!socket_access(false, true, never));
        assert!(!socket_access(true, false, never));
    }

    /// `supervise` holds the guard from before the coordinator reads the token
    /// until its start-up closure ends, and the supervisor's spawn failure in
    /// `run` deletes the token. (`supervise` needs a sandbox user to run, so
    /// these read the source: dropping the guard early, `let _ =`, removing
    /// it, or removing the deletion fails here.)
    #[test]
    fn the_token_guard_lives_through_the_coordinator_start_and_a_failed_spawn_deletes_the_token() {
        let source = include_str!("detached.rs");
        let guard = source
            .find("let _token = coordinator::token_guard(")
            .unwrap();
        let start = source.find("Coordinator::start(").unwrap();
        assert!(
            guard < start,
            "the guard must be bound before the coordinator starts"
        );
        let failed = source
            .find("cannot start the supervisor: {error}\"")
            .unwrap();
        let cleanup = source[failed..]
            .find("coordinator::discard_token_file(")
            .unwrap();
        let finish = source[failed..].find("finish_without_workload(").unwrap();
        assert!(cleanup < finish);
        // The guard function itself.
        let state = tempfile::tempdir().unwrap();
        fs::write(state.path().join(DELEGATE_FILE), b"x").unwrap();
        assert!(token_guard(state.path(), false).is_none());
        assert!(state.path().join(DELEGATE_FILE).exists());
        drop(token_guard(state.path(), true));
        assert!(!state.path().join(DELEGATE_FILE).exists());
    }

    /// A marker that cannot be written must not leave the token behind.
    #[test]
    fn a_marker_that_cannot_be_written_still_deletes_the_token() {
        let state = tempfile::tempdir().unwrap();
        fs::write(
            state.path().join(DELEGATE_FILE),
            b"someone\ndckr_pat_secret\n",
        )
        .unwrap();
        // The marker's path is a directory: creating it fails.
        fs::create_dir(state.path().join(DELEGATE_USED)).unwrap();
        assert!(forget_delegate(state.path()).is_err());
        assert!(!state.path().join(DELEGATE_FILE).exists());
    }

    /// The guard `supervise` holds deletes the token on any exit.
    #[test]
    fn the_supervisors_token_guard_deletes_the_file_when_it_drops() {
        let state = tempfile::tempdir().unwrap();
        let file = state.path().join(DELEGATE_FILE);
        fs::write(&file, b"someone\ndckr_pat_secret\n").unwrap();
        drop(TokenGuard(state.path().to_owned()));
        assert!(!file.exists());
        assert!(!state.path().join(DELEGATE_USED).exists());
        // Nothing to delete is fine.
        drop(TokenGuard(state.path().to_owned()));
    }

    /// The probe asks the kernel as the workload user (ACLs count): a file
    /// the user's ids can open is reachable, one they cannot is not.
    #[test]
    fn the_socket_probe_asks_the_kernel_as_the_workload_user() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let (uid, gid) = (
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
        );
        let open = dir.path().join("open");
        let shut = dir.path().join("shut");
        for (path, mode) in [(&open, 0o600), (&shut, 0o000)] {
            fs::write(path, b"").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        assert!(reachable_as(&open, uid, gid).unwrap());
        // Root can open anything; only a user's own ids are refused.
        assert_eq!(reachable_as(&shut, uid, gid).unwrap(), uid == 0);
    }

    #[test]
    fn a_missing_probe_program_is_named() {
        let error = probe_command("marsh-no-such-program", &[]).unwrap_err();
        assert!(
            error.to_string().contains("marsh-no-such-program"),
            "{error}"
        );
        assert!(error.to_string().contains("`sudo` and `id`"), "{error}");
    }

    /// Both places that start a privileged workload call `lock_privileges`
    /// before they spawn it (a spawn seam would need a real sandbox user, so
    /// this reads the source: removing either call fails here).
    #[test]
    fn both_workload_spawn_sites_lock_privileges_first() {
        for (file, source, spawn) in [
            (
                "cloud_helper.rs",
                include_str!("../cloud_helper.rs"),
                "command.spawn()?",
            ),
            (
                "detached.rs",
                include_str!("detached.rs"),
                ".spawn()
",
            ),
        ] {
            let lock = source.find("lock_privileges()?;");
            let spawned = source.find(spawn);
            assert!(
                matches!((lock, spawned), (Some(lock), Some(spawned)) if lock < spawned),
                "{file}: lock_privileges()? must come before the workload spawn"
            );
        }
    }

    #[test]
    fn a_recorded_call_carries_no_terminal_control() {
        let record = CallRecord {
            kit: "codex\u{1b}]52;c;AAAA\u{7}".into(),
            args: vec!["a\u{1b}[2Jb".into(), "x".repeat(1000)],
            exit: 0,
            summary: "ok\u{9b}31m\r\nfake line".into(),
            cause: String::new(),
        }
        .plain();
        let all = format!("{record:?}");
        assert!(!all.contains("\\u{1b}") && !all.contains("\\u{7}") && !all.contains("\\u{9b}"));
        assert_eq!(record.kit, "codex]52;c;AAAA");
        assert_eq!(record.args[0], "a[2Jb");
        assert!(record.args[1].len() <= 4 * DISPLAY_ARG_CHARS);
        assert_eq!(record.summary, "ok31mfake line");
    }

    /// The lifecycle, not its parts: sealing stops new calls, waits for a
    /// write-back in progress, and from then on every write-back is refused.
    #[test]
    fn sealing_waits_for_a_write_back_in_progress_and_then_refuses_every_later_one() {
        let (closing, sealed) = (AtomicBool::new(false), Mutex::new(false));
        let finished = AtomicBool::new(false);
        std::thread::scope(|scope| {
            // A write-back is in progress (the gate is held).
            let writing = write_back_gate(&sealed).unwrap();
            let seal = scope.spawn(|| {
                seal_state(&closing, &sealed);
                finished.store(true, Ordering::SeqCst);
            });
            // Wait (bounded) until the sealing thread has started: `closing` is
            // set before it takes the gate, so a thread that never ran cannot
            // make the "has not finished" check below pass.
            let give_up = Instant::now() + Duration::from_secs(10);
            while !closing.load(Ordering::Acquire) {
                assert!(Instant::now() < give_up, "the sealing thread never ran");
                std::thread::sleep(Duration::from_millis(5));
            }
            std::thread::sleep(Duration::from_millis(150));
            assert!(
                !finished.load(Ordering::SeqCst),
                "sealing did not wait for the write-back"
            );
            drop(writing);
            seal.join().unwrap();
        });
        assert!(closing.load(Ordering::Acquire));
        let refused = write_back_gate(&sealed).unwrap_err();
        assert!(
            refused.contains("ended before the call returned"),
            "{refused}"
        );
        // The production `seal` is that transition (it needs a coordinator
        // with a signed-in CLI to run, so this reads the source: a `seal` that
        // no longer seals fails here).
        let source = include_str!("coordinator.rs");
        let production = &source[..source.find("#[cfg(test)]\nmod tests {").unwrap()];
        let seal = &production[production.find("pub(super) fn seal(&self)").unwrap()..];
        let seal = &seal[..seal.find("\n    }").unwrap()];
        assert!(
            seal.contains("seal_state(&self.closing, &self.sealed)"),
            "{seal}"
        );
    }

    /// A sealed run takes no more write-backs (the gate refuses), an open one
    /// does, and the gate is held across the write so `seal` waits for it.
    #[test]
    fn a_sealed_run_refuses_a_calls_write_back() {
        let sealed = Mutex::new(false);
        {
            let held = write_back_gate(&sealed).unwrap();
            assert!(!*held);
        }
        *sealed.lock().unwrap() = true;
        let refused = write_back_gate(&sealed).unwrap_err();
        assert!(
            refused.contains("ended before the call returned"),
            "{refused}"
        );
        // `apply` takes the gate before it reads the payload or runs anything
        // (it needs a coordinator with a signed-in CLI to run, so this reads
        // the source: removing the gate from `apply` fails here).
        let source = include_str!("coordinator.rs");
        let production = &source[..source.find("#[cfg(test)]\nmod tests {").unwrap()];
        let apply = &production[production.find("fn apply(&self, payload: &Path)").unwrap()..];
        let gate = apply
            .find("write_back_gate(&self.coordinator.sealed)?")
            .unwrap();
        assert!(gate < apply.find("File::open(payload)").unwrap());
        assert!(gate < apply.find(".output()").unwrap());
    }

    fn facts() -> Isolation {
        Isolation {
            user: "marsh-run".into(),
            uid: 1001,
            gid: 1001,
            groups: vec![1001],
            sudo: "User marsh-run is not allowed to run sudo on box.\n".into(),
            docker_socket: Some((0, 999, 0o660)),
            socket_access: false,
        }
    }

    #[test]
    fn the_token_is_read_only_when_the_workload_user_is_cut_off_from_root() {
        assert_eq!(isolation_problem(&facts()), None);
        let broken = [
            Isolation { uid: 0, ..facts() },
            Isolation {
                gid: 0,
                groups: vec![0],
                ..facts()
            },
            Isolation {
                socket_access: true,
                ..facts()
            },
            Isolation {
                groups: vec![1001, 27],
                ..facts()
            },
            Isolation {
                sudo: "User marsh-run may run the following commands:\n    (ALL) NOPASSWD: ALL\n"
                    .into(),
                ..facts()
            },
            Isolation {
                sudo: String::new(),
                ..facts()
            },
            Isolation {
                docker_socket: Some((0, 0, 0o666)),
                ..facts()
            },
            Isolation {
                docker_socket: Some((1001, 0, 0o600)),
                ..facts()
            },
            Isolation {
                docker_socket: Some((0, 1001, 0o660)),
                ..facts()
            },
        ];
        for facts in &broken {
            assert!(isolation_problem(facts).is_some(), "{:?}", facts.sudo);
        }
        assert!(
            isolation_problem(&Isolation {
                docker_socket: None,
                ..facts()
            })
            .is_none()
        );
    }

    #[test]
    fn the_token_file_is_gone_after_sign_in_and_a_marker_says_it_was_used() {
        let state = tempfile::tempdir().unwrap();
        let path = state.path().join(DELEGATE_FILE);
        fs::write(&path, b"someone\ndckr_pat_secret\n").unwrap();
        forget_delegate(state.path()).unwrap();
        assert!(!path.exists());
        assert!(state.path().join(DELEGATE_USED).exists());
        // Twice is fine (a run that is retried before it starts).
        forget_delegate(state.path()).unwrap();
    }

    fn plan(max_children: u32) -> DelegatePlan {
        DelegatePlan {
            kits: BTreeMap::from([(
                "codex".to_owned(),
                DelegateKit {
                    kit: format!("docker.io/docker/codex@sha256:{}", "c".repeat(64)),
                    name: "codex".into(),
                    entrypoint: vec!["codex".into()],
                },
            )]),
            max_children,
            ttl_seconds: 7200,
            cpus: 2,
            account: "someone".into(),
            vm_prefix: "marsh-".into(),
        }
    }

    #[test]
    fn only_the_runs_kits_start_and_never_past_the_cap() {
        let guard = Guard::new(plan(8));
        assert!(matches!(guard.admit("claude"), Err((127, _))));
        for _ in 0..8 {
            assert_eq!(
                guard.admit("codex").unwrap().kit,
                format!("docker.io/docker/codex@sha256:{}", "c".repeat(64))
            );
        }
        let (code, message) = guard.admit("codex").unwrap_err();
        assert_eq!(code, 125);
        assert!(
            message.contains("limit (MARSH_CLOUD_CHILDREN)"),
            "{message}"
        );
        // A refused name never used a slot.
        let guard = Guard::new(plan(1));
        assert!(guard.admit("pi").is_err());
        assert!(guard.admit("codex").is_ok());
    }

    #[test]
    fn hub_repositories_are_found_for_the_access_check() {
        let digest = "c".repeat(64);
        assert_eq!(
            hub_repository(&format!("docker.io/mcavage/marsh-codex@sha256:{digest}")).as_deref(),
            Some("mcavage/marsh-codex")
        );
        assert_eq!(
            hub_repository(&format!("docker.io/alpine:3@sha256:{digest}")).as_deref(),
            Some("library/alpine")
        );
        assert_eq!(
            hub_repository(&format!("ghcr.io/o/k@sha256:{digest}")),
            None
        );
        assert_eq!(hub_repository("docker.io/Bad\"Name@sha256:x"), None);
    }

    #[test]
    fn a_child_gets_what_remains_of_the_runs_time_limit() {
        let guard = Guard::new(plan(8));
        assert_eq!(guard.ttl_after(Duration::ZERO), Duration::from_hours(2));
        assert_eq!(
            guard.ttl_after(Duration::from_mins(90)),
            Duration::from_mins(30)
        );
        assert_eq!(
            guard.ttl_after(Duration::from_millis(1500)),
            Duration::from_secs(7199)
        );
        // Never below the stock minimum, even past the limit.
        assert_eq!(
            guard.ttl_after(Duration::from_hours(3)),
            Duration::from_mins(1)
        );
    }

    #[test]
    fn the_delegate_input_is_an_id_and_one_token() {
        assert_eq!(
            parse_delegate(b"markc741\ndckr_pat_abc-123\n"),
            Some(("markc741".into(), "dckr_pat_abc-123".into()))
        );
        for bad in [
            &b""[..],
            b"id\n",
            b"\ntoken\n",
            b"id with space\ntoken\n",
            b"id\ntok en\n",
            b"id\ntok\x01en\n",
        ] {
            assert_eq!(parse_delegate(bad), None, "{bad:?}");
        }
    }
}
