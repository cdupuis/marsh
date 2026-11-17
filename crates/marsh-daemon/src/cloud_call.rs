//! The cloud crossing shared by the laptop daemon and the remote
//! coordinator of a detached run (`docs/design/cloud-detach.md` s6): stock
//! `sbx --cloud exec` control steps against the `marsh-local` helper, the
//! framed run carrier, and one registered-Kit call in its own agent sandbox
//! (create, copy the caller's files in, relay, confirm, capture, delete,
//! write back).

use crate::cloud_fs::ApplyReport;
use crate::process::JobControl;
use marsh_contracts::cloud::{LinkRequest, MAX_ARCHIVE, run_frame};
use marsh_runtime::Attachment;
use marsh_sbx::cloud::{CloudError, CloudSandboxId, CloudSbx};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// The uploaded helper (sandbox user's private directory); `prepare` installs
/// the root-owned copy every later step runs through `sudo -n`.
pub const UPLOADED: &str = "/tmp/marsh-cloud/marsh-local";
const HELPER: &str = marsh_contracts::cloud::INSTALLED_HELPER;
pub const STEP_TIMEOUT: Duration = Duration::from_mins(10);
pub const CONTROL_TIMEOUT: Duration = Duration::from_mins(1);
/// Exported names that describe the caller's machine, not the sandbox.
pub const LOCAL_ONLY: [&str; 6] = ["SHLVL", "OLDPWD", "PWD", "TMPDIR", "SHELL", "_"];

/// Make stock CLI failures actionable: sign-in and entitlement come first.
#[must_use]
pub fn actionable(error: &CloudError) -> String {
    let text = error.to_string();
    let lower = text.to_ascii_lowercase();
    if lower.contains("login")
        || lower.contains("sign in")
        || lower.contains("unauthorized")
        || lower.contains("not authenticated")
    {
        format!(
            "{text}\nmarsh: cloud: sign in with `sbx login` using an account with Docker Cloud sandbox access"
        )
    } else if lower.contains("subscription") || lower.contains("entitle") || lower.contains("quota")
    {
        format!(
            "{text}\nmarsh: cloud: this Docker account has no Docker Cloud sandbox capacity (subscription or quota)"
        )
    } else {
        text
    }
}

/// How control steps reach the helper: the session cloud shell runs them as
/// root through `sudo` (installed helper, `marsh-run` workload); a Kit
/// sandbox has no root, so the uploaded helper runs as the Kit's own user.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ctl {
    pub kit: bool,
}

impl Ctl {
    /// A control step: `(program, words)`.
    #[must_use]
    pub fn step(self, args: &[&str]) -> (String, Vec<String>) {
        let mut words = Vec::new();
        let program = if self.kit {
            UPLOADED.to_owned()
        } else {
            words.extend(["-n".to_owned(), HELPER.to_owned()]);
            "/usr/bin/sudo".to_owned()
        };
        words.extend(args.iter().map(|arg| (*arg).to_owned()));
        (program, words)
    }

    /// A step that touches the workspace as the workload user.
    pub fn as_workload(self, args: &[&str]) -> (String, Vec<String>) {
        if self.kit {
            return self.step(args);
        }
        let mut words = ["-n", "-u", "marsh-run", HELPER]
            .map(str::to_owned)
            .to_vec();
        words.extend(args.iter().map(|arg| (*arg).to_owned()));
        ("/usr/bin/sudo".to_owned(), words)
    }

    /// The first step, from the uploaded helper (it installs itself).
    pub fn prepare(self, root: &str) -> (String, Vec<String>) {
        let mut words = Vec::new();
        let program = if self.kit {
            UPLOADED.to_owned()
        } else {
            words.extend(["-n".to_owned(), UPLOADED.to_owned()]);
            "/usr/bin/sudo".to_owned()
        };
        words.extend(["--internal-cloud", "prepare", root].map(str::to_owned));
        (program, words)
    }

    /// `sh -c` script that unpacks a gzip snapshot from stdin into `$1`.
    #[must_use]
    pub fn unpack_script(self) -> String {
        if self.kit {
            format!("/usr/bin/gzip -dc | {UPLOADED} --internal-cloud unpack - \"$1\"")
        } else {
            format!(
                "/usr/bin/gzip -dc | /usr/bin/sudo -n {HELPER} --internal-cloud unpack - \"$1\""
            )
        }
    }
}

pub fn os_args(args: &[String]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

/// One stock exec step's result.
pub struct Step {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Step {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    #[must_use]
    pub fn diagnostic(&self) -> String {
        String::from_utf8_lossy(&self.stderr)
            .chars()
            .take(1024)
            .collect::<String>()
            .trim()
            .to_owned()
    }
}

pub fn read_bounded(mut reader: impl Read, mut sink: impl Write, limit: u64) -> io::Result<u64> {
    let copied = io::copy(&mut (&mut reader).take(limit + 1), &mut sink)?;
    if copied > limit {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "stream exceeds its byte limit",
        ));
    }
    sink.flush()?;
    // Drain without keeping anything, so the remote side is never blocked.
    io::copy(&mut reader, &mut io::sink())?;
    Ok(copied)
}

/// Run one control step to completion within `timeout`, feeding `input` and
/// copying stdout to `stdout` (at most `limit` bytes). On timeout the local
/// carrier is terminated and the step fails; that is not proof the remote
/// command stopped, so callers quarantine on failure.
pub fn step(
    attachment: Attachment,
    input: Option<Box<dyn Read + Send>>,
    stdout: Box<dyn Write + Send>,
    limit: u64,
    timeout: Duration,
) -> Result<Step, String> {
    let Attachment {
        mut stdin,
        stdout: out,
        stderr: err,
        mut process,
        ..
    } = attachment;
    let feeder = thread::spawn(move || -> io::Result<()> {
        if let Some(mut input) = input {
            io::copy(&mut input, &mut stdin)?;
        }
        drop(stdin);
        Ok(())
    });
    let output = thread::spawn(move || read_bounded(out, stdout, limit));
    let errors = thread::spawn(move || {
        let mut bytes = Vec::new();
        read_bounded(err, &mut bytes, 64 * 1024).map(|_| bytes)
    });
    let deadline = Instant::now() + timeout;
    let code = loop {
        match process.try_wait() {
            Ok(Some(code)) => break Some(code),
            Ok(None) if Instant::now() >= deadline => {
                let _ = process.terminate();
                break None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(error) => return Err(error.to_string()),
        }
    };
    let fed = feeder.join().map_err(|_| "input thread panicked")?;
    let copied = output.join().map_err(|_| "output thread panicked")?;
    let stderr = errors
        .join()
        .map_err(|_| "error thread panicked")?
        .unwrap_or_default();
    let Some(code) = code else {
        return Err("cloud step timed out".into());
    };
    if code == 0 {
        fed.map_err(|e| format!("cloud upload failed: {e}"))?;
        copied.map_err(|e| e.to_string())?;
    }
    Ok(Step {
        code: Some(code),
        stdout: Vec::new(),
        stderr,
    })
}

/// [`step`] keeping a small stdout in memory.
pub fn small_step<S: AsRef<str>>(
    adapter: &CloudSbx,
    id: &CloudSandboxId,
    program: &str,
    args: &[S],
    input: Option<Box<dyn Read + Send>>,
    timeout: Duration,
) -> Result<Step, String> {
    let args = args
        .iter()
        .map(|arg| OsString::from(arg.as_ref()))
        .collect::<Vec<_>>();
    let attachment = adapter
        .spawn(id, program, &args)
        .map_err(|e| actionable(&e))?;
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let mut result = step(
        attachment,
        input,
        Box::new(SharedBuffer(Arc::clone(&buffer))),
        64 * 1024,
        timeout,
    )?;
    result.stdout = std::mem::take(
        &mut *buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    Ok(result)
}

/// The stock CLI failed before reaching the sandbox (sign-in token refresh,
/// often contended with other stock processes, or a TLS timeout while
/// attaching the exec): the command did not run. Only repeatable steps, and
/// the at-most-once `run`, are started again on this.
#[must_use]
pub fn failed_before_start(step: &Step) -> bool {
    let text = String::from_utf8_lossy(&step.stderr);
    !step.ok()
        && (text.contains("init cloud dispatcher")
            || text.contains("access token source")
            || text.contains("refresh lock held")
            || (text.contains("attach exec in cloud sandbox")
                && text.contains("TLS handshake timeout")))
}

/// Start the helper's `run` and wait for its start signal (an empty ACK).
/// When the stock CLI failed before reaching the sandbox, the run is
/// started again: the helper runs at most once per sandbox (an exclusive
/// marker), so a repeat can never run the command twice.
pub fn spawn_run(adapter: &CloudSbx, id: &CloudSandboxId, ctl: Ctl) -> Result<Attachment, String> {
    let (program, words) = ctl.step(&["--internal-cloud", "run"]);
    spawn_run_with(
        || {
            adapter
                .spawn(id, &program, &os_args(&words))
                .map_err(|error| actionable(&error))
        },
        ACK_TIMEOUT,
    )
}

/// [`spawn_run`] with the stock exec started by `spawn`, and every wait on it
/// (the acknowledgement, the end of an exec that closed its output, the
/// diagnostics it left) bounded by `bound`.
fn spawn_run_with(
    mut spawn: impl FnMut() -> Result<Attachment, String>,
    bound: Duration,
) -> Result<Attachment, String> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let Attachment {
            stdin,
            mut stdout,
            stderr,
            mut process,
            control,
        } = spawn()?;
        let (read, returned) = read_ack(stdout, &mut *process, bound);
        stdout = returned;
        match read {
            Ok(Some((run_frame::ACK, payload))) if payload == 0_u64.to_be_bytes() => {
                return Ok(Attachment {
                    stdin,
                    stdout,
                    stderr,
                    process,
                    control,
                });
            }
            Ok(None) => {
                let (code, diagnostic) = end_unacked_exec(stderr, &mut *process, bound);
                let step = Step {
                    code,
                    stdout: Vec::new(),
                    stderr: diagnostic,
                };
                if attempt < 4 && failed_before_start(&step) {
                    thread::sleep(Duration::from_secs(2 * attempt));
                    continue;
                }
                // Not started, or started and lost: the caller confirms.
                return Ok(Attachment {
                    stdin,
                    stdout: Box::new(io::empty()),
                    stderr: Box::new(io::Cursor::new(step.stderr)),
                    process: Box::new(Exited(code)),
                    control,
                });
            }
            Ok(Some(_)) | Err(_) => {
                return Ok(Attachment {
                    stdin,
                    stdout: Box::new(io::empty()),
                    stderr,
                    process,
                    control,
                });
            }
        }
    }
}

type AckRead = io::Result<Option<(u8, Vec<u8>)>>;

/// The first frame of the carrier, within `timeout`: past it the stock exec is
/// ended (the read then fails) and the caller confirms from the sandbox.
fn read_ack(
    mut stdout: Box<dyn Read + Send>,
    process: &mut dyn marsh_runtime::AttachedProcess,
    timeout: Duration,
) -> (AckRead, Box<dyn Read + Send>) {
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let read = run_frame::read(&mut stdout);
        let _ = send.send((read, stdout));
    });
    if let Ok(done) = receive.recv_timeout(timeout) {
        return done;
    }
    let _ = process.terminate();
    receive
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| {
            (
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no acknowledgement",
                )),
                Box::new(io::empty()),
            )
        })
}

/// The carrier closed its output without the start signal: let the stock
/// exec finish, but never past `grace` (it may be alive with its pipes closed;
/// an exec that outlives the grace is ended), then read what it said.
fn end_unacked_exec(
    mut stderr: Box<dyn Read + Send>,
    process: &mut dyn marsh_runtime::AttachedProcess,
    bound: Duration,
) -> (Option<i32>, Vec<u8>) {
    let code = wait_until(process, Some(Instant::now() + bound));
    // The diagnostics are read on their own thread: a descriptor the exec
    // handed on can keep the pipe open long after the exec itself is gone.
    let kept = Arc::new(Mutex::new(Vec::new()));
    let (done, finished) = mpsc::channel();
    {
        let kept = Arc::clone(&kept);
        thread::spawn(move || {
            let _ = read_bounded(&mut stderr, SharedBuffer(kept), 64 * 1024);
            let _ = done.send(());
        });
    }
    if finished.recv_timeout(bound).is_err() {
        let _ = process.cancel_io();
    }
    let diagnostic = std::mem::take(
        &mut *kept
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    (code, diagnostic)
}

/// How long an exec that was told to end may take to be reaped.
const REAP_GRACE: Duration = Duration::from_secs(10);

/// A stock exec that already ended, handed on with its exit code.
pub struct Exited(Option<i32>);

impl marsh_runtime::AttachedProcess for Exited {
    fn wait(&mut self) -> io::Result<i32> {
        self.0
            .ok_or_else(|| io::Error::other("the stock exec ended without a status"))
    }
    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        self.wait().map(Some)
    }
    fn terminate(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What of an agent call's requested environment reaches its own sandbox:
/// the credential filter, and nothing marsh reserves or binds to a place.
fn child_environment(
    env: std::collections::BTreeMap<String, Vec<u8>>,
) -> std::collections::BTreeMap<String, Vec<u8>> {
    env.into_iter()
        .filter(|(name, value)| {
            crate::split::cloud_forwardable(name, value)
                && !marsh_contracts::reserved_exported_environment_name(name)
                && !marsh_contracts::placement_bound_environment_name(name)
                && !LOCAL_ONLY.contains(&name.as_str())
        })
        .collect()
}

/// One attempt's copy of a step's input (it may carry the delegation token),
/// overwritten when the attempt ends rather than freed as it is.
struct Scrubbed {
    bytes: Vec<u8>,
    at: usize,
}

impl Scrubbed {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            at: 0,
        }
    }
}

impl Read for Scrubbed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = buf.len().min(self.bytes.len() - self.at);
        buf[..count].copy_from_slice(&self.bytes[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}

impl Drop for Scrubbed {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// [`small_step`] for steps that are safe to repeat when the stock CLI
/// failed before starting them; `input` is replayed whole.
pub fn retried_step<S: AsRef<str>>(
    adapter: &CloudSbx,
    id: &CloudSandboxId,
    program: &str,
    args: &[S],
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Step, String> {
    let mut attempt = 0;
    loop {
        let feed = input.map(|bytes| Box::new(Scrubbed::new(bytes)) as Box<dyn Read + Send>);
        let step = small_step(adapter, id, program, args, feed, timeout)?;
        attempt += 1;
        if attempt >= 4 || !failed_before_start(&step) {
            return Ok(step);
        }
        thread::sleep(Duration::from_secs(2 * attempt));
    }
}

pub struct SharedBuffer(pub Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[must_use]
pub fn summary(report: &ApplyReport) -> String {
    use std::fmt::Write as _;
    let plural = |count: u64| if count == 1 { "" } else { "s" };
    let mut text = format!(
        "wrote back {} change{} ({} created, {} modified, {} deleted)",
        report.total(),
        plural(report.total()),
        report.created,
        report.modified,
        report.deleted
    );
    if !report.kept.is_empty() {
        let shown = report
            .kept
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let more = report.kept.len().saturating_sub(5);
        let _ = write!(
            text,
            "; kept {} directories deleted remotely that still hold local files: {shown}{}",
            report.kept.len(),
            if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            }
        );
    }
    if report.ignored > 0 {
        let _ = write!(
            text,
            "; {} ignored file{} left in the cloud",
            report.ignored,
            plural(report.ignored)
        );
    }
    text
}

/// Relay queued stdin to the carrier and its output back to the caller.
/// Returns the carrier's exit code (`None` if it could not be observed).
/// Unacknowledged stdin bytes in flight to the remote workload.
pub struct Window {
    state: Mutex<(u64, bool)>,
    changed: std::sync::Condvar,
    limit: u64,
}

impl Default for Window {
    fn default() -> Self {
        Self::with_limit(run_frame::STDIN_WINDOW)
    }
}

impl Window {
    #[must_use]
    pub fn with_limit(limit: u64) -> Self {
        Self {
            state: Mutex::new((0, false)),
            changed: std::sync::Condvar::new(),
            limit,
        }
    }

    /// Wait until `len` more bytes fit; false once input is closed.
    pub fn reserve(&self, len: u64) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !state.1 && state.0 > 0 && state.0 + len > self.limit {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if state.1 {
            return false;
        }
        state.0 += len;
        true
    }

    pub fn acknowledge(&self, len: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.0 = state.0.saturating_sub(len);
        self.changed.notify_all();
    }

    pub fn close(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1 = true;
        self.changed.notify_all();
    }
}

/// The carrier's stdin, shared by the stdin writer and output acknowledgements.
pub type CarrierInput = Arc<Mutex<Box<dyn Write + Send>>>;

pub fn carrier_frame(input: &CarrierInput, tag: u8, payload: &[u8]) -> io::Result<()> {
    let mut input = input
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_frame::write(&mut **input, tag, payload)
}

/// What the run carrier delivered.
pub struct Carried {
    /// The carrier's own exit code, if observed.
    pub code: Option<i32>,
    /// The helper's end-of-output marker arrived: no output was lost.
    pub output_complete: bool,
}

/// Who a run carrier serves: the session caller, or an agent call relayed
/// from a parent cloud workload.
pub trait Caller: Send + Sync + 'static {
    /// Workload stdout or stderr (`run_frame::STDOUT`/`STDERR`); may block.
    fn deliver(&self, tag: u8, bytes: Vec<u8>);
    /// One input chunk of `len` bytes was forwarded to the carrier.
    fn forwarded(&self, len: u64);
    /// The workload stopped reading its input.
    fn input_closed(&self);
    /// Helper diagnostics (unframed carrier stderr).
    fn diagnostic(&self, bytes: Vec<u8>);
}

/// Replies to one agent call over its parent's carrier, within the parent's
/// acknowledged window.
#[derive(Clone)]
pub struct CallReply {
    id: u32,
    input: CarrierInput,
    window: Arc<Window>,
}

impl CallReply {
    fn tagged(&self, body: &[u8]) -> Vec<u8> {
        let mut payload = self.id.to_be_bytes().to_vec();
        payload.extend_from_slice(body);
        payload
    }

    fn send(&self, tag: u8, bytes: &[u8]) {
        for chunk in bytes.chunks(run_frame::MAX_PAYLOAD - 4) {
            let len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            if !self.window.reserve(len) {
                return;
            }
            let _ = carrier_frame(&self.input, tag, &self.tagged(chunk));
        }
    }

    pub fn stderr(&self, text: &str) {
        self.send(run_frame::KIT_ERR, text.as_bytes());
    }

    pub fn exit(&self, code: i32) {
        let _ = carrier_frame(
            &self.input,
            run_frame::KIT_EXIT,
            &self.tagged(&code.to_be_bytes()),
        );
    }

    /// The call's stdin bytes were taken: let the parent helper send more.
    pub fn taken(&self, len: u64) {
        let _ = carrier_frame(&self.input, run_frame::OUTPUT_ACK, &len.to_be_bytes());
    }
}

impl Caller for CallReply {
    fn deliver(&self, tag: u8, bytes: Vec<u8>) {
        let tag = if tag == run_frame::STDOUT {
            run_frame::KIT_OUT
        } else {
            run_frame::KIT_ERR
        };
        self.send(tag, &bytes);
    }
    fn forwarded(&self, len: u64) {
        self.taken(len);
    }
    fn input_closed(&self) {}
    fn diagnostic(&self, bytes: Vec<u8>) {
        self.send(run_frame::KIT_ERR, &bytes);
    }
}

/// Serves agent calls made by a cloud workload (`KIT_OPEN`).
pub trait CallHost: Send + Sync + 'static {
    /// Count a call before its thread starts (so settlement waits for it);
    /// false once the parent is settling: refuse it.
    fn begin(&self) -> bool;
    fn call(&self, request: LinkRequest, input: mpsc::Receiver<Option<Vec<u8>>>, reply: CallReply);
}

/// Relay queued stdin to the carrier within the acknowledged window and the
/// helper's framed output back to the caller, acknowledging each delivered
/// output frame (the stock channel drops output a slow reader leaves behind).
/// Agent calls from the workload go to `calls`.
pub fn run_carrier(
    carrier: Attachment,
    caller: Arc<dyn Caller>,
    queue: Option<mpsc::Receiver<Option<Vec<u8>>>>,
    resize: Option<mpsc::Receiver<(u16, u16)>>,
    calls: Option<Arc<dyn CallHost>>,
    deadline: Option<Instant>,
) -> Carried {
    run_carrier_within(carrier, caller, queue, resize, calls, deadline, REAP_GRACE)
}

/// [`run_carrier`], with the teardown after the exec ends (the stream
/// threads' joins) bounded by `teardown`.
#[allow(clippy::too_many_lines)] // Cooperating stream threads and one join.
#[allow(clippy::needless_pass_by_value)] // Cloned into each stream thread.
fn run_carrier_within(
    carrier: Attachment,
    caller: Arc<dyn Caller>,
    queue: Option<mpsc::Receiver<Option<Vec<u8>>>>,
    resize: Option<mpsc::Receiver<(u16, u16)>>,
    calls: Option<Arc<dyn CallHost>>,
    deadline: Option<Instant>,
    teardown: Duration,
) -> Carried {
    let Attachment {
        stdin,
        stdout,
        stderr,
        mut process,
        ..
    } = carrier;
    let input: CarrierInput = Arc::new(Mutex::new(stdin));
    if let Some(resize) = resize {
        let input = Arc::clone(&input);
        thread::spawn(move || {
            while let Ok((rows, columns)) = resize.recv() {
                let mut size = rows.to_be_bytes().to_vec();
                size.extend_from_slice(&columns.to_be_bytes());
                if carrier_frame(&input, run_frame::RESIZE, &size).is_err() {
                    break;
                }
            }
        });
    }
    let window = Arc::new(Window::default());
    {
        let (caller, window, input) =
            (Arc::clone(&caller), Arc::clone(&window), Arc::clone(&input));
        thread::spawn(move || {
            let Some(queue) = queue else {
                let _ = carrier_frame(&input, run_frame::EOF, &[]);
                return;
            };
            while let Ok(Some(bytes)) = queue.recv() {
                let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                if !window.reserve(len) || carrier_frame(&input, run_frame::DATA, &bytes).is_err() {
                    // The remote command stopped reading: end the input.
                    caller.input_closed();
                    return;
                }
                caller.forwarded(len);
            }
            let _ = carrier_frame(&input, run_frame::EOF, &[]);
        });
    }
    // Delivery to the caller may be slow; the carrier must still be read
    // promptly (the stock channel drops output left unread). Output waits
    // here, bounded by the helper's acknowledged window.
    let (deliver, deliveries) = mpsc::channel::<(u8, Vec<u8>)>();
    let delivery = {
        let (caller, input) = (Arc::clone(&caller), Arc::clone(&input));
        thread::spawn(move || {
            while let Ok((tag, payload)) = deliveries.recv() {
                let len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
                caller.deliver(tag, payload);
                let _ = carrier_frame(&input, run_frame::OUTPUT_ACK, &len.to_be_bytes());
            }
        })
    };
    let frames = {
        let (window, input) = (Arc::clone(&window), Arc::clone(&input));
        let mut stdout = stdout;
        thread::spawn(move || {
            let mut complete = false;
            let mut inboxes =
                std::collections::HashMap::<u32, mpsc::Sender<Option<Vec<u8>>>>::new();
            // Each call's replies have their own window, so a caller that
            // stops reading stalls only its own call.
            let mut windows = std::collections::HashMap::<u32, Arc<Window>>::new();
            while let Ok(Some((tag, payload))) = run_frame::read(&mut stdout) {
                match tag {
                    run_frame::STDOUT | run_frame::STDERR => {
                        let _ = deliver.send((tag, payload));
                    }
                    run_frame::ACK => {
                        window.acknowledge(payload.try_into().map_or(u64::MAX, u64::from_be_bytes));
                    }
                    run_frame::END => complete = true,
                    run_frame::KIT_ACK if payload.len() == 12 => {
                        let id =
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        if let Some(window) = windows.get(&id) {
                            window.acknowledge(
                                payload[4..].try_into().map_or(u64::MAX, u64::from_be_bytes),
                            );
                        }
                    }
                    run_frame::KIT_OPEN | run_frame::KIT_IN | run_frame::KIT_IN_EOF
                        if payload.len() >= 4 =>
                    {
                        let id =
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        let body = payload[4..].to_vec();
                        let call_window = Arc::clone(windows.entry(id).or_insert_with(|| {
                            Arc::new(Window::with_limit(run_frame::CALL_WINDOW))
                        }));
                        let reply = CallReply {
                            id,
                            input: Arc::clone(&input),
                            window: call_window,
                        };
                        match tag {
                            run_frame::KIT_OPEN => {
                                reply.taken(u64::try_from(body.len()).unwrap_or(u64::MAX));
                                let (sender, inbox) = mpsc::channel();
                                inboxes.insert(id, sender);
                                if let (Ok(request), Some(calls)) =
                                    (serde_json::from_slice::<LinkRequest>(&body), &calls)
                                    && calls.begin()
                                {
                                    let calls = Arc::clone(calls);
                                    thread::spawn(move || calls.call(request, inbox, reply));
                                } else {
                                    reply.stderr("marsh: agent call refused: not available here, or the cloud block is ending\n");
                                    reply.exit(127);
                                }
                            }
                            run_frame::KIT_IN => {
                                let len = u64::try_from(body.len()).unwrap_or(u64::MAX);
                                let delivered = inboxes
                                    .get(&id)
                                    .is_some_and(|inbox| inbox.send(Some(body)).is_ok());
                                if !delivered {
                                    reply.taken(len);
                                }
                            }
                            _ => {
                                if let Some(inbox) = inboxes.remove(&id) {
                                    let _ = inbox.send(None);
                                }
                            }
                        }
                    }
                    _ => window.close(),
                }
            }
            window.close();
            for call in windows.values() {
                call.close();
            }
            // Drain anything after a malformed frame so the carrier can end.
            let _ = io::copy(&mut stdout, &mut io::sink());
            complete
        })
    };
    // Helper diagnostics (not workload output) arrive unframed on stderr.
    let diagnostics = {
        let caller = Arc::clone(&caller);
        let mut stderr = stderr;
        thread::spawn(move || {
            let mut buffer = vec![0_u8; 64 * 1024];
            while let Ok(count) = stderr.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                caller.diagnostic(buffer[..count].to_vec());
            }
        })
    };
    let code = wait_until(&mut *process, deadline);
    // A stream thread can be held by a descriptor the exec handed on, so each
    // join is bounded; past it the attachment is told to cancel its I/O and
    // what has not finished is left behind (the output is then incomplete).
    let mut until = Instant::now() + teardown;
    let mut left_behind = false;
    let mut cancel = |finished: bool, until: &mut Instant| {
        if !finished && !left_behind {
            left_behind = true;
            let _ = process.cancel_io();
            *until = Instant::now() + Duration::from_millis(500);
        }
    };
    let frames_done = join_within(frames, until);
    cancel(frames_done.is_some(), &mut until);
    cancel(join_within(delivery, until).is_some(), &mut until);
    cancel(join_within(diagnostics, until).is_some(), &mut until);
    let output_complete = frames_done.unwrap_or(false);
    window.close();
    // Release the carrier's stdin so nothing keeps the exec session open. A
    // writer that is stuck holds this lock, so its I/O is cancelled first and
    // the lock is waited for only as long as the teardown bound.
    let _ = process.cancel_io();
    let lock_until = Instant::now() + teardown;
    loop {
        match input.try_lock() {
            Ok(mut input) => {
                *input = Box::new(io::sink());
                break;
            }
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                *poisoned.into_inner() = Box::new(io::sink());
                break;
            }
            Err(std::sync::TryLockError::WouldBlock) if Instant::now() < lock_until => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(std::sync::TryLockError::WouldBlock) => break,
        }
    }
    Carried {
        code,
        output_complete,
    }
}

/// How long past a sandbox's own time limit the carrier is waited for.
pub const CARRIER_GRACE: Duration = Duration::from_mins(2);
/// How long the helper's acknowledgement of a run may take.
pub const ACK_TIMEOUT: Duration = Duration::from_mins(5);

/// The deadline of a carrier whose sandbox lives `ttl` from now.
#[must_use]
pub fn carrier_deadline(ttl: Duration) -> Instant {
    Instant::now() + ttl + CARRIER_GRACE
}

/// Join a thread, but not past `until`:
/// `None` when it had not finished (its thread is left to end by itself).
fn join_within<T>(handle: thread::JoinHandle<T>, until: Instant) -> Option<T> {
    while !handle.is_finished() {
        if Instant::now() >= until {
            return None;
        }
        thread::sleep(Duration::from_millis(5));
    }
    handle.join().ok()
}

/// Wait for the stock exec; at `deadline` end it (the sandbox's own limit has
/// passed and the CLI never noticed, e.g. a half-open connection). The caller
/// then confirms the run's end from the sandbox, which handles an end it
/// cannot confirm.
fn wait_until(
    process: &mut dyn marsh_runtime::AttachedProcess,
    deadline: Option<Instant>,
) -> Option<i32> {
    wait_until_with(process, deadline, REAP_GRACE)
}

fn wait_until_with(
    process: &mut dyn marsh_runtime::AttachedProcess,
    deadline: Option<Instant>,
    reap: Duration,
) -> Option<i32> {
    let Some(deadline) = deadline else {
        return process.wait().ok();
    };
    loop {
        match process.try_wait() {
            Ok(Some(code)) => return Some(code),
            Ok(None) => {}
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            let _ = process.terminate();
            // Not an unbounded wait: a process that will not die is left.
            let reaped = Instant::now() + reap;
            while Instant::now() < reaped {
                if let Ok(Some(code)) = process.try_wait() {
                    return Some(code);
                }
                thread::sleep(Duration::from_millis(10));
            }
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// The marsh workspace mixin: creates the caller's natural workspace path,
/// owned by the Kit's user, at sandbox startup (a Kit sandbox has no root).
pub const WORKSPACE_MIXIN: &str = r#"# syntax=docker/sandbox-kit:3@sha256:11bb68806aef6a68d45c10c0c3b3dc86c2f794a296b5a933661d9dadf760b753
schemaVersion: "3"
displayName: marsh cloud workspace
description: Creates the caller's natural workspace path for a marsh cloud placement
kind: mixin
capabilities:
  - type: com.docker.sandbox/lifecycle@1
    config:
      startup:
        - command: [sh, -c, 'case "$MARSH_CLOUD_ROOT" in /?*) [ ! -e "$MARSH_CLOUD_ROOT" ] && mkdir -p "$MARSH_CLOUD_ROOT" && chown agent:agent "$MARSH_CLOUD_ROOT";; esac']
          user: "0"
          env: [MARSH_CLOUD_ROOT]
          description: Create the natural workspace path
"#;

/// Upload the gzip helper to a fresh sandbox and check its digest.
pub fn upload_helper(
    adapter: &CloudSbx,
    id: &CloudSandboxId,
    helper: &(Vec<u8>, String),
) -> Result<(), String> {
    let (bytes, digest) = helper;
    match retried_step(
        adapter,
        id,
        "/bin/sh",
        &[
            "-c",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; umask 077 && mkdir -p /tmp/marsh-cloud && gzip -dc > /tmp/marsh-cloud/marsh-local && chmod 700 /tmp/marsh-cloud/marsh-local && sha256sum /tmp/marsh-cloud/marsh-local",
        ],
        Some(bytes),
        STEP_TIMEOUT,
    ) {
        Ok(step)
            if step.ok() && String::from_utf8_lossy(&step.stdout).starts_with(digest.as_str()) =>
        {
            Ok(())
        }
        Ok(step) => Err(format!("helper upload failed: {}", step.diagnostic())),
        Err(message) => Err(format!("helper upload failed: {message}")),
    }
}

/// The job control that signals a node's workload (INT, TERM, KILL).
pub fn signal_control(adapter: &Arc<CloudSbx>, id: &CloudSandboxId, ctl: Ctl) -> JobControl {
    let (adapter, id) = (Arc::clone(adapter), id.clone());
    JobControl(Arc::new(move |signal: &str| {
        let signal = match signal {
            "KILL" => "KILL",
            "TERM" | "HUP" => "TERM",
            _ => "INT",
        };
        let (adapter, id) = (Arc::clone(&adapter), id.clone());
        thread::spawn(move || {
            let (program, args) = ctl.step(&["--internal-cloud", "signal", signal]);
            let _ = retried_step(&adapter, &id, &program, &args, None, CONTROL_TIMEOUT);
        });
    }))
}

/// The recorded status: present only once every workload writer is gone.
pub fn confirm_status(adapter: &CloudSbx, id: &CloudSandboxId, ctl: Ctl) -> Option<i32> {
    let (program, args) = ctl.step(&["--internal-cloud", "status"]);
    retried_step(adapter, id, &program, &args, None, CONTROL_TIMEOUT)
        .ok()
        .filter(Step::ok)
        .and_then(|step| {
            String::from_utf8_lossy(&step.stdout)
                .trim()
                .parse::<i32>()
                .ok()
        })
}

/// Download the node's delta into owner-only retained storage.
pub fn capture_delta(
    adapter: &CloudSbx,
    id: &CloudSandboxId,
    ctl: Ctl,
    root: &str,
    results: &Path,
    payload: &Path,
) -> Result<u64, String> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(results)
        .map_err(|e| e.to_string())?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(payload)
        .map_err(|e| e.to_string())?;
    let (program, args) = ctl.step(&["--internal-cloud", "delta", root, "-"]);
    let attachment = adapter
        .spawn(id, &program, &os_args(&args))
        .map_err(|e| actionable(&e))?;
    let step = step(
        attachment,
        None,
        Box::new(io::BufWriter::new(file)),
        MAX_ARCHIVE,
        STEP_TIMEOUT,
    )?;
    if step.ok() {
        Ok(marsh_contracts::cloud::ignored_count(&step.stderr))
    } else {
        Err(step.diagnostic())
    }
}

/// The caller's current files, streamed from the parent's `archive` step.
pub struct Archive {
    pub stdout: Box<dyn Read + Send>,
    /// Waits for the archive step; its diagnostic on failure.
    pub finish: Box<dyn FnOnce() -> Result<(), String> + Send>,
}

/// The parent side of one agent call: where its files come from and go
/// back to, and the call's bookkeeping. The laptop daemon reaches the
/// parent sandbox over stock exec; a detached run's coordinator is in it.
pub trait ChildParent: Sync {
    /// Stream the parent's current files (`--internal-cloud archive ROOT`,
    /// fed `request`, a serialized [`CloudRequest`]).
    ///
    /// # Errors
    /// The archive step could not start.
    fn archive(&self, request: Vec<u8>) -> Result<Archive, String>;
    /// Apply the call's returned delta to the parent's live view: the
    /// summary, empty for no changes.
    ///
    /// # Errors
    /// The write-back did not complete (or the parent no longer accepts it).
    fn apply(&self, payload: &Path) -> Result<String, String>;
    /// The call was cancelled.
    fn cancelled(&self) -> bool;
    /// The agent sandbox exists (before anything runs in it).
    fn created(&self, _id: &CloudSandboxId) {}
    /// The workload is about to start; `control` signals it.
    ///
    /// # Errors
    /// The call may not start now.
    fn running(&self, id: &CloudSandboxId, control: JobControl) -> Result<(), String>;
}

/// One registered-Kit call's agent sandbox.
pub struct ChildCall<'a> {
    pub adapter: &'a Arc<CloudSbx>,
    /// The Kit's digest-pinned reference, its declared name and entrypoint.
    pub kit: &'a marsh_contracts::OciImage,
    pub manifest: marsh_sbx::cloud::KitManifest,
    /// The workspace mixin directory (`WORKSPACE_MIXIN`).
    pub mixin: &'a Path,
    /// The parent's workspace root (the natural path).
    pub root: &'a str,
    pub cpus: u32,
    pub ttl: Duration,
    pub stop_on_timeout: bool,
    /// The gzip helper and its SHA-256.
    pub helper: &'a (Vec<u8>, String),
    /// Where the delta is captured (its directory is made owner-only).
    pub payload: std::path::PathBuf,
}

/// How a call ended.
#[derive(Debug)]
pub struct ChildOutcome {
    pub execution: crate::ExecutionOutcome,
    pub code: i32,
    pub cause: String,
    pub cleanup: crate::CleanupState,
    /// What came back (`wrote back ...`), empty for no changes.
    pub summary: String,
}

fn note(caller: &dyn Caller, name: &str, message: &str) {
    caller.diagnostic(format!("marsh: {name}: {message}\n").into_bytes());
}

/// Run one call in its own agent sandbox: create it from the Kit, copy the
/// parent's current files in, relay the call's streams, confirm its end,
/// capture its delta, delete the sandbox, then write the changes back into
/// the parent before returning. Never replays: an unconfirmed end captures
/// nothing.
#[allow(clippy::too_many_lines)] // One ordered crossing: provision, copy, run, return.
#[allow(clippy::needless_pass_by_value)] // The call's request and streams are consumed.
pub fn run_child(
    call: &ChildCall<'_>,
    parent: &dyn ChildParent,
    name: &str,
    request: LinkRequest,
    input: mpsc::Receiver<Option<Vec<u8>>>,
    caller: Arc<dyn Caller>,
) -> ChildOutcome {
    use crate::{CleanupState, ExecutionOutcome};
    use std::os::unix::ffi::OsStrExt as _;
    let not_started = |message: String, cleanup: CleanupState| {
        note(&*caller, name, &message);
        ChildOutcome {
            execution: ExecutionOutcome::NotStarted,
            code: 125,
            cause: format!("cloud_setup_failed: {message}"),
            cleanup,
            summary: String::new(),
        }
    };
    if parent.cancelled() {
        return not_started("cancelled".into(), CleanupState::NotRequired);
    }
    let adapter = call.adapter;
    let spec = marsh_sbx::cloud::CloudImageSpec {
        image: call.kit.clone(),
        kit: Some(marsh_sbx::cloud::CloudKit {
            name: call.manifest.name.clone(),
            mixins: vec![call.mixin.to_path_buf()],
            env: vec![("MARSH_CLOUD_ROOT".into(), call.root.to_owned())],
        }),
        cpus: call.cpus,
        memory_mib: call.cpus * 2048,
        ttl: call.ttl,
        stop_on_timeout: call.stop_on_timeout,
    };
    caller.diagnostic(format!("[starting a Docker Cloud sandbox: Kit {name}…]\n").into_bytes());
    let record = match adapter.create(&spec) {
        Ok(record) => record,
        Err(CloudError::CreateUncertain {
            name: created,
            diagnostic,
        }) => {
            // The sandbox may exist; ownership keeps it for cleanup.
            let cleanup = match adapter
                .reconcile()
                .ok()
                .and_then(|records| records.into_iter().find(|r| r.name == created))
                .and_then(|record| record.id)
                .map(|id| adapter.retire(&id))
            {
                Some(Ok(())) => CleanupState::Verified,
                _ => CleanupState::Uncertain,
            };
            let error = CloudError::CreateUncertain {
                name: created,
                diagnostic,
            };
            return not_started(actionable(&error), cleanup);
        }
        Err(error) => return not_started(actionable(&error), CleanupState::NotRequired),
    };
    let Some(id) = record.id.clone() else {
        return not_started("created sandbox has no ID".into(), CleanupState::Uncertain);
    };
    parent.created(&id);
    let retire = || match adapter.retire(&id) {
        Ok(()) => CleanupState::Verified,
        Err(_) => CleanupState::Uncertain,
    };
    let setup_failed = |message: String| {
        let _ = adapter.quarantine(&id);
        not_started(message, retire())
    };
    let child = Ctl { kit: true };
    if let Err(message) = upload_helper(adapter, &id, call.helper) {
        return setup_failed(message);
    }
    let (program, words) = child.prepare(call.root);
    match retried_step(adapter, &id, &program, &words, None, CONTROL_TIMEOUT) {
        Ok(step) if step.ok() => {}
        Ok(step) => return setup_failed(format!("workspace path: {}", step.diagnostic())),
        Err(message) => return setup_failed(format!("workspace path: {message}")),
    }
    let requested = Path::new(std::ffi::OsStr::from_bytes(&request.cwd));
    let cwd = if requested.starts_with(call.root)
        && requested
            .components()
            .all(|component| !matches!(component, std::path::Component::ParentDir))
    {
        request.cwd.clone()
    } else {
        call.root.as_bytes().to_vec()
    };
    let mut argv = call
        .manifest
        .entrypoint
        .iter()
        .map(|word| word.as_bytes().to_vec())
        .collect::<Vec<_>>();
    argv.extend(request.argv.iter().cloned());
    let child_request = marsh_contracts::cloud::CloudRequest {
        cwd,
        root: call.root.as_bytes().to_vec(),
        mode: marsh_contracts::cloud::CloudMode::Argv,
        argv,
        env: child_environment(request.env),
        terminal: None,
        // An agent call's own sandbox has no command links: no further calls.
        kits: Vec::new(),
        stdin_terminal: false,
        detached: false,
        delegate: None,
        ignore: None,
    };
    if let Err(message) = copy_view(adapter, &id, call.root, parent, &child_request) {
        return setup_failed(format!("copying the block's files: {message}"));
    }
    if parent.cancelled() {
        return setup_failed("cancelled".into());
    }
    if let Err(message) = parent.running(&id, signal_control(adapter, &id, child)) {
        return setup_failed(message);
    }
    let carrier = match spawn_run(adapter, &id, child) {
        Ok(carrier) => carrier,
        Err(message) => return setup_failed(message),
    };
    let delivered = run_carrier(
        carrier,
        Arc::clone(&caller),
        Some(input),
        None,
        None,
        Some(carrier_deadline(call.ttl)),
    );
    let Some(exit_code) = confirm_status(adapter, &id, child) else {
        note(
            &*caller,
            name,
            "lost the call before it was confirmed ended; nothing was written back",
        );
        let _ = adapter.quarantine(&id);
        return ChildOutcome {
            execution: ExecutionOutcome::Unknown,
            code: 125,
            cause: format!("transport_lost: carrier exit {:?}", delivered.code),
            cleanup: retire(),
            summary: String::new(),
        };
    };
    // Capture, retire, then return the changes to the parent's live view.
    let results = call.payload.parent().unwrap_or(Path::new("/"));
    if let Err(message) = capture_delta(adapter, &id, child, call.root, results, &call.payload) {
        let _ = fs::remove_file(&call.payload);
        let _ = adapter.quarantine(&id);
        note(
            &*caller,
            name,
            &format!(
                "could not download its file changes: {message}; the sandbox {} is kept",
                id.as_str()
            ),
        );
        return ChildOutcome {
            execution: ExecutionOutcome::Exited { code: exit_code },
            code: 125,
            cause: format!("capture_failed: {message}; sandbox retained"),
            cleanup: CleanupState::Uncertain,
            summary: String::new(),
        };
    }
    let cleanup = retire();
    let (code, cause, summary) = match parent.apply(&call.payload) {
        Ok(summary) => {
            let _ = fs::remove_file(&call.payload);
            if !summary.is_empty() {
                note(&*caller, name, &summary);
            }
            if delivered.output_complete {
                (exit_code, "exited".to_owned(), summary)
            } else {
                note(&*caller, name, "its output did not all arrive");
                (125, "output_incomplete".to_owned(), summary)
            }
        }
        Err(message) => {
            note(
                &*caller,
                name,
                &format!(
                    "write-back stopped: {message}; the full delta is kept at {}",
                    call.payload.display()
                ),
            );
            (
                125,
                format!("write_back_failed: {message}"),
                format!("write-back stopped: {message}"),
            )
        }
    };
    ChildOutcome {
        execution: ExecutionOutcome::Exited { code: exit_code },
        code,
        cause,
        cleanup,
        summary,
    }
}

/// Stream the parent's current files (`archive`) into the agent sandbox
/// (`unpack`), never through intermediate storage.
fn copy_view(
    adapter: &CloudSbx,
    child: &CloudSandboxId,
    root: &str,
    parent: &dyn ChildParent,
    request: &marsh_contracts::cloud::CloudRequest,
) -> Result<(), String> {
    let request = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    let archive = parent.archive(request)?;
    let script = Ctl { kit: true }.unpack_script();
    let unpack = adapter
        .spawn(
            child,
            "/bin/sh",
            &["-c".into(), script.into(), "sh".into(), root.into()],
        )
        .map_err(|e| actionable(&e))?;
    let unpacked = step(
        unpack,
        Some(archive.stdout),
        Box::new(io::sink()),
        0,
        STEP_TIMEOUT,
    );
    let archived = (archive.finish)();
    match (unpacked, archived) {
        (Ok(step), Ok(())) if step.ok() => Ok(()),
        (Ok(step), archived) => Err(format!(
            "{} {}",
            archived.err().unwrap_or_default(),
            step.diagnostic()
        )
        .trim()
        .to_owned()),
        (Err(message), _) => Err(message),
    }
}

/// The helper's `apply` report (JSON on stdout): the summary, empty for no
/// changes.
///
/// # Errors
/// The apply stopped (its message and what was already written).
pub fn apply_report(stdout: &[u8], ok: bool, diagnostic: &str) -> Result<String, String> {
    let report: serde_json::Value =
        serde_json::from_slice(stdout).unwrap_or(serde_json::Value::Null);
    let count = |key: &str| report[key].as_u64().unwrap_or(0);
    let applied = ApplyReport {
        created: count("created"),
        modified: count("modified"),
        deleted: count("deleted"),
        kept: report["kept"].as_array().map_or_default(|kept| {
            kept.iter()
                .filter_map(|k| k.as_str().map(ToOwned::to_owned))
                .collect()
        }),
        ignored: 0,
        listings: std::collections::BTreeSet::new(),
    };
    match report["error"].as_str() {
        Some(error) => Err(format!("{error}; {} already written", summary(&applied))),
        None if !ok => Err(diagnostic.to_owned()),
        None if applied.total() == 0 && applied.kept.is_empty() => Ok(String::new()),
        None => Ok(summary(&applied)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An agent call's sandbox gets the same credential filter as a block's.
    #[test]
    fn an_agent_calls_environment_drops_credential_shaped_names_and_values() {
        let env = [
            ("DOCKER_AUTH_CONFIG", "{}"),
            ("NOTES", "xoxs-1234-abcd"),
            ("DATABASE_URL", "mysql://app:hunter2@db/app"),
            ("DB", "host=db password = 'abc=def' dbname=app"),
            ("DB2", "Server=db;Password = \"abc=def\";Database=app"),
            ("DB3", "Server=db;Password=\"\"\"abc\";Database=app"),
            ("GIT_AUTHOR_EMAIL", "ada@example.com"),
            ("RUST_LOG", "debug"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.as_bytes().to_vec()))
        .collect();
        let sent = child_environment(env);
        assert_eq!(
            sent.keys().map(String::as_str).collect::<Vec<_>>(),
            ["GIT_AUTHOR_EMAIL", "RUST_LOG"]
        );
    }

    /// A stock exec that never exits until it is terminated, whose output
    /// pipe stays open (a half-open connection).
    struct Hung {
        ended: Arc<std::sync::atomic::AtomicBool>,
        writer: Option<io::PipeWriter>,
        /// Set by `cancel_io` (the stub supports it, as the real exec does).
        cancelled: Arc<std::sync::atomic::AtomicBool>,
    }

    impl marsh_runtime::AttachedProcess for Hung {
        fn wait(&mut self) -> io::Result<i32> {
            loop {
                if let Some(code) = self.try_wait()? {
                    return Ok(code);
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        fn try_wait(&mut self) -> io::Result<Option<i32>> {
            Ok(self
                .ended
                .load(std::sync::atomic::Ordering::SeqCst)
                .then_some(137))
        }
        fn terminate(&mut self) -> io::Result<()> {
            self.ended.store(true, std::sync::atomic::Ordering::SeqCst);
            self.writer.take();
            Ok(())
        }
        fn supports_io_cancellation(&self) -> bool {
            true
        }
        fn cancel_io(&self) -> io::Result<()> {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    struct Quiet;

    impl Caller for Quiet {
        fn deliver(&self, _tag: u8, _bytes: Vec<u8>) {}
        fn forwarded(&self, _len: u64) {}
        fn input_closed(&self) {}
        fn diagnostic(&self, _bytes: Vec<u8>) {}
    }

    fn hung() -> (Attachment, Arc<std::sync::atomic::AtomicBool>) {
        let (reader, writer) = io::pipe().unwrap();
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        (
            Attachment {
                stdin: Box::new(io::sink()),
                stdout: Box::new(reader),
                stderr: Box::new(io::empty()),
                process: Box::new(Hung {
                    ended: Arc::clone(&ended),
                    writer: Some(writer),
                    cancelled: Arc::default(),
                }),
                control: marsh_runtime::no_attachment_control(),
            },
            ended,
        )
    }

    /// C-04: a carrier that never ends is ended at its deadline, and the
    /// run's end is then left to the caller's status confirmation.
    #[test]
    fn a_carrier_that_outlives_its_deadline_is_ended() {
        let (exec, ended) = hung();
        let started = Instant::now();
        let carried = run_carrier(
            exec,
            Arc::new(Quiet),
            None,
            None,
            None,
            Some(Instant::now() + Duration::from_millis(100)),
        );
        assert!(ended.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(carried.code, Some(137));
        assert!(!carried.output_complete);
        assert!(started.elapsed() < Duration::from_secs(20));
    }

    /// An exec whose output closed at once (EOF before the start signal) but
    /// which stays alive, and whose stderr pipe a retained descriptor holds
    /// open: `spawn_run`'s path returns within its bound, ends the exec, and
    /// does not wait for the pipe. (Reverting `spawn_run_with`'s EOF arm to an
    /// unbounded wait or drain makes this hang.)
    #[test]
    fn eof_before_the_acknowledgement_does_not_wait_for_a_live_exec_or_its_pipes() {
        let (held_stderr, _writer_kept_open) = io::pipe().unwrap();
        let (exec, ended) = hung();
        let Attachment { process, .. } = exec;
        let mut parts = Some((process, held_stderr));
        let started = Instant::now();
        let attachment = spawn_run_with(
            || {
                let (process, stderr) = parts.take().unwrap();
                Ok(Attachment {
                    stdin: Box::new(io::sink()),
                    stdout: Box::new(io::empty()),
                    stderr: Box::new(stderr),
                    process,
                    control: marsh_runtime::no_attachment_control(),
                })
            },
            Duration::from_millis(150),
        )
        .unwrap();
        assert!(
            ended.load(std::sync::atomic::Ordering::SeqCst),
            "the exec was not ended"
        );
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        // The caller gets the exit the exec ended with and no output.
        let mut process = attachment.process;
        assert_eq!(process.wait().unwrap(), 137);
    }

    /// The pieces: the diagnostics of an exec that is gone are read for at most
    /// the bound even when their pipe stays open.
    #[test]
    fn the_diagnostics_of_an_ended_exec_are_read_for_at_most_the_bound() {
        let (mut stderr_reader, mut stderr_writer) = io::pipe().unwrap();
        io::Write::write_all(&mut stderr_writer, b"boom").unwrap();
        let (exec, _) = hung();
        let Attachment { mut process, .. } = exec;
        let started = Instant::now();
        let (code, diagnostic) = end_unacked_exec(
            Box::new(std::mem::replace(&mut stderr_reader, io::pipe().unwrap().0)),
            &mut *process,
            Duration::from_millis(150),
        );
        assert_eq!(code, Some(137));
        assert_eq!(diagnostic, b"boom");
        assert!(started.elapsed() < Duration::from_secs(20));
        drop(stderr_writer);
    }

    /// Teardown after the deadline is bounded too: the exec is gone but a
    /// descriptor it handed on keeps the carrier's output open, so the stream
    /// threads cannot finish; `run_carrier` still returns, output incomplete.
    #[test]
    fn a_retained_output_pipe_does_not_hold_the_carrier_past_its_teardown_bound() {
        // Both output pipes stay open (a descriptor the exec handed on), and
        // stderr has something to read: the diagnostics thread is held too.
        let (reader, _stdout_kept_open) = io::pipe().unwrap();
        let (stderr_reader, mut stderr_writer) = io::pipe().unwrap();
        io::Write::write_all(&mut stderr_writer, b"diagnostic").unwrap();
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exec = Attachment {
            stdin: Box::new(io::sink()),
            stdout: Box::new(reader),
            stderr: Box::new(stderr_reader),
            process: Box::new(Hung {
                ended: Arc::clone(&ended),
                writer: None,
                cancelled: Arc::clone(&cancelled),
            }),
            control: marsh_runtime::no_attachment_control(),
        };
        let started = Instant::now();
        let carried = run_carrier_within(
            exec,
            Arc::new(Quiet),
            None,
            None,
            None,
            Some(Instant::now() + Duration::from_millis(50)),
            Duration::from_millis(100),
        );
        assert!(ended.load(std::sync::atomic::Ordering::SeqCst));
        // Past the join bound the attachment's I/O was cancelled.
        assert!(cancelled.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(carried.code, Some(137));
        assert!(!carried.output_complete);
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        drop(stderr_writer);
    }

    /// A stdin writer stuck inside a write holds the carrier's input lock; the
    /// teardown does not wait for it past its bound (it would otherwise block
    /// on the lock for as long as the write stalls).
    #[test]
    fn a_stuck_stdin_writer_does_not_hold_the_carrier_teardown() {
        struct Stuck;
        impl io::Write for Stuck {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                thread::sleep(Duration::from_secs(6));
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exec = Attachment {
            stdin: Box::new(Stuck),
            stdout: Box::new(io::empty()),
            stderr: Box::new(io::empty()),
            process: Box::new(Hung {
                ended: Arc::clone(&ended),
                writer: None,
                cancelled: Arc::default(),
            }),
            control: marsh_runtime::no_attachment_control(),
        };
        let (queue, input) = mpsc::channel();
        queue.send(Some(b"typed".to_vec())).unwrap();
        // Let the stdin thread take the lock and stall inside the write.
        let stalled = Instant::now();
        let carried = thread::scope(|scope| {
            let run = scope.spawn(|| {
                run_carrier_within(
                    exec,
                    Arc::new(Quiet),
                    Some(input),
                    None,
                    None,
                    Some(Instant::now() + Duration::from_millis(300)),
                    Duration::from_millis(100),
                )
            });
            run.join().unwrap()
        });
        assert_eq!(carried.code, Some(137));
        assert!(
            stalled.elapsed() < Duration::from_secs(4),
            "teardown waited for the stuck writer: {:?}",
            stalled.elapsed()
        );
        drop(queue);
    }

    /// An exec that ignores `terminate` is not waited for forever.
    #[test]
    fn an_exec_that_ignores_terminate_is_left_after_the_reap_bound() {
        struct Stubborn;
        impl marsh_runtime::AttachedProcess for Stubborn {
            fn wait(&mut self) -> io::Result<i32> {
                loop {
                    thread::sleep(Duration::from_secs(1));
                }
            }
            fn try_wait(&mut self) -> io::Result<Option<i32>> {
                Ok(None)
            }
            fn terminate(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let started = Instant::now();
        let code = wait_until_with(
            &mut Stubborn,
            Some(Instant::now() + Duration::from_millis(50)),
            Duration::from_millis(100),
        );
        assert_eq!(code, None);
        assert!(started.elapsed() < Duration::from_secs(20));
    }

    /// The acknowledgement bound at its call site: an exec whose output stays
    /// open and silent is ended and returned by `spawn_run_with` within the
    /// bound (replacing its `read_ack` by a plain read hangs this).
    #[test]
    fn a_silent_exec_is_ended_by_the_spawn_path_within_its_bound() {
        let (exec, ended) = hung();
        let mut parts = Some(exec);
        let started = Instant::now();
        let attachment =
            spawn_run_with(|| Ok(parts.take().unwrap()), Duration::from_millis(150)).unwrap();
        assert!(ended.load(std::sync::atomic::Ordering::SeqCst));
        assert!(started.elapsed() < Duration::from_secs(20));
        drop(attachment);
    }

    /// The deadlines at their call sites: an agent call's carrier and a
    /// block's carrier are both run with `carrier_deadline` (a deadline of
    /// `None` is an unbounded wait; this reads the source, since both sites
    /// need a real sandbox to run).
    #[test]
    fn the_carrier_callers_pass_a_deadline() {
        // Only the production part of each file: this test's own text must not
        // be what it finds.
        let production = |source: &'static str| -> &'static str {
            &source[..source.find("#[cfg(test)]\nmod tests {").unwrap()]
        };
        let child = production(include_str!("cloud_call.rs"));
        assert!(child.contains("Some(carrier_deadline(call.ttl))"));
        // The backend file is another crate's: nothing here can match itself.
        let backend = include_str!("../../marsh-backend/src/cloud.rs");
        assert!(backend.contains("cloud_call::carrier_deadline(options.ttl)"));
        assert!(backend.contains("Some(deadline),"));
    }

    /// C-04: a helper that never acknowledges the run is given up on.
    #[test]
    fn a_missing_acknowledgement_ends_the_exec_instead_of_hanging() {
        let (carrier, ended) = hung();
        let Attachment {
            stdout,
            mut process,
            ..
        } = carrier;
        let (read, _) = read_ack(stdout, &mut *process, Duration::from_millis(100));
        assert!(ended.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!matches!(read, Ok(Some(_))));
    }

    #[test]
    fn a_retried_steps_input_is_replayed_whole_from_a_scrubbed_copy() {
        let mut copy = Scrubbed::new(b"someone\ndckr_pat_x\n");
        let mut got = Vec::new();
        let mut chunk = [0_u8; 4];
        loop {
            let count = copy.read(&mut chunk).unwrap();
            if count == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(got, b"someone\ndckr_pat_x\n");
        // What the drop overwrites with.
        copy.bytes.fill(0);
        assert!(copy.bytes.iter().all(|byte| *byte == 0));
    }
}
