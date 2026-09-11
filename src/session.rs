//! Removes the builds of a run from the device once the run ends.
//!
//! A run is the `cargo` process of a `cargo test`, which invokes the runner once per test binary,
//! or the `cargo-nextest` process of a `cargo nextest run`, which invokes it once per test. The
//! invocations of a run share the builds on the device, so none of them can remove a build when it
//! is done. Instead, the first invocation starts a watcher, which waits for the run to end and then
//! removes the directories the run used - unless another run still uses them.
//!
//! Every invocation marks the directories it uses with a file `<SESSIONS_DIR>/<session>/<name>`,
//! under the device lock and before it relies on them. The watcher removes the markers of its
//! session, and every directory no other session has marked.

use crate::{
    ensure_hdc_shell_success, has_marker, shell_quote, with_device_lock, Hdc, LOCK_TIMEOUT_MARKER,
    TEST_BIN_DIR,
};
use anyhow::{bail, Context};

/// The directory in [`TEST_BIN_DIR`] which holds a directory of markers for every session.
pub(crate) const SESSIONS_DIR: &str = ".sessions";

/// The first argument which makes the runner the watcher of a session, followed by the pid of the
/// run, the id of the session, and the name of its session file.
pub(crate) const WATCH_FLAG: &str = "--cleanup-after";

/// The markers of the runs which keep their builds, and of the runs which could not start a
/// session of their own. No watcher removes them, and the collection of unused builds ignores
/// them, so they only keep the directories from being removed by the end of another run. A run
/// keeping its builds marks them with its own session as well, which protects them from the
/// collection until the run ends.
const KEEP_SESSION: &str = "keep";

/// How long a marker keeps a directory from being collected as unused. A marker older than this
/// belongs to a run whose watcher never got to remove it.
pub(crate) const MARKER_TTL_MINUTES: u64 = 24 * 60;

const SESSION_ID_LEN: usize = 16;

/// The session of the run this invocation belongs to.
pub(crate) struct Session {
    id: String,
    /// Whether the run keeps its builds on the device after it ends.
    keep: bool,
}

impl Session {
    /// A session without a watcher, which leaves the builds to the collection of unused builds.
    pub(crate) fn keep() -> Self {
        Self {
            id: KEEP_SESSION.to_owned(),
            keep: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_id(id: &str, keep: bool) -> Self {
        Self {
            id: id.to_owned(),
            keep,
        }
    }

    /// The shell command which marks the directories `names` in [`TEST_BIN_DIR`] as used by this
    /// session. The directories need not exist yet.
    pub(crate) fn mark_command(&self, names: &[&str]) -> String {
        let mut sessions = vec![self.id.as_str()];
        if self.keep && self.id != KEEP_SESSION {
            sessions.push(KEEP_SESSION);
        }
        let dirs = sessions
            .iter()
            .map(|id| format!("{TEST_BIN_DIR}/{SESSIONS_DIR}/{id}"))
            .collect::<Vec<String>>();
        let mut command = "mkdir -p".to_owned();
        for dir in &dirs {
            command.push(' ');
            command.push_str(&shell_quote(dir));
        }
        command.push_str(" && touch");
        for dir in &dirs {
            for name in names {
                command.push(' ');
                command.push_str(&shell_quote(&format!("{dir}/{name}")));
            }
        }
        command
    }
}

/// A shell condition, run in [`TEST_BIN_DIR`], which holds if a run which has not ended yet has
/// marked the directory named by the variable `$name`. The markers of the runs which keep their
/// builds do not count: those runs leave their builds to the collection of unused builds.
pub(crate) fn marked_by_a_run() -> String {
    format!("ls {SESSIONS_DIR}/[0-9a-f]*/\"$name\" >/dev/null 2>&1")
}

/// Joins the session of the run which invoked this runner, starting it and its watcher if this is
/// the first invocation of the run. With `keep`, the watcher leaves the builds of the run to the
/// collection of unused builds.
///
/// Where no session can be started, the builds are marked as kept instead.
pub(crate) fn join(keep: bool) -> Session {
    #[cfg(unix)]
    match unix::join() {
        Ok(id) => return Session { id, keep },
        Err(err) => log::warn!("The builds of this run stay on the device after it: {err:#}"),
    }
    #[cfg(not(unix))]
    let _ = keep;
    Session::keep()
}

/// Waits for the run with the pid `owner` to end, and then removes the directories which only the
/// session `id` uses from the device. `lock_name` is the session file, which is removed on the way
/// out.
pub(crate) fn watch(owner: &str, id: &str, lock_name: &str) -> anyhow::Result<()> {
    let owner = owner
        .parse::<u32>()
        .ok()
        .filter(|&pid| pid > 1 && i32::try_from(pid).is_ok())
        .with_context(|| format!("Invalid pid of the run: {owner}"))?;
    if !is_session_id(id) {
        bail!("Invalid session id: {id}");
    }
    #[cfg(unix)]
    let _lock = unix::SessionFile::new(lock_name)?;
    #[cfg(unix)]
    unix::wait_for_exit(owner);
    #[cfg(not(unix))]
    let _ = (owner, lock_name);

    let hdc = Hdc::from_env()?;
    let output = hdc.shell(&[&cleanup_command(id)])?;
    ensure_hdc_shell_success(
        &output,
        "Failed to remove the builds of the run from the device",
    )?;
    if has_marker(
        &String::from_utf8_lossy(&output.stdout),
        LOCK_TIMEOUT_MARKER,
    ) {
        bail!("Timed out waiting for the lock on the device");
    }
    Ok(())
}

/// Removes the markers of the session `id`, and every directory no other session has marked.
pub(crate) fn cleanup_command(id: &str) -> String {
    let markers = format!("{SESSIONS_DIR}/{id}");
    let cleanup = format!(
        "for marker in {markers}/*; do \
         [ -e \"$marker\" ] || continue; \
         name=\"${{marker##*/}}\"; \
         rm -f \"$marker\"; \
         ls {SESSIONS_DIR}/*/\"$name\" >/dev/null 2>&1 || rm -rf \"$name\"; \
         done; \
         rmdir {markers} 2>/dev/null; true",
        markers = shell_quote(&markers),
    );
    format!(
        "cd {TEST_BIN_DIR} 2>/dev/null || exit 0; {}",
        with_device_lock(&cleanup, &format!("echo {LOCK_TIMEOUT_MARKER}"))
    )
}

/// Held while this invocation transfers a directory to the device, so that the other invocations
/// on this host wait for the transfer rather than send the same files side by side - like the two
/// listing invocations nextest starts for every test binary at the same moment. Released on drop.
pub(crate) struct TransferLock {
    #[cfg(unix)]
    _lock: unix::HeldLock,
}

/// Takes the transfer locks of the directories `names` on the device `device`, waiting for the
/// invocations holding them. Best-effort: without them, invocations may transfer side by side,
/// which costs time, not correctness.
pub(crate) fn lock_transfers(device: &str, names: &[&str]) -> Vec<TransferLock> {
    #[cfg(unix)]
    {
        let mut locks = Vec::new();
        // Always in the same order - the build, then the files of the package - so that two
        // invocations never wait for each other.
        for name in names {
            match unix::lock_exclusive(&format!("transfer-{device}-{name}")) {
                Ok(lock) => locks.push(TransferLock { _lock: lock }),
                Err(err) => log::warn!("Failed to lock the transfer of {name}: {err:#}"),
            }
        }
        locks
    }
    #[cfg(not(unix))]
    {
        let _ = (device, names);
        Vec::new()
    }
}

fn is_session_id(id: &str) -> bool {
    id.len() == SESSION_ID_LEN && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The fields of `/proc/<pid>/stat` which identify a process and its parent.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, PartialEq)]
struct ProcStat {
    comm: String,
    ppid: u32,
    /// When the process started, in clock ticks since boot. Together with the pid, it identifies
    /// a process: the pid of a process which has ended can be reused, but not with the same start.
    start_time: u64,
}

/// Parses `/proc/<pid>/stat`. The name of the process comes in parentheses, and may contain spaces
/// and parentheses itself, so the fields are counted from the last closing parenthesis.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_stat(stat: &str) -> Option<ProcStat> {
    let (head, rest) = stat.rsplit_once(')')?;
    let comm = head.split_once('(')?.1.to_owned();
    // `rest` starts with the third field, the state.
    let fields = rest.split_whitespace().collect::<Vec<&str>>();
    Some(ProcStat {
        comm,
        ppid: fields.get(1)?.parse().ok()?,
        start_time: fields.get(19)?.parse().ok()?,
    })
}

#[cfg(unix)]
mod unix {
    use super::{is_session_id, WATCH_FLAG};
    use crate::random_id;
    use anyhow::{bail, Context};
    use std::fs::{File, OpenOptions};
    use std::io::{ErrorKind, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// How long an invocation waits for the first invocation of its run to start the watcher.
    const SESSION_ID_TIMEOUT: Duration = Duration::from_secs(1);

    /// How often the watcher checks whether the run still exists, where it cannot wait for it.
    const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(250);

    /// The session of a run is recorded in a file named after the run. The watcher holds a lock on
    /// it for as long as it lives, so a file nobody holds a lock on belongs to a run which has not
    /// started its watcher yet, or whose watcher is gone.
    pub(super) fn join() -> anyhow::Result<String> {
        let owner = find_owner();
        let path = lock_dir()?.join(&owner.key);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("Failed to open {}", path.display()))?;

        if try_lock(&file)? {
            // The first invocation of the run. The id is written only once the watcher runs, so
            // that the other invocations never join a session nobody watches.
            file.set_len(0)?;
            let id = random_id();
            spawn_watcher(owner.pid, &id, &owner.key, file.try_clone()?)?;
            file.write_all(id.as_bytes())?;
            log::debug!("Started the session {id} of the run {}", owner.pid);
            return Ok(id);
        }

        let deadline = Instant::now() + SESSION_ID_TIMEOUT;
        loop {
            let id = std::fs::read_to_string(&path)?;
            if is_session_id(&id) {
                log::debug!("Joined the session {id} of the run {}", owner.pid);
                return Ok(id);
            }
            if Instant::now() >= deadline {
                bail!("{} holds no session id", path.display());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The process whose end is the end of the run, and the name of its session file.
    struct Owner {
        pid: u32,
        key: String,
    }

    /// The nearest `cargo` or `cargo-nextest` among the ancestors, so that a wrapper script in
    /// between, which does not `exec` the runner, still leaves all invocations of the run in one
    /// session. Without one, the parent: whatever invokes the runner repeatedly.
    #[cfg(target_os = "linux")]
    fn find_owner() -> Owner {
        const MAX_DEPTH: usize = 8;

        let proc_stat = |pid: u32| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| super::parse_proc_stat(&stat))
        };
        let parent = std::os::unix::process::parent_id();
        let owner = |pid: u32, start_time: u64| Owner {
            pid,
            key: format!("{pid}-{start_time}"),
        };

        let mut pid = parent;
        for _ in 0..MAX_DEPTH {
            let Some(stat) = proc_stat(pid) else {
                break;
            };
            if matches!(stat.comm.as_str(), "cargo" | "cargo-nextest") {
                return owner(pid, stat.start_time);
            }
            if stat.ppid <= 1 {
                break;
            }
            pid = stat.ppid;
        }
        owner(parent, proc_stat(parent).map_or(0, |stat| stat.start_time))
    }

    #[cfg(not(target_os = "linux"))]
    fn find_owner() -> Owner {
        let pid = std::os::unix::process::parent_id();
        Owner {
            pid,
            key: pid.to_string(),
        }
    }

    /// Starts the watcher of the session, which inherits the lock on the session file as its
    /// stdin and so holds it until it exits.
    fn spawn_watcher(owner: u32, id: &str, lock_name: &str, lock: File) -> anyhow::Result<()> {
        let exe = runner_executable()?;
        let watcher = Command::new(exe)
            .arg(WATCH_FLAG)
            .arg(owner.to_string())
            .arg(id)
            .arg(lock_name)
            .stdin(Stdio::from(lock))
            // cargo and nextest wait for the output pipes of the runner to close.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Out of the process group, which receives Ctrl-C from the terminal, and which nextest
            // terminates when a test times out.
            .process_group(0)
            .spawn()
            .context("Failed to start the watcher of the run")?;
        // The watcher outlives this invocation, and is adopted by init once this invocation exits.
        drop(watcher);
        Ok(())
    }

    /// The executable of this runner. On Linux, `/proc/self/exe` still works when the file has
    /// been replaced since the runner started, e.g. by a `cargo install` during the run.
    fn runner_executable() -> anyhow::Result<PathBuf> {
        #[cfg(target_os = "linux")]
        return Ok(PathBuf::from("/proc/self/exe"));
        #[cfg(not(target_os = "linux"))]
        return std::env::current_exe().context("Failed to find the runner's executable");
    }

    /// The session file of a run, which the watcher removes however it exits.
    pub(super) struct SessionFile {
        path: PathBuf,
    }

    impl SessionFile {
        pub(super) fn new(name: &str) -> anyhow::Result<Self> {
            if name.is_empty() || name.contains('/') || name == "." || name == ".." {
                bail!("Invalid session file name: {name}");
            }
            Ok(Self {
                path: lock_dir()?.join(name),
            })
        }
    }

    impl Drop for SessionFile {
        fn drop(&mut self) {
            // Still locked by this watcher, so no other run can be using the file.
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Waits for the process `pid` to exit. It is not a child of this process, so it cannot be
    /// waited for directly.
    pub(super) fn wait_for_exit(pid: u32) {
        #[cfg(target_os = "linux")]
        if wait_with_pidfd(pid) {
            return;
        }
        while is_alive(pid) {
            std::thread::sleep(EXIT_POLL_INTERVAL);
        }
    }

    /// Waits for `pid` through a pidfd, which refers to the process rather than to its pid, so
    /// cannot mistake a new process with the same pid for it. `false` where pidfds are not
    /// available (before Linux 5.3), or the process is gone already.
    #[cfg(target_os = "linux")]
    fn wait_with_pidfd(pid: u32) -> bool {
        use std::os::fd::{FromRawFd, OwnedFd};

        // SAFETY: pidfd_open takes a pid and flags, and returns a new file descriptor or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd < 0 {
            return false;
        }
        // SAFETY: pidfd_open returned a new file descriptor, which nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: `pollfd` is a valid pollfd, and the 1 passed as the number of entries
            // matches it.
            if unsafe { libc::poll(&mut pollfd, 1, -1) } >= 0 {
                return true;
            }
            if std::io::Error::last_os_error().kind() != ErrorKind::Interrupted {
                return false;
            }
        }
    }

    /// Whether the process `pid` exists. `watch` only accepts pids above 1 which fit a `pid_t`, so
    /// this never addresses a process group or every process.
    fn is_alive(pid: u32) -> bool {
        // SAFETY: signal 0 sends nothing, it only checks whether the process exists.
        if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    /// An exclusive lock on a file in the directory of the session files.
    pub(super) struct HeldLock {
        file: File,
        path: PathBuf,
    }

    /// Takes the exclusive lock on the file `name`, waiting for whoever holds it.
    pub(super) fn lock_exclusive(name: &str) -> anyhow::Result<HeldLock> {
        let path = lock_dir()?.join(name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("Failed to open {}", path.display()))?;
        loop {
            // SAFETY: flock takes a file descriptor, which `file` keeps open for the duration of
            // the call, and flags.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(HeldLock { file, path });
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::Interrupted {
                return Err(err).with_context(|| format!("Failed to lock {}", path.display()));
            }
        }
    }

    impl Drop for HeldLock {
        /// Removes the file, unless another invocation has replaced it already. An invocation
        /// still waiting on the removed file then takes its lock unopposed, which at worst lets it
        /// transfer side by side with a newcomer - after it found the transfer it waited for.
        fn drop(&mut self) {
            let same_file = match (self.file.metadata(), std::fs::symlink_metadata(&self.path)) {
                (Ok(held), Ok(current)) => {
                    held.ino() == current.ino() && held.dev() == current.dev()
                }
                _ => false,
            };
            if same_file {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    /// Takes the lock on `file` if nobody holds it.
    fn try_lock(file: &File) -> anyhow::Result<bool> {
        // SAFETY: flock takes a file descriptor, which `file` keeps open for the duration of the
        // call, and flags.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Ok(false);
        }
        Err(err).context("Failed to lock the session file")
    }

    /// The directory of the session files, private to this user, since the directory for
    /// temporary files is usually shared.
    fn lock_dir() -> anyhow::Result<PathBuf> {
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        // SAFETY: getuid cannot fail, and has no preconditions.
        let uid = unsafe { libc::getuid() };
        let dir = base.join(format!("ohos-test-runner-{uid}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(err).with_context(|| format!("Failed to create {}", dir.display()))
            }
        }
        // Someone else could have created the directory first, to make this user write through
        // a link of theirs.
        let metadata = std::fs::symlink_metadata(&dir)?;
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            bail!("{} is not a directory private to this user", dir.display());
        }
        Ok(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cleanup_command, is_session_id, marked_by_a_run, parse_proc_stat, ProcStat, Session,
        SESSIONS_DIR,
    };
    use crate::TEST_BIN_DIR;

    #[test]
    fn marks_directories_for_the_session() {
        let command =
            Session::with_id("0123456789abcdef", false).mark_command(&["fedcba9876543210"]);
        assert_eq!(
            command,
            format!(
                "mkdir -p '{TEST_BIN_DIR}/{SESSIONS_DIR}/0123456789abcdef' && \
                 touch '{TEST_BIN_DIR}/{SESSIONS_DIR}/0123456789abcdef/fedcba9876543210'"
            )
        );
    }

    #[test]
    fn a_run_keeping_its_builds_protects_them_until_it_ends() {
        // The session marker keeps the collection away during the run, and the keep marker
        // keeps the end of the run - and of other runs - from removing them.
        let command =
            Session::with_id("0123456789abcdef", true).mark_command(&["fedcba9876543210"]);
        for session in ["0123456789abcdef", "keep"] {
            assert!(
                command.contains(&format!(
                    "'{TEST_BIN_DIR}/{SESSIONS_DIR}/{session}/fedcba9876543210'"
                )),
                "{command}"
            );
        }
        let fallback = Session::keep().mark_command(&["fedcba9876543210"]);
        assert_eq!(
            fallback.matches("fedcba9876543210").count(),
            1,
            "{fallback}"
        );
    }

    #[test]
    fn the_cleanup_only_removes_directories_no_other_session_uses() {
        let command = cleanup_command("0123456789abcdef");
        assert!(
            command.contains(&format!(
                "for marker in '{SESSIONS_DIR}/0123456789abcdef'/*"
            )),
            "{command}"
        );
        // Any other marker counts, including those of the runs which keep their builds.
        assert!(
            command.contains(&format!(
                "ls {SESSIONS_DIR}/*/\"$name\" >/dev/null 2>&1 || rm -rf \"$name\""
            )),
            "{command}"
        );
        assert!(command.contains("flock -n 9"), "{command}");
    }

    #[test]
    fn only_the_markers_of_ongoing_runs_protect_from_the_collection() {
        // Session ids are hex, the session of the runs keeping their builds is not.
        assert_eq!(
            marked_by_a_run(),
            format!("ls {SESSIONS_DIR}/[0-9a-f]*/\"$name\" >/dev/null 2>&1")
        );
        assert!(!"keep".starts_with(|c: char| c.is_ascii_hexdigit()));
    }

    #[test]
    fn session_ids_are_short_hex_strings() {
        assert!(is_session_id("0123456789abcdef"));
        assert!(!is_session_id("0123456789abcde"));
        assert!(!is_session_id("0123456789abcdeg"));
        assert!(!is_session_id("keep"));
        assert!(!is_session_id("'; rm -rf / #aaa"));
    }

    #[test]
    fn parses_proc_stat() {
        let stat = "4242 (cargo (x) y) S 4200 4242 4200 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 \
                    987654 1000 100";
        assert_eq!(
            parse_proc_stat(stat),
            Some(ProcStat {
                comm: "cargo (x) y".to_owned(),
                ppid: 4200,
                start_time: 987654,
            })
        );
        assert_eq!(parse_proc_stat("garbage"), None);
    }
}
