//! Removes the builds of a run from the device once the run ends.
//!
//! A run is the process which invokes the runner: `cargo` for `cargo test`, which invokes it once
//! per test binary, and `cargo-nextest` for `cargo nextest run`, which invokes it once per test.
//! The invocations of a run share the builds on the device, so none of them can remove a build
//! when it is done. Instead, the first invocation starts a watcher, which waits for the run to end
//! and then removes the directories the run used - unless another run still uses them.
//!
//! Every invocation marks the directories it uses with a file named after the session of its run,
//! in [`SESSIONS_DIR`]. The watcher removes the markers of its session, and with them every
//! directory no other session has marked.

use crate::{ensure_hdc_shell_success, shell_quote, Hdc, TEST_BIN_DIR};
use anyhow::{bail, Context};

/// The directory inside a build or fixture directory, which holds a marker file for every session
/// using it.
pub(crate) const SESSIONS_DIR: &str = ".sessions";

/// The first argument which makes the runner the watcher of a session, followed by the pid of the
/// run and the id of the session.
pub(crate) const WATCH_FLAG: &str = "--cleanup-after";

const SESSION_ID_LEN: usize = 16;

/// The session of the run this invocation belongs to.
pub(crate) struct Session {
    id: String,
}

impl Session {
    #[cfg(test)]
    pub(crate) fn with_id(id: &str) -> Self {
        Self { id: id.to_owned() }
    }

    /// The shell command which marks `dir` as used by this session.
    pub(crate) fn mark_command(&self, dir: &str) -> String {
        format!(
            "mkdir -p {} && touch {}",
            shell_quote(&format!("{dir}/{SESSIONS_DIR}")),
            shell_quote(&format!("{dir}/{SESSIONS_DIR}/{}", self.id))
        )
    }
}

/// Joins the session of the run which invoked this runner, starting it and its watcher if this is
/// the first invocation of the run.
///
/// `None` when the builds cannot be removed at the end of the run, which leaves them to the
/// collection of unused builds.
pub(crate) fn join() -> Option<Session> {
    #[cfg(unix)]
    match unix::join() {
        Ok(session) => return Some(session),
        Err(err) => log::warn!("The builds of this run stay on the device after it: {err:#}"),
    }
    None
}

/// Waits for the run with the pid `owner` to end, and then removes the directories which only the
/// session `id` uses from the device.
pub(crate) fn watch(owner: &str, id: &str) -> anyhow::Result<()> {
    let owner = owner
        .parse::<u32>()
        .with_context(|| format!("Invalid pid of the run: {owner}"))?;
    if !is_session_id(id) {
        bail!("Invalid session id: {id}");
    }
    #[cfg(unix)]
    unix::wait_for_exit(owner);
    #[cfg(not(unix))]
    let _ = owner;
    let hdc = Hdc::from_env()?;
    let output = hdc.shell(&[&cleanup_command(id)])?;
    ensure_hdc_shell_success(
        &output,
        "Failed to remove the builds of the run from the device",
    )?;
    #[cfg(unix)]
    unix::remove_lock(owner);
    Ok(())
}

/// Removes the markers of the session `id`, and every directory no other session has marked.
///
/// `rmdir` only removes the directory of the markers once it is empty, so of two sessions ending
/// at the same time, exactly one removes a directory they shared.
pub(crate) fn cleanup_command(id: &str) -> String {
    let marker = shell_quote(&format!("{SESSIONS_DIR}/{id}"));
    let sessions = shell_quote(SESSIONS_DIR);
    format!(
        "cd {TEST_BIN_DIR} 2>/dev/null || exit 0; \
         for dir in */; do \
         dir=\"${{dir%/}}\"; \
         [ -e \"$dir\"/{marker} ] || continue; \
         rm -f \"$dir\"/{marker}; \
         rmdir \"$dir\"/{sessions} 2>/dev/null && rm -rf \"$dir\"; \
         done"
    )
}

fn is_session_id(id: &str) -> bool {
    id.len() == SESSION_ID_LEN && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(unix)]
mod unix {
    use super::{is_session_id, Session, SESSION_ID_LEN, WATCH_FLAG};
    use anyhow::{bail, Context};
    use sha2::{Digest, Sha256};
    use std::fs::{File, OpenOptions};
    use std::io::{ErrorKind, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime};

    /// How long an invocation waits for the first invocation of its run to write the session id.
    const SESSION_ID_TIMEOUT: Duration = Duration::from_secs(1);

    /// How often the watcher checks whether the run still exists, where it cannot wait for it.
    const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(250);

    /// The session of a run is recorded in a file named after the run's pid. The watcher holds a
    /// lock on it for as long as it lives, so a file nobody holds a lock on was left behind by a
    /// run which has ended, and whose pid a new run happens to have.
    pub(super) fn join() -> anyhow::Result<Session> {
        let owner = std::os::unix::process::parent_id();
        let path = lock_path(owner)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("Failed to open {}", path.display()))?;

        if try_lock(&file)? {
            // The first invocation of the run: nobody has written its session id yet.
            file.set_len(0)?;
            let id = new_session_id(owner);
            file.write_all(id.as_bytes())?;
            spawn_watcher(owner, &id, file)?;
            return Ok(Session { id });
        }

        // The first invocation of the run holds the lock, and writes the id right after taking it.
        let deadline = Instant::now() + SESSION_ID_TIMEOUT;
        loop {
            let id = std::fs::read_to_string(&path)?;
            if is_session_id(&id) {
                return Ok(Session { id });
            }
            if Instant::now() >= deadline {
                bail!("{} holds no session id", path.display());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Starts the watcher of the session, which inherits the lock on the session file as its
    /// stdin and so holds it until it exits.
    fn spawn_watcher(owner: u32, id: &str, lock: File) -> anyhow::Result<()> {
        let exe = std::env::current_exe().context("Failed to find the runner's executable")?;
        let watcher = Command::new(exe)
            .arg(WATCH_FLAG)
            .arg(owner.to_string())
            .arg(id)
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

    fn is_alive(pid: u32) -> bool {
        // SAFETY: signal 0 sends nothing, it only checks whether the process exists.
        if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
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

    /// Removes the session file of the run `owner`. The watcher calls this while it still holds
    /// the lock, so no other run can have started to use the file.
    pub(super) fn remove_lock(owner: u32) {
        if let Ok(path) = lock_path(owner) {
            let _ = std::fs::remove_file(path);
        }
    }

    /// The session file of the run `owner`, in a directory only this user can write to, since
    /// the directory for temporary files is usually shared.
    fn lock_path(owner: u32) -> anyhow::Result<PathBuf> {
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
        Ok(dir.join(owner.to_string()))
    }

    fn new_session_id(owner: u32) -> String {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(format!("{owner} {} {nanos}", std::process::id()));
        let mut id = hex::encode(hasher.finalize());
        id.truncate(SESSION_ID_LEN);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::{cleanup_command, is_session_id, Session, SESSIONS_DIR};

    #[test]
    fn marks_a_directory_for_the_session() {
        let session = Session {
            id: "0123456789abcdef".to_owned(),
        };
        let command = session.mark_command("/data/local/tmp/ohos-test-runner/fedcba9876543210");
        assert_eq!(
            command,
            format!(
                "mkdir -p '/data/local/tmp/ohos-test-runner/fedcba9876543210/{SESSIONS_DIR}' && \
                 touch '/data/local/tmp/ohos-test-runner/fedcba9876543210/{SESSIONS_DIR}/0123456789abcdef'"
            )
        );
    }

    #[test]
    fn the_cleanup_only_removes_directories_no_other_session_uses() {
        let command = cleanup_command("0123456789abcdef");
        assert!(
            command.contains(&format!("rm -f \"$dir\"/'{SESSIONS_DIR}/0123456789abcdef'")),
            "{command}"
        );
        assert!(
            command.contains(&format!(
                "rmdir \"$dir\"/'{SESSIONS_DIR}' 2>/dev/null && rm -rf \"$dir\""
            )),
            "{command}"
        );
    }

    #[test]
    fn session_ids_are_short_hex_strings() {
        assert!(is_session_id("0123456789abcdef"));
        assert!(!is_session_id("0123456789abcde"));
        assert!(!is_session_id("0123456789abcdeg"));
        assert!(!is_session_id("'; rm -rf / #aaa"));
    }
}
