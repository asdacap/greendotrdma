//! The SSH keys authorized to open a `greendotctl pipe` session — today the
//! Kubernetes CSI controller's login, tomorrow anything that wants to drive
//! the helper protocol without a root credential.
//!
//! greendot-web is unprivileged and cannot even traverse into the packaged
//! user's home (`0750 greendot-csi:greendot-csi`), so key management has to
//! land here. Two rules make that safe to expose on a web form:
//!
//! 1. **The daemon owns the options.** The rpc carries only the public key;
//!    the `command="<us> pipe",restrict` prefix is synthesized from our own
//!    executable path. A compromised web cannot turn a pipe grant into a
//!    shell, because it never gets to say what the key may run.
//! 2. **Foreign lines are never rewritten.** A line we did not author (an
//!    admin's manual entry, possibly a bare key — a full shell) is preserved
//!    byte-for-byte through an add or a revoke, and reported so the diagnostic
//!    can show it in red.
//!
//! Membership of the daemon-socket group is what actually authorizes the key
//! at the helper socket (see `peer_allowed` in `main.rs`); sshd only gets it
//! as far as the pipe. [`report`] surfaces both halves, because a key that
//! logs in and is then rejected at the socket is the confusing failure.

use greendot_proto::ops::SshPublicKeyLine;
use greendot_proto::{SshFingerprint, SubStatus, Task, ops, pb};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{Gid, Uid, chown, fchown, mkstemp};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The packaged SSH login whose `authorized_keys` this module owns.
pub const SSH_USER: &str = "greendot-csi";
/// Where the box's own host keys live, for the known_hosts the page renders.
const SSH_HOST_KEY_GLOB_DIR: &str = "/etc/ssh";
/// Used only if `current_exe()` fails; the path the deb installs.
const FALLBACK_PIPE_BIN: &str = "/usr/libexec/greendotrdma/greendotctl";

/// How this daemon reaches the packaged user's `authorized_keys`.
pub struct PipeKeyConfig {
    /// The SSH login, NSS-resolved for its home directory, uid and gid.
    pub user: String,
    /// The group whose members the helper socket admits (`greendot`).
    pub socket_group: String,
    /// The pipe binary, resolved once at startup (see [`resolve_pipe_bin`]).
    pub pipe_bin: PathBuf,
    /// Test-only: use this directory as the user's home and skip every
    /// ownership change, so the tests run unprivileged (the `--nvmet-root`
    /// idiom).
    pub home_override: Option<PathBuf>,
}

impl PipeKeyConfig {
    /// The exact options prefix we write, and the only one we recognize as
    /// ours. sshd runs this command whatever the client asks for; `restrict`
    /// turns off port/agent/pty forwarding.
    pub fn forced_command(&self) -> String {
        format!("command=\"{} pipe\",restrict", self.pipe_bin.display())
    }
}

/// The pipe binary is *this* binary: the daemon is `greendotctl serve`, and
/// `greendotctl pipe` is the forced command. Resolving it (rather than
/// hardcoding the deb path) is what lets the nix VM test — where greendotctl
/// lives in the store — authorize a working key.
///
/// Resolve once at startup: after a package upgrade `/proc/self/exe` reads
/// `…(deleted)`, and that must never reach `authorized_keys`.
pub fn resolve_pipe_bin() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| FALLBACK_PIPE_BIN.into())
}

/// The resolved target: where the file is, and who must own it.
struct Target {
    home: PathBuf,
    ssh_dir: PathBuf,
    authorized_keys: PathBuf,
    /// `None` under `home_override` — the tests are not root and own the tree
    /// already.
    ids: Option<(Uid, Gid)>,
}

fn resolve(cfg: &PipeKeyConfig) -> io::Result<Target> {
    let (home, ids) = match &cfg.home_override {
        Some(home) => (home.clone(), None),
        None => {
            let user = nix::unistd::User::from_name(&cfg.user)
                .map_err(io::Error::other)?
                .ok_or_else(|| io::Error::other(format!("user {} does not exist", cfg.user)))?;
            (user.dir, Some((user.uid, user.gid)))
        }
    };
    let ssh_dir = home.join(".ssh");
    Ok(Target {
        authorized_keys: ssh_dir.join("authorized_keys"),
        ssh_dir,
        home,
        ids,
    })
}

/// One `authorized_keys` line. `raw` is what we write back, so a line we did
/// not author survives verbatim.
struct Line {
    raw: String,
    kind: LineKind,
}

enum LineKind {
    /// Blank or a `#` comment.
    Blank,
    Key(ParsedKey),
    /// A key line we could not parse. Preserved, and counted — an entry we
    /// cannot read is one whose options we also cannot vouch for.
    Unparsable,
}

struct ParsedKey {
    key: SshPublicKeyLine,
    options: String,
    /// The options are exactly the forced command we synthesize.
    ours: bool,
}

/// Split an `authorized_keys` line into its options prefix and key body.
/// sshd reads options up to the first unquoted space, so a `"`-quoted option
/// value (`command="a b"`) may contain spaces; walk the line with that rule
/// rather than splitting on the first space.
fn split_options(line: &str) -> (&str, &str) {
    // A line that already parses as a key has no options at all.
    if SshPublicKeyLine::new(line).is_ok() {
        return ("", line);
    }
    let mut in_quotes = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => return (&line[..i], line[i..].trim_start()),
            _ => {}
        }
    }
    ("", line)
}

/// Parse one line. The key body goes through the same validated parser the
/// `PipeKeyAdd` ingress uses, so what we display is what we would accept.
fn parse_line(raw: &str, forced_command: &str) -> Line {
    let trimmed = raw.trim();
    let raw = raw.to_owned();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Line {
            raw,
            kind: LineKind::Blank,
        };
    }
    let (options, body) = split_options(trimmed);
    match SshPublicKeyLine::new(body) {
        Ok(key) => Line {
            raw,
            kind: LineKind::Key(ParsedKey {
                key,
                options: options.to_owned(),
                ours: options == forced_command,
            }),
        },
        Err(_) => Line {
            raw,
            kind: LineKind::Unparsable,
        },
    }
}

impl Line {
    fn key(&self) -> Option<&ParsedKey> {
        match &self.kind {
            LineKind::Key(key) => Some(key),
            _ => None,
        }
    }

    fn has_fingerprint(&self, fingerprint: &str) -> bool {
        self.key()
            .is_some_and(|k| k.key.fingerprint().as_str() == fingerprint)
    }
}

/// Read and parse the file. A missing file is an empty key set, not an error:
/// the packaged user starts with no `.ssh` at all.
fn read_lines(target: &Target, forced_command: &str) -> io::Result<Vec<Line>> {
    let text = match std::fs::read_to_string(&target.authorized_keys) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    Ok(text
        .lines()
        .map(|raw| parse_line(raw, forced_command))
        .collect())
}

/// `.ssh` must exist, be private, and belong to the SSH user — sshd refuses to
/// read a group- or world-writable `authorized_keys` path.
fn ensure_ssh_dir(target: &Target) -> io::Result<()> {
    if !target.ssh_dir.exists() {
        std::fs::create_dir_all(&target.ssh_dir)?;
    }
    std::fs::set_permissions(&target.ssh_dir, std::fs::Permissions::from_mode(0o700))?;
    if let Some((uid, gid)) = target.ids {
        chown(&target.ssh_dir, Some(uid), Some(gid))?;
    }
    Ok(())
}

/// Write the file through a sibling temp file: same directory, so `rename` is
/// on one filesystem and cannot `EXDEV`; owner and mode set *before* the
/// rename, so the file never appears at its final path readable by anyone
/// else; the temp file removed on any failure.
fn write_atomic(target: &Target, body: &str) -> io::Result<()> {
    let template = target.ssh_dir.join(".authorized_keys.XXXXXX");
    let (fd, tmp) = mkstemp(&template)?;
    let write = || -> io::Result<()> {
        let mut file = std::fs::File::from(fd);
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
        fchmod(&file, Mode::from_bits_truncate(0o600))?;
        if let Some((uid, gid)) = target.ids {
            fchown(&file, Some(uid), Some(gid))?;
        }
        Ok(())
    };
    match write().and_then(|()| std::fs::rename(&tmp, &target.authorized_keys)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Every line back, newline-terminated. Foreign lines round-trip through
/// `raw`, so an admin's hand-written entry survives byte-for-byte.
fn render(lines: &[Line]) -> String {
    lines.iter().map(|l| format!("{}\n", l.raw)).collect()
}

/// Runs one step as a named subtask (the `nvmet::step` idiom): the closure's
/// status completes it, an `Err` records the message and fails it. `Err` from
/// this fn is only a sink failure (the client is gone).
fn step(
    task: &mut Task,
    name: String,
    f: impl FnOnce() -> io::Result<SubStatus>,
) -> io::Result<SubStatus> {
    let mut sub = task.begin_subtask(name);
    match f() {
        Ok(status) => {
            sub.complete(status);
            Ok(status)
        }
        Err(e) => {
            writeln!(sub.stderr(), "{e}")?;
            sub.set_result(1, Some(e.to_string()));
            sub.complete(SubStatus::Failed);
            Ok(SubStatus::Failed)
        }
    }
}

/// The `PipeKeyAdd` op. Idempotent: re-adding a fingerprint that is already
/// authorized is a Skipped no-op, not a duplicate line.
pub fn add(cfg: &PipeKeyConfig, op: &ops::PipeKeyAdd, task: &mut Task) -> io::Result<()> {
    let forced = cfg.forced_command();
    let fingerprint = op.public_key.fingerprint().as_str().to_owned();

    let mut target = None;
    let done = step(task, format!("Resolve {}", cfg.user), || {
        target = Some(resolve(cfg)?);
        Ok(SubStatus::Success)
    })?;
    if done == SubStatus::Failed {
        return Ok(());
    }
    let target = target.expect("resolve succeeded");

    let done = step(task, "Ensure .ssh directory".into(), || {
        ensure_ssh_dir(&target)?;
        Ok(SubStatus::Success)
    })?;
    if done == SubStatus::Failed {
        return Ok(());
    }

    step(task, format!("Authorize key {fingerprint}"), || {
        let lines = read_lines(&target, &forced)?;
        if lines.iter().any(|l| l.has_fingerprint(&fingerprint)) {
            return Ok(SubStatus::Skipped);
        }
        // The options come from us, never from the request; the key body is
        // the canonical re-serialization, never the admin's bytes.
        let mut body = render(&lines);
        body.push_str(&format!("{forced} {}\n", op.public_key.canonical()));
        write_atomic(&target, &body)?;
        Ok(SubStatus::Success)
    })?;
    Ok(())
}

/// The `PipeKeyRevoke` op. Absent-tolerant (Skipped), and matches on the
/// fingerprint alone — so a key an admin installed by hand, forced command or
/// not, can be revoked from the page too.
pub fn revoke(
    cfg: &PipeKeyConfig,
    fingerprint: &SshFingerprint,
    task: &mut Task,
) -> io::Result<()> {
    let forced = cfg.forced_command();

    let mut target = None;
    let done = step(task, format!("Resolve {}", cfg.user), || {
        target = Some(resolve(cfg)?);
        Ok(SubStatus::Success)
    })?;
    if done == SubStatus::Failed {
        return Ok(());
    }
    let target = target.expect("resolve succeeded");

    step(task, format!("Revoke key {fingerprint}"), || {
        let lines = read_lines(&target, &forced)?;
        let (drop, keep): (Vec<Line>, Vec<Line>) = lines
            .into_iter()
            .partition(|l| l.has_fingerprint(fingerprint.as_str()));
        if drop.is_empty() {
            return Ok(SubStatus::Skipped);
        }
        write_atomic(&target, &render(&keep))?;
        Ok(SubStatus::Success)
    })?;
    Ok(())
}

/// The `PipeAccessReport` typed read. Best-effort throughout: a fact we cannot
/// establish is reported as false/empty, and the web renders that as a failed
/// criterion rather than an error page.
pub fn report(cfg: &PipeKeyConfig) -> pb::PipeAccessReportReply {
    let forced = cfg.forced_command();
    let mut reply = pb::PipeAccessReportReply {
        user: cfg.user.clone(),
        socket_group: cfg.socket_group.clone(),
        forced_command: forced.clone(),
        forced_command_bin_ok: is_executable(&cfg.pipe_bin),
        host_keys: host_keys(Path::new(SSH_HOST_KEY_GLOB_DIR)),
        ..Default::default()
    };

    let target = match resolve(cfg) {
        Ok(target) => target,
        // Under a home_override the user need not exist; the tests and the
        // report agree that the rest is still readable.
        Err(_) => return reply,
    };
    reply.user_exists = cfg.home_override.is_some() || target.ids.is_some();
    reply.in_socket_group = cfg.home_override.is_some() || in_socket_group(cfg);

    // sshd walks the home dir, .ssh and the file itself; any one of them owned
    // by the wrong user makes it refuse the key with nothing in the client's
    // face. Under a home_override the tree is the test's own, so skip owner.
    let want_owner = target.ids.map(|(uid, _)| uid.as_raw());
    (reply.home_ok, reply.home_detail) = check_strict_modes(&target.home, want_owner, false);
    (reply.ssh_dir_ok, reply.ssh_dir_detail) =
        check_strict_modes(&target.ssh_dir, want_owner, false);
    // An absent authorized_keys is fine — it means no key is authorized yet.
    (reply.authorized_keys_ok, reply.authorized_keys_detail) =
        check_strict_modes(&target.authorized_keys, want_owner, true);

    if let Ok(lines) = read_lines(&target, &forced) {
        reply.unparsable_lines = lines
            .iter()
            .filter(|l| matches!(l.kind, LineKind::Unparsable))
            .count() as u32;
        reply.keys = lines
            .iter()
            .filter_map(Line::key)
            .map(|k| pb::PipeKeyEntry {
                fingerprint: k.key.fingerprint().as_str().to_owned(),
                algorithm: k.key.algorithm().to_owned(),
                comment: k.key.comment().to_owned(),
                forced_command_ok: k.ours,
                options: k.options.clone(),
            })
            .collect();
    }
    reply
}

/// Whether the SSH user is in the group the helper socket admits. Without it
/// sshd runs the forced command and the daemon then hangs up on the pipe —
/// the failure this criterion exists to name.
fn in_socket_group(cfg: &PipeKeyConfig) -> bool {
    let Ok(Some(user)) = nix::unistd::User::from_name(&cfg.user) else {
        return false;
    };
    let Ok(Some(group)) = nix::unistd::Group::from_name(&cfg.socket_group) else {
        return false;
    };
    if user.gid == group.gid {
        return true;
    }
    group.mem.contains(&cfg.user)
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// `(ok, detail)` for one path under sshd's StrictModes rule: it must be owned
/// by root or by the SSH user, and not writable by group or other. This is
/// deliberately sshd's rule rather than "exactly 0700", so a tree that is
/// stricter than the one we write is not reported as broken.
///
/// `absent_ok` reports a missing path as fine (no key authorized yet).
fn check_strict_modes(path: &Path, want_owner: Option<u32>, absent_ok: bool) -> (bool, String) {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return match absent_ok {
                true => (true, format!("{} does not exist yet", path.display())),
                false => (false, format!("{} does not exist", path.display())),
            };
        }
        Err(e) => return (false, format!("{}: {e}", path.display())),
    };
    let (mode, uid) = (meta.permissions().mode() & 0o777, meta.uid());
    if mode & 0o022 != 0 {
        return (
            false,
            format!(
                "{} is {mode:04o} — sshd refuses a group- or world-writable path",
                path.display()
            ),
        );
    }
    if let Some(owner) = want_owner
        && uid != owner
        && uid != 0
    {
        return (
            false,
            format!(
                "{} is owned by uid {uid} — sshd requires root or uid {owner}",
                path.display()
            ),
        );
    }
    (true, format!("{} {mode:04o}", path.display()))
}

/// The box's own host keys, so the page can render a `known_hosts` line and
/// retire the `ssh-keyscan` trust-on-first-use step. We ship the bare key
/// line: only the browser knows what hostname the admin reaches the box by.
fn host_keys(dir: &Path) -> Vec<pb::HostKey> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut keys: Vec<pb::HostKey> = entries
        .filter_map(Result::ok)
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("ssh_host_") && name.ends_with(".pub")
        })
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|text| SshPublicKeyLine::new(text).ok())
        .map(|k| pb::HostKey {
            algorithm: k.algorithm().to_owned(),
            fingerprint: k.fingerprint().as_str().to_owned(),
            // A known_hosts entry is host + type + base64: no comment.
            key_line: k.key_only().to_owned(),
        })
        .collect();
    keys.sort_by(|a, b| a.algorithm.cmp(&b.algorithm));
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test::Collector;
    use greendot_proto::TaskEvent;
    use greendot_proto::ops::SshPublicKeyLine;

    const KEY_A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdhWt9PS+RZA4evy8mCnJjidpS48BAw5bb6TV7mGJ26 admin@laptop";
    const FP_A: &str = "SHA256:NEU/y0JmR4RY7ck8XRGElQSKmEzy2SirhXgqbFWxZ00";
    const KEY_B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFGvh5dCNEpW2su1YjKfn7o6vBmSKLBY0y1MSjCJ7VXs ci@runner";
    const FP_B: &str = "SHA256:PTvF/Bqiml/FpQj4Txm/tyvd9k+/e4RKrZxJix35Weg";
    const PIPE_BIN: &str = "/usr/libexec/greendotrdma/greendotctl";
    /// A line this UI never wrote: no forced command, so it is a full shell.
    const FOREIGN: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIziEv2eE0qWpMVbe4hxnInGUUvAy+iySGuhXKJEId1u root@somewhere";

    fn cfg(home: &Path) -> PipeKeyConfig {
        PipeKeyConfig {
            user: SSH_USER.into(),
            socket_group: "greendot".into(),
            pipe_bin: PIPE_BIN.into(),
            home_override: Some(home.to_path_buf()),
        }
    }

    fn forced() -> String {
        format!("command=\"{PIPE_BIN} pipe\",restrict")
    }

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gd-pipekeys-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run(f: impl FnOnce(&mut Task) -> io::Result<()>) -> Vec<TaskEvent> {
        let mut c = Collector::default();
        let mut task = Task::new(&mut c);
        f(&mut task).unwrap();
        task.complete().unwrap();
        c.events
    }

    fn subtask_names(events: &[TaskEvent]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match e {
                TaskEvent::SubtaskStarted { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect()
    }

    /// The status of the last subtask — Skipped vs Success is the idempotence
    /// signal the web renders.
    fn last_subtask_status(events: &[TaskEvent]) -> SubStatus {
        events
            .iter()
            .filter_map(|e| match e {
                TaskEvent::SubtaskFinished { status, .. } => Some(*status),
                _ => None,
            })
            .next_back()
            .expect("a subtask ran")
    }

    fn add_key(cfg: &PipeKeyConfig, key: &str) -> Vec<TaskEvent> {
        let op = ops::PipeKeyAdd {
            public_key: SshPublicKeyLine::new(key).unwrap(),
        };
        run(|t| add(cfg, &op, t))
    }

    fn revoke_key(cfg: &PipeKeyConfig, fp: &str) -> Vec<TaskEvent> {
        let fp = SshFingerprint::new(fp).unwrap();
        run(|t| revoke(cfg, &fp, t))
    }

    fn read_keys(home: &Path) -> String {
        std::fs::read_to_string(home.join(".ssh/authorized_keys")).unwrap_or_default()
    }

    fn seed(home: &Path, body: &str) {
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".ssh/authorized_keys"), body).unwrap();
    }

    /// The whole lifecycle against one tempdir home: the first add creates a
    /// private `.ssh`, every authorized line carries the forced command,
    /// re-adding is Skipped, and revoke is absent-tolerant.
    #[test]
    fn add_is_idempotent_and_revoke_is_absent_tolerant() {
        let home = tmpdir("lifecycle");
        let cfg = cfg(&home);

        let events = add_key(&cfg, KEY_A);
        assert_eq!(
            subtask_names(&events),
            [
                format!("Resolve {SSH_USER}"),
                "Ensure .ssh directory".into(),
                format!("Authorize key {FP_A}")
            ]
        );
        assert_eq!(last_subtask_status(&events), SubStatus::Success);
        assert_eq!(read_keys(&home), format!("{} {KEY_A}\n", forced()));
        // sshd refuses a group-readable .ssh; the key file is ours alone.
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(home.join(".ssh")), 0o700);
        assert_eq!(mode(home.join(".ssh/authorized_keys")), 0o600);

        // Re-adding the same fingerprint must not append a second line.
        let events = add_key(&cfg, KEY_A);
        assert_eq!(last_subtask_status(&events), SubStatus::Skipped);
        assert_eq!(read_keys(&home), format!("{} {KEY_A}\n", forced()));

        add_key(&cfg, KEY_B);
        assert_eq!(
            read_keys(&home),
            format!("{f} {KEY_A}\n{f} {KEY_B}\n", f = forced())
        );

        let events = revoke_key(&cfg, FP_A);
        assert_eq!(last_subtask_status(&events), SubStatus::Success);
        assert_eq!(read_keys(&home), format!("{} {KEY_B}\n", forced()));

        // Revoking what is already gone is a no-op, not a failure — the web
        // retries, and a fenced key must stay fenced.
        let events = revoke_key(&cfg, FP_A);
        assert_eq!(last_subtask_status(&events), SubStatus::Skipped);
        assert_eq!(read_keys(&home), format!("{} {KEY_B}\n", forced()));

        std::fs::remove_dir_all(&home).unwrap();
    }

    /// A line we did not author — an admin's manual entry, here without a
    /// forced command, i.e. a full shell — survives an add and a revoke of
    /// another key byte-for-byte, and is reported as not-ours so the
    /// diagnostic can flag it.
    #[test]
    fn foreign_lines_are_preserved_and_flagged() {
        let home = tmpdir("foreign");
        let cfg = cfg(&home);
        seed(&home, &format!("# managed by hand\n{FOREIGN}\n"));

        add_key(&cfg, KEY_A);
        assert_eq!(
            read_keys(&home),
            format!("# managed by hand\n{FOREIGN}\n{} {KEY_A}\n", forced())
        );

        let report = report(&cfg);
        let ours: Vec<_> = report.keys.iter().map(|k| k.forced_command_ok).collect();
        assert_eq!(ours, [false, true], "the bare key is not ours");
        assert_eq!(report.keys[0].options, "", "a bare key has no options");
        assert_eq!(report.keys[1].fingerprint, FP_A);
        assert_eq!(report.keys[1].comment, "admin@laptop");
        assert_eq!(report.forced_command, forced());

        revoke_key(&cfg, FP_A);
        assert_eq!(
            read_keys(&home),
            format!("# managed by hand\n{FOREIGN}\n"),
            "revoking our key leaves the foreign line untouched"
        );
        std::fs::remove_dir_all(&home).unwrap();
    }

    /// Revoke matches on the fingerprint alone, so a hand-installed shell key
    /// can be removed from the page — the reason the diagnostic bothers to
    /// surface it.
    #[test]
    fn a_foreign_key_can_be_revoked_by_fingerprint() {
        let home = tmpdir("revoke-foreign");
        let cfg = cfg(&home);
        seed(&home, &format!("{KEY_B}\n"));

        let events = revoke_key(&cfg, FP_B);
        assert_eq!(last_subtask_status(&events), SubStatus::Success);
        assert_eq!(read_keys(&home), "");
        std::fs::remove_dir_all(&home).unwrap();
    }

    /// sshd parses options up to the first *unquoted* space; our own forced
    /// command contains one inside `command="… pipe"`.
    #[test]
    fn options_split_respects_quoted_spaces() {
        let line = format!("{} {KEY_A}", forced());
        assert_eq!(split_options(&line), (forced().as_str(), KEY_A));
        // A bare key has no options at all.
        assert_eq!(split_options(KEY_A), ("", KEY_A));
        // A foreign options prefix is captured, not mistaken for a key.
        let other = format!("no-pty,command=\"/bin/sh -c id\" {KEY_A}");
        assert_eq!(
            split_options(&other),
            ("no-pty,command=\"/bin/sh -c id\"", KEY_A)
        );
    }

    /// sshd refuses a key whose home, `.ssh` or `authorized_keys` is writable
    /// by group or other, and says nothing useful to the client. The report is
    /// where that shows up — so it must actually notice.
    #[test]
    fn a_group_writable_path_fails_the_strict_modes_check() {
        let home = tmpdir("strictmodes");
        let cfg = cfg(&home);
        add_key(&cfg, KEY_A);
        assert!(report(&cfg).ssh_dir_ok);

        std::fs::set_permissions(home.join(".ssh"), std::fs::Permissions::from_mode(0o770))
            .unwrap();
        let writable = report(&cfg);
        assert!(!writable.ssh_dir_ok);
        assert!(writable.ssh_dir_detail.contains("group- or world-writable"));
        // A stricter-than-ours tree is still fine: this is sshd's rule, not
        // an exact-mode match.
        std::fs::set_permissions(home.join(".ssh"), std::fs::Permissions::from_mode(0o500))
            .unwrap();
        assert!(report(&cfg).ssh_dir_ok);

        std::fs::set_permissions(home.join(".ssh"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::fs::remove_dir_all(&home).unwrap();
    }

    /// The report degrades rather than erroring when nothing has been set up
    /// yet: no `.ssh`, no keys, but the forced command is still shown so the
    /// admin can see what would be written.
    #[test]
    fn report_on_a_bare_home_is_empty_not_failed() {
        let home = tmpdir("bare");
        let cfg = cfg(&home);
        let report = report(&cfg);
        assert!(report.keys.is_empty());
        assert!(report.home_ok, "the home dir exists and is ours");
        assert!(!report.ssh_dir_ok, "no .ssh yet");
        assert!(
            report.authorized_keys_ok,
            "an absent authorized_keys is fine — no key authorized yet"
        );
        assert_eq!(report.forced_command, forced());
        assert!(
            !report.forced_command_bin_ok,
            "the deb path is not installed here"
        );
        std::fs::remove_dir_all(&home).unwrap();
    }
}
