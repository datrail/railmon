//! Scoping a capture to one container's process tree (`--process-tree`).
//!
//! `--session` scoped a container's capture to its init's process session,
//! on the assumption that the container's processes share it. They needn't:
//! OpenClaw's CLI runs each turn in a worker that starts a session of its own,
//! so the session filter dropped every model call it made (datrail/railmon#70).
//! A `docker exec` process starts a session of its own too, and keeping those
//! out (the scanner's among them) is what the session filter was for. What
//! tells the two apart is ancestry: the agent's processes descend from the
//! container's init, even when reparented to it, while a `docker exec`
//! process is a child of the runtime's shim, outside the container's tree.
//!
//! A process whose parent left the tree but which stays in the root's own
//! session is in too: when the root leads a session (a keyed target always
//! does), an orphan reparented outside the tree is still the target's, as it
//! was under `--session`.
//!
//! A process is placed once, from `/proc` in the host PID namespace, while
//! it runs, and remembered by its start time, so a PID the kernel reuses is
//! placed again. A record from a process that exited before it was ever
//! placed can't be placed, and is let through, as `--session` lets one
//! through: dropping it would let an agent hide a call in a process that
//! exits at once. Only a process that runs the file the probe hooks makes a
//! record at all, which outside the agent's tree is a `docker exec` process
//! or another container running the same image.

use std::collections::HashMap;
use std::path::PathBuf;

/// Deeper than any real process tree; bounds a walk over a looping `/proc`.
const MAX_DEPTH: usize = 512;
/// Placed processes remembered before exited ones are forgotten, and all of
/// them if none has exited: a running process is cheap to place again.
const MAX_REMEMBERED: usize = 4096;

pub struct ProcessTree {
    root: u32,
    proc: PathBuf,
    /// pid -> (its start time, whether it is in the tree).
    placed: HashMap<u32, (u64, bool)>,
}

impl ProcessTree {
    pub fn new(root: u32) -> Self {
        Self::with_proc(root, "/proc")
    }

    pub fn with_proc(root: u32, proc: impl Into<PathBuf>) -> Self {
        Self {
            root,
            proc: proc.into(),
            placed: HashMap::new(),
        }
    }

    /// Whether a record from `pid` belongs to the capture.
    pub fn admits(&mut self, pid: u32) -> bool {
        if pid == self.root {
            return true;
        }
        let Some((parent, session, start)) = self.stat(pid) else {
            return self.placed.get(&pid).is_none_or(|&(_, inside)| inside);
        };
        if let Some(&(known, inside)) = self.placed.get(&pid) {
            if known == start {
                return inside;
            }
        }
        let inside = session == self.root || self.descends(parent);
        if self.placed.len() >= MAX_REMEMBERED {
            let proc = self.proc.clone();
            self.placed
                .retain(|pid, _| proc.join(pid.to_string()).exists());
            if self.placed.len() >= MAX_REMEMBERED {
                self.placed.clear();
            }
        }
        self.placed.insert(pid, (start, inside));
        inside
    }

    fn descends(&self, mut pid: u32) -> bool {
        for _ in 0..MAX_DEPTH {
            if pid == self.root {
                return true;
            }
            if pid <= 1 {
                return false;
            }
            match self.stat(pid) {
                Some((parent, _, _)) => pid = parent,
                None => return false,
            }
        }
        false
    }

    /// (parent pid, session, start time) from `/proc/<pid>/stat`, read after
    /// the parenthesised comm. The comm is the process's to set: it can hold
    /// spaces, parentheses and bytes that aren't UTF-8, so only the ASCII
    /// fields after it are decoded.
    fn stat(&self, pid: u32) -> Option<(u32, u32, u64)> {
        let bytes = std::fs::read(self.proc.join(pid.to_string()).join("stat")).ok()?;
        let after = bytes.iter().rposition(|&b| b == b')')? + 2;
        let text = std::str::from_utf8(bytes.get(after..)?).ok()?;
        let fields: Vec<&str> = text.split_whitespace().collect();
        // Field 4 is the parent, field 6 the session and field 22 the start
        // time; the slice starts at field 3, the state.
        Some((
            fields.get(1)?.parse().ok()?,
            fields.get(3)?.parse().ok()?,
            fields.get(19)?.parse().ok()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn process(proc: &Path, pid: u32, parent: u32, start: u64, comm: &str) {
        in_session(proc, pid, parent, 0, start, comm);
    }

    fn in_session(proc: &Path, pid: u32, parent: u32, session: u32, start: u64, comm: &str) {
        let dir = proc.join(pid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let mut fields = vec![
            "S".to_string(),
            parent.to_string(),
            "5".into(),
            session.to_string(),
        ];
        fields.extend((7..22).map(|n| n.to_string()));
        fields.push(start.to_string());
        fields.push("0".into());
        std::fs::write(
            dir.join("stat"),
            format!("{pid} ({comm}) {}\n", fields.join(" ")),
        )
        .unwrap();
    }

    fn exit(proc: &Path, pid: u32) {
        std::fs::remove_dir_all(proc.join(pid.to_string())).unwrap();
    }

    /// A container: init 100 runs a launcher 101, whose worker 102 started a
    /// session of its own (OpenClaw's turn); 200 is the shim, whose child 201
    /// is a `docker exec` process.
    fn container(proc: &Path) {
        process(proc, 1, 0, 1, "systemd");
        process(proc, 90, 1, 5, "containerd-shim");
        process(proc, 100, 90, 10, "sh");
        process(proc, 101, 100, 20, "MainThread");
        process(proc, 102, 101, 30, "openclaw");
        process(proc, 201, 90, 40, "python3");
        process(proc, 300, 1, 50, "node");
    }

    #[test]
    fn the_agents_processes_are_in_and_docker_exec_and_the_host_are_out() {
        let dir = tempfile::tempdir().unwrap();
        container(dir.path());
        let mut tree = ProcessTree::with_proc(100, dir.path());
        assert!(tree.admits(100));
        assert!(tree.admits(101));
        assert!(
            tree.admits(102),
            "a worker in a session of its own is still the agent's"
        );
        assert!(!tree.admits(201), "a docker exec process is not");
        assert!(!tree.admits(300), "nor is the host's");
        assert!(!tree.admits(90));
    }

    #[test]
    fn a_reparented_orphan_is_still_in_the_tree() {
        let dir = tempfile::tempdir().unwrap();
        container(dir.path());
        exit(dir.path(), 101);
        process(dir.path(), 102, 100, 30, "openclaw");
        let mut tree = ProcessTree::with_proc(100, dir.path());
        assert!(tree.admits(102));
    }

    #[test]
    fn an_orphan_reparented_out_of_the_tree_stays_in_by_the_roots_session() {
        let dir = tempfile::tempdir().unwrap();
        container(dir.path());
        // A keyed target 101 leads session 101; its daemon 104 was orphaned
        // to the host's init but kept the session, while 105 left both.
        in_session(dir.path(), 101, 100, 101, 20, "agent");
        in_session(dir.path(), 104, 1, 101, 70, "daemon");
        in_session(dir.path(), 105, 1, 105, 80, "daemon");
        let mut tree = ProcessTree::with_proc(101, dir.path());
        assert!(tree.admits(102), "a worker in a session of its own");
        assert!(tree.admits(104), "an orphan still in the target's session");
        assert!(!tree.admits(105), "an orphan that left the session too");
        assert!(!tree.admits(100), "the target's own parent");
    }

    #[test]
    fn an_exited_process_is_judged_by_what_was_seen_while_it_ran() {
        let dir = tempfile::tempdir().unwrap();
        container(dir.path());
        let mut tree = ProcessTree::with_proc(100, dir.path());
        assert!(tree.admits(102));
        assert!(!tree.admits(201));
        exit(dir.path(), 102);
        exit(dir.path(), 201);
        assert!(tree.admits(102));
        assert!(
            !tree.admits(201),
            "a docker exec process stays out after it exits"
        );
    }

    #[test]
    fn a_process_never_seen_alive_is_let_through() {
        let dir = tempfile::tempdir().unwrap();
        container(dir.path());
        let mut tree = ProcessTree::with_proc(100, dir.path());
        assert!(
            tree.admits(4242),
            "a call made from a process that exited at once"
        );
    }

    #[test]
    fn a_comm_that_is_not_utf8_is_read_past() {
        let dir = tempfile::tempdir().unwrap();
        container(dir.path());
        let stat = dir.path().join("102/stat");
        let text = std::fs::read(&stat).unwrap();
        let close = text.iter().position(|&b| b == b')').unwrap();
        let mut bytes = b"102 (ev\xff\xfeil".to_vec();
        bytes.extend_from_slice(&text[close..]);
        std::fs::write(&stat, bytes).unwrap();
        let mut tree = ProcessTree::with_proc(100, dir.path());
        assert!(tree.admits(102));
        assert!(!tree.admits(201));
    }

    #[test]
    fn a_full_memory_of_running_processes_is_started_again() {
        let dir = tempfile::tempdir().unwrap();
        container(dir.path());
        let mut tree = ProcessTree::with_proc(100, dir.path());
        for pid in 0..MAX_REMEMBERED as u32 {
            tree.placed.insert(10_000 + pid, (1, false));
            process(dir.path(), 10_000 + pid, 1, 1, "node");
        }
        assert!(tree.admits(102));
        assert_eq!(tree.placed.len(), 1);
    }

    #[test]
    fn a_reused_pid_is_placed_again() {
        let dir = tempfile::tempdir().unwrap();
        container(dir.path());
        let mut tree = ProcessTree::with_proc(100, dir.path());
        assert!(tree.admits(102));
        exit(dir.path(), 102);
        process(dir.path(), 102, 1, 99, "node");
        assert!(
            !tree.admits(102),
            "the host's process that got the pid is not the agent's"
        );
    }

    #[test]
    fn a_comm_with_spaces_and_parentheses_is_read_past() {
        let dir = tempfile::tempdir().unwrap();
        container(dir.path());
        process(dir.path(), 103, 101, 60, "a) (b c");
        let mut tree = ProcessTree::with_proc(100, dir.path());
        assert!(tree.admits(103));
    }

    #[test]
    fn a_parent_loop_ends() {
        let dir = tempfile::tempdir().unwrap();
        process(dir.path(), 7, 8, 1, "a");
        process(dir.path(), 8, 7, 1, "b");
        let mut tree = ProcessTree::with_proc(100, dir.path());
        assert!(!tree.admits(7));
    }
}
