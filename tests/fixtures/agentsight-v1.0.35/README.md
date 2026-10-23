# AgentSight v1.0.35 parity capture (DR-170)

One run of `workload.py`, captured on 2026-10-23 (kernel 7.3) by AgentSight
v1.0.35's process probe and, side by side, by ebpf-tls-tap's listensnoop and
filesnoop:

- `process.agentsight.jsonl`: `agentsight debug process -- -m 0 --pidns-of
  <workload pid> --trace-net --heartbeat 2`, exactly as printed, banner
  included;
- `listen.listensnoop.jsonl`, `files.filesnoop.jsonl`: `listensnoop -n -H 2`
  and `filesnoop -n -H 2`, entered into the workload's PID namespace with
  `nsenter -p`. The lines the two probes wrote about themselves (they ran
  inside that namespace) are left out.

The workload ran as PID 1 of its own PID namespace (`unshare --pid --fork
--mount-proc`). It listens on a fixed port, port 0, an unbound socket, `[::]:0`
and `[::1]`, binds UDP, accepts one IPv4 and one IPv6 client, reads, writes,
appends, creates two non-UTF-8 names and a 688-byte path, and runs
`/bin/true`. Then it starts a child in a nested PID namespace (a sandboxed tool
call, agentsight#238) and forks from a worker thread (agentsight#240), each
of which listens and writes a file. After it, a process entered with `nsenter
-p` (as `docker exec` enters) listens and writes, and a control process
outside the namespace does both, which neither probe may report. The path
of `workload.py` is rewritten to `/parity/workload.py`.

`tests-python/test_agentsight_adapter.py` checks that the scanner reads the
same listeners, peers and files from the adapted capture as from the probes'.
