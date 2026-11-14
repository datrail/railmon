# Changelog

Notable changes to RailMon, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases are the
`v0.1.0-mN` milestone tags; each date is the tagged commit's date.

A line marked **Rule pack N** bumps `rule_pack_version`
(`RULE_PACK_VERSION` in `tools/scan/evidence_bundle.py`). After a bump, a
baseline locked on the previous pack reads `CONTRACT_MISMATCH` until it is
re-locked.

Each PR adds its line under `## Unreleased`.

## Unreleased

Rule pack 14 (unchanged since v0.1.0-m15).

### Added

- `railmon scan --mode pod` runs the scanner as a sidecar in a Kubernetes pod and names the agent from the downward API ([#122](https://github.com/datrail/railmon/pull/122)).
- Pod mode reads the agent's own process, found again after a restart, instead of the sidecar's ([#123](https://github.com/datrail/railmon/pull/123)).
- `asp_spelling`, a standard-library package holding the one ASP value spelling RailDash and Rail Center both read ([#118](https://github.com/datrail/railmon/pull/118)).
- `asp_normalize`, one normalization from an evidence bundle (v1 or v2) to each agent's attributes ([#119](https://github.com/datrail/railmon/pull/119)).

### Changed

- A tag's GitHub Release notes open with the annotated tag's message ([#121](https://github.com/datrail/railmon/pull/121)).
- The Dockerfile's comment on the OpenShell CLI no longer says CI installs the same release ([#120](https://github.com/datrail/railmon/pull/120)).

## [v0.1.0-m16] - 2026-11-03

Rule pack 14 (unchanged).

### Changed

- The container release workflow creates the tag's GitHub Release ([#117](https://github.com/datrail/railmon/pull/117)).

### Security

- rustls 0.23.46, for four advisories ([#116](https://github.com/datrail/railmon/pull/116)).

## [v0.1.0-m15] - 2026-10-29

### Added

- `egress_containment` carries an OpenShell sandbox's allow-list, read from OpenShell by `railmon openshell` ([#115](https://github.com/datrail/railmon/pull/115)).

### Changed

- **Rule pack 14.** A crowded group of written files is listed as `<dir>/*.<ext>`, so a write isn't lost to the list cap; OpenShell placeholders are classified as references ([#113](https://github.com/datrail/railmon/pull/113)).
- Skills name their MCP server and say whether they are a tool or a server; a probed tool keeps its `inputSchema` and annotations ([#114](https://github.com/datrail/railmon/pull/114)).
- A keyed target's tap follows its uid and process tree, not one session ([#111](https://github.com/datrail/railmon/pull/111)).
- CONTRIBUTING documents the required `rail-review` status ([#112](https://github.com/datrail/railmon/pull/112)).

## [v0.1.0-m14] - 2026-10-27

### Fixed

- `railmon collect` follows the container's process tree, not one session, so a real OpenClaw agent's calls are captured ([#110](https://github.com/datrail/railmon/pull/110)).

## [v0.1.0-m13] - 2026-10-24

### Fixed

- An agent switched to a new target starts on a fresh listen and files file ([#109](https://github.com/datrail/railmon/pull/109)).

## [v0.1.0-m12] - 2026-10-24

### Fixed

- A streamed reply whose connection closed between chunks is recorded and paired with its request ([#108](https://github.com/datrail/railmon/pull/108)).

## [v0.1.0-m11] - 2026-10-24

### Changed

- The image's OpenShell CLI is 0.1.5 ([#107](https://github.com/datrail/railmon/pull/107)).

### Fixed

- An OpenShell L7 denial's port comes from its URL's scheme ([#107](https://github.com/datrail/railmon/pull/107)).

## [v0.1.0-m10] - 2026-10-24

### Added

- `railmon openshell` posts an OpenShell sandbox's policy and its supervisor's denials to RailDash ([#106](https://github.com/datrail/railmon/pull/106)).

## [v0.1.0-m9] - 2026-10-24

### Added

- Follow an OpenShell sandbox by name, `openshell:<sandbox>` ([#105](https://github.com/datrail/railmon/pull/105)).

## [v0.1.0-m8] - 2026-10-24

Rule pack 13 (unchanged).

### Changed

- `railmon collect` pairs a reply with its request by AgentSight 1.0.35's `http_exchange_id` ([#104](https://github.com/datrail/railmon/pull/104)).

### Fixed

- RailDash's local token is passed as `--token=…` ([#103](https://github.com/datrail/railmon/pull/103)).

## [v0.1.0-m7] - 2026-10-23

### Changed

- **Rule pack 13.** `listen` and `files` run AgentSight v1.0.35's process probe by default; RailMon no longer carries its own eBPF probes ([#102](https://github.com/datrail/railmon/pull/102)).

## [v0.1.0-m6] - 2026-10-23

### Added

- AgentSight's process probe can feed the listen and files lines, opt-in ([#99](https://github.com/datrail/railmon/pull/99)).
- The demo agent declares its MCP server; the demo client opens a GET stream and ends its session ([#101](https://github.com/datrail/railmon/pull/101)).

### Changed

- **Rule pack 12.** The user is read from the image's `Config.User`, MCP allow lists are recorded, credential names are narrowed, and JSON is parsed strictly ([#98](https://github.com/datrail/railmon/pull/98)).
- A target manifest without agent keys fails closed with `MULTI_AGENT_KEY_REQUIRED` instead of sending an unkeyed v1 bundle ([#100](https://github.com/datrail/railmon/pull/100)).

## [v0.1.0-m5] - 2026-10-20

### Changed

- The release builds each architecture natively, without QEMU ([#92](https://github.com/datrail/railmon/pull/92)).
- The docs name Rail Center's register route, not its removed evidence-bundles route ([#95](https://github.com/datrail/railmon/pull/95)).
- The scan README says Rail Center's register answer carries no ticket ([#96](https://github.com/datrail/railmon/pull/96)).

### Fixed

- A compressed HTTP/1 reply is decoded before the parser reads it as text ([#94](https://github.com/datrail/railmon/pull/94)).

## [v0.1.0-m4] - 2026-10-13

### Added

- Emit ASP v1 deployment identity keys ([#19](https://github.com/datrail/railmon/pull/19)).
- Capture multiple agents without collapsing their identities ([#21](https://github.com/datrail/railmon/pull/21)).
- Probe each MCP server's `tools/list` instead of synthesizing one skill ([#22](https://github.com/datrail/railmon/pull/22)).
- Deliver evidence bundles to RailDash and scan on an interval ([#24](https://github.com/datrail/railmon/pull/24)).
- Send `X-RailDash-Token` with evidence-bundle delivery ([#25](https://github.com/datrail/railmon/pull/25)).
- Discover MCP servers declared through environment variables ([#26](https://github.com/datrail/railmon/pull/26)).
- Publish the evidence bundle v2 schema with its own fixtures ([#27](https://github.com/datrail/railmon/pull/27)).
- Run agent-scoped scanning and registration once per agent key ([#30](https://github.com/datrail/railmon/pull/30)).
- Emit and validate evidence bundle v2 ([#31](https://github.com/datrail/railmon/pull/31)).
- Resolve non-delegated cgroup locators to a process incarnation ([#33](https://github.com/datrail/railmon/pull/33)).
- Capture, log and expose `RAIL_AGENT_KEY` as a diagnostic hint ([#34](https://github.com/datrail/railmon/pull/34)).
- Restart a target's tap safely across process exit and PID reuse ([#35](https://github.com/datrail/railmon/pull/35)).
- Judge an unsigned x-rail ticket against the process target ([#36](https://github.com/datrail/railmon/pull/36)).
- The image ships the v2 bundle schema ([#38](https://github.com/datrail/railmon/pull/38)).
- Document multi-agent manifest authoring, reporting, diagnosis and rollback ([#39](https://github.com/datrail/railmon/pull/39)).
- Scanner registration takes a token file and the `gcp` mode ([#48](https://github.com/datrail/railmon/pull/48)).
- **Rule pack 2.** Listening sockets fold into observed reach as a drift signal ([#49](https://github.com/datrail/railmon/pull/49)).
- The image ships listensnoop as `railmon listen` ([#50](https://github.com/datrail/railmon/pull/50)).
- **Rule pack 3.** Accepted peers fold into the bundle as `observed_ingress_peers` ([#51](https://github.com/datrail/railmon/pull/51)).
- **Rule pack 4.** filesnoop's file opens fold into the bundle as `observed_file_access` ([#58](https://github.com/datrail/railmon/pull/58)).
- The v1 schema publishes `observed_file_access`'s value shape ([#59](https://github.com/datrail/railmon/pull/59)).
- Evidence bundle v2 attributes may carry an optional `window` member ([#64](https://github.com/datrail/railmon/pull/64)), and the six window-bounded lists emit it ([#65](https://github.com/datrail/railmon/pull/65)).
- Record the sockets the agent was already listening on when listen attached ([#67](https://github.com/datrail/railmon/pull/67)).
- `railmon collect` follows a container: its TLS library, its process session and its restarts ([#72](https://github.com/datrail/railmon/pull/72)).
- **Rule pack 8.** The evidence bundle carries every field the registration payload does ([#74](https://github.com/datrail/railmon/pull/74)).
- **Rule pack 9.** The bundle carries dynamic agent data, and the schema publishes which attributes are dynamic ([#76](https://github.com/datrail/railmon/pull/76)).
- Send Rail Center the evidence bundle on `/v1/agents/register` ([#79](https://github.com/datrail/railmon/pull/79)).
- Send RailDash's write token with every capture, and a heartbeat while a tap is attached ([#82](https://github.com/datrail/railmon/pull/82)).
- The demo agent has an MCP server, reads through it, and can upload on demand ([#85](https://github.com/datrail/railmon/pull/85)).
- `demo_mcp_call.py --big N` measures the capture past its 1 MiB bound ([#86](https://github.com/datrail/railmon/pull/86)).
- Capture an agent in an OpenShell sandbox: the collector finds it, and runc's per-exec procfs paths fold ([#87](https://github.com/datrail/railmon/pull/87)).
- **Rule pack 11.** The bundle says whether the agent's egress is contained (`egress_containment`) ([#88](https://github.com/datrail/railmon/pull/88)).
- The arm64 image installs AgentSight's aarch64 build ([#90](https://github.com/datrail/railmon/pull/90)).

### Changed

- Align the evidence source schema ([#20](https://github.com/datrail/railmon/pull/20)).
- One canonical evidence-bundle schema, walked rather than re-coded by hand ([#23](https://github.com/datrail/railmon/pull/23)).
- RailScan-era names move to RailMon's; the old ones keep working ([#53](https://github.com/datrail/railmon/pull/53)).
- `railmon forward` sends interactions in Rail Center's batch envelope ([#56](https://github.com/datrail/railmon/pull/56)).
- Take agentsight-capture 1.0.34, which drops hpack 0.3 for loona-hpack ([#62](https://github.com/datrail/railmon/pull/62)).
- The image pins the AgentSight release it downloads and checks its SHA-256 ([#83](https://github.com/datrail/railmon/pull/83)).
- **Rule pack 5.** Randomly named temp files fold in observed file access ([#60](https://github.com/datrail/railmon/pull/60)).
- **Rule pack 6.** `observed_destinations` reads `BLIND` when no AgentSight snapshot was given ([#61](https://github.com/datrail/railmon/pull/61)).
- **Rule pack 7.** `observed_file_access` folds `/proc/<pid>` paths to `/proc/*/` ([#69](https://github.com/datrail/railmon/pull/69)).
- Each distinct file open is appended once, so an always-on `files.jsonl` stays bounded ([#68](https://github.com/datrail/railmon/pull/68)).
- **Rule pack 10.** Python bytecode-cache writes fold into `<dir>/__pycache__/*.pyc` ([#84](https://github.com/datrail/railmon/pull/84)).
- `RAIL_AUTH_MODE` applies to the collector's webhook and `railmon forward` ([#47](https://github.com/datrail/railmon/pull/47)).
- The skills scanner does not register with Rail Center ([#80](https://github.com/datrail/railmon/pull/80)).
- Point a new user at datrail-project first ([#66](https://github.com/datrail/railmon/pull/66)); the README's opening says what RailMon does today ([#91](https://github.com/datrail/railmon/pull/91)).
- Correct the public docs and drop internal references ([#55](https://github.com/datrail/railmon/pull/55)); fix documentation drift and remove duplicate code, no behaviour change ([#77](https://github.com/datrail/railmon/pull/77)); the scan README states where the bundle goes ([#73](https://github.com/datrail/railmon/pull/73)).
- CI and releases run on `ubuntu-26.04` by name ([#46](https://github.com/datrail/railmon/pull/46)); workflow actions move to their Node 24 majors ([#63](https://github.com/datrail/railmon/pull/63)).
- CI runs the RailMon and RailDash images together ([#44](https://github.com/datrail/railmon/pull/44)), with acceptance against the built image: fail-closed and single-agent cases ([#41](https://github.com/datrail/railmon/pull/41)), stricter fail-closed evidence checks ([#42](https://github.com/datrail/railmon/pull/42)) and stale PID reuse ([#43](https://github.com/datrail/railmon/pull/43)); an end-to-end check that RailDash locks a multi-agent baseline and reports a stopped agent as drift on that agent ([#52](https://github.com/datrail/railmon/pull/52)); tests for target-manifest validation and ownership ([#28](https://github.com/datrail/railmon/pull/28)) and for owner-only keyed artifacts that keep no ticket ([#32](https://github.com/datrail/railmon/pull/32)).

### Fixed

- One bad target no longer aborts a whole multi-agent run ([#29](https://github.com/datrail/railmon/pull/29)).
- An analyzer panic on captured traffic is contained to its own tap ([#37](https://github.com/datrail/railmon/pull/37)).
- Shut down cleanly on SIGTERM, not only SIGINT ([#40](https://github.com/datrail/railmon/pull/40)).
- A colliding process is captured as ambiguous instead of left untapped ([#45](https://github.com/datrail/railmon/pull/45)).
- A scan fails on an invalid bundle, config is documented, and interval scans no longer pile up ASPs ([#54](https://github.com/datrail/railmon/pull/54)).
- The interval PID-reuse test replaces only the scanner's sleep ([#57](https://github.com/datrail/railmon/pull/57)).
- A request whose response never pairs is forwarded as incomplete, with a count ([#71](https://github.com/datrail/railmon/pull/71)).
- A Node agent's reads on other connections stay out of a streamed reply ([#75](https://github.com/datrail/railmon/pull/75)).
- Run as a script, the scanner catches the `ScannerError` its helpers raise ([#78](https://github.com/datrail/railmon/pull/78)).
- `egress_containment`'s `via` and `network_mode` are strings or null ([#89](https://github.com/datrail/railmon/pull/89)).

### Security

- rustls 0.23.45, for a TLS 1.3 handshake advisory ([#81](https://github.com/datrail/railmon/pull/81)).

## [v0.1.0-m3] - 2026-09-15

### Added

- **Rule pack 1.** Emit the v1 evidence bundle the published schema accepts; `rule_pack_version` starts at 1 ([#17](https://github.com/datrail/railmon/pull/17)).

### Changed

- Evidence credential classes align with the schema ([#18](https://github.com/datrail/railmon/pull/18)).

## [v0.1.0-m2] - 2026-09-01

The initial public release, commit `45c58a8`. The work merged before it
(PRs #2 to #16) is squashed into that one commit.

Note: the `v0.1.0` tag points at the same commit `45c58a8`. It is a stray
tag, not a release; the milestone is `v0.1.0-m2`.

[v0.1.0-m16]: https://github.com/datrail/railmon/compare/v0.1.0-m15...v0.1.0-m16
[v0.1.0-m15]: https://github.com/datrail/railmon/compare/v0.1.0-m14...v0.1.0-m15
[v0.1.0-m14]: https://github.com/datrail/railmon/compare/v0.1.0-m13...v0.1.0-m14
[v0.1.0-m13]: https://github.com/datrail/railmon/compare/v0.1.0-m12...v0.1.0-m13
[v0.1.0-m12]: https://github.com/datrail/railmon/compare/v0.1.0-m11...v0.1.0-m12
[v0.1.0-m11]: https://github.com/datrail/railmon/compare/v0.1.0-m10...v0.1.0-m11
[v0.1.0-m10]: https://github.com/datrail/railmon/compare/v0.1.0-m9...v0.1.0-m10
[v0.1.0-m9]: https://github.com/datrail/railmon/compare/v0.1.0-m8...v0.1.0-m9
[v0.1.0-m8]: https://github.com/datrail/railmon/compare/v0.1.0-m7...v0.1.0-m8
[v0.1.0-m7]: https://github.com/datrail/railmon/compare/v0.1.0-m6...v0.1.0-m7
[v0.1.0-m6]: https://github.com/datrail/railmon/compare/v0.1.0-m5...v0.1.0-m6
[v0.1.0-m5]: https://github.com/datrail/railmon/compare/v0.1.0-m4...v0.1.0-m5
[v0.1.0-m4]: https://github.com/datrail/railmon/compare/v0.1.0-m3...v0.1.0-m4
[v0.1.0-m3]: https://github.com/datrail/railmon/compare/v0.1.0-m2...v0.1.0-m3
[v0.1.0-m2]: https://github.com/datrail/railmon/releases/tag/v0.1.0-m2
