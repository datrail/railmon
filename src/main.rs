//! RailMon — the runtime-interaction collector.
//!
//! Spawns AgentSight, pairs the HTTP it reconstructs into interactions,
//! attributes each one to an agent from its `x-rail` ticket, and forwards them.
//!
//! The CLI is deliberately unchanged from the Python it replaces: existing
//! compose files, run scripts and the container entrypoint pass these flags,
//! and a port that quietly renamed them would break every caller for no gain.

mod auth;
mod http1_guard;
mod identity;
mod interaction;
mod pipeline;
mod sink;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use futures::{Stream, StreamExt};
use pipeline::{CaptureFilters, Pairer};
use sink::Sink;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;
use tokio::signal::unix::{signal, Signal, SignalKind};
use tokio_stream::StreamMap;

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// Forward the analyzed events as they come, without pairing.
    Raw,
    /// Pair requests with responses into interactions.
    Http,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// RailMon's own JSONL shape.
    LegacyHttp,
    /// Rail Center `/v1/interactions` events.
    RuntimeInteraction,
}

#[derive(Parser)]
#[command(
    name = "railmon",
    about = "Capture and forward an agent's HTTP traffic"
)]
struct Args {
    /// Operator-owned multi-agent target manifest. Its absence preserves the
    /// exact legacy single-target path.
    #[arg(long)]
    target_manifest: Option<PathBuf>,

    /// Resolve `--target-manifest`, print each declared agent's outcome and
    /// scan-scoping fields (agent_key, status, config_roots, binary_path,
    /// pid) as a JSON array on stdout, and exit without capturing. This is
    /// the contract the Python scanner's `--target-manifest` mode reads to
    /// run agent-scoped scanning once per key (DR-109 M2) — it exists so
    /// that process resolution has exactly one implementation, not a second
    /// one reimplemented in Python at the risk of diverging from it.
    #[arg(long, requires = "target_manifest")]
    print_resolved_targets: bool,

    /// Absolute path of the scanner's un-keyed `--registration-output`. With
    /// `--target-manifest`, each agent's `<path>.<agent_key>` registration
    /// state maps the `agent_id` an unsigned `x-rail` ticket claims back to an
    /// `agent_key`, so a ticket that agrees with the process target is
    /// recorded as corroboration and one naming a sibling agent as a
    /// `conflict`. Without it every claim stays unresolved and keyed rows are
    /// attributed by process target alone.
    #[arg(long, requires = "target_manifest")]
    registration_state: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "http")]
    mode: Mode,

    /// Webhook URL to forward interactions to.
    #[arg(long)]
    webhook: Option<String>,

    /// Output file for captured interactions (JSONL).
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    /// Binary with statically linked SSL, e.g. an agent CLI.
    #[arg(long)]
    binary_path: Option<String>,

    #[arg(long)]
    pid: Option<i32>,
    #[arg(long)]
    uid: Option<i32>,
    #[arg(long)]
    comm: Option<String>,

    /// Capture only processes in this process session (host PID namespace).
    /// A container's processes share its init's session unless one starts
    /// its own, so this scopes capture to one container; `railmon collect`
    /// with RAIL_COLLECT_CONTAINER sets it (DR-187). An event whose process
    /// has already exited is let through, since its session can't be read.
    #[arg(long)]
    session: Option<u32>,

    /// Path to the agentsight (or bare sslsniff) binary. Defaults to
    /// AGENTSIGHT_PATH, then SSLSNIFF_PATH, then ./bin/agentsight, then the
    /// container path — the same order the Python resolved.
    #[arg(long, alias = "sslsniff")]
    agentsight: Option<String>,

    /// Interactions per webhook batch.
    #[arg(long, default_value_t = 10)]
    batch_size: usize,

    /// Maximum seconds between webhook flushes.
    #[arg(long, default_value_t = 2.0)]
    flush_interval: f64,

    #[arg(long, value_enum, default_value = "legacy-http")]
    output_format: OutputFormat,

    /// Seconds a request waits for its response before it is forwarded as an
    /// incomplete interaction (DR-186). Well past any real model stream, since
    /// a reply that arrives after its request expired pairs with the next
    /// request on its thread. 0 waits for ever, as before.
    #[arg(long, default_value_t = 600.0)]
    pending_timeout: f64,

    /// Session id recorded on every interaction. Generated when not given.
    #[arg(long)]
    session_id: Option<String>,
}

/// SIGINT or SIGTERM, whichever comes first. Both mean "stop and flush": SIGTERM
/// is what `docker stop`, Kubernetes and systemd send, and without a handler
/// it either killed the collector outright — losing the buffered webhook batch
/// and every pending request — or, as the image's PID 1, was ignored until the
/// runtime's SIGKILL did the same ten seconds later (DR-130).
///
/// Both listeners live for the whole capture. A `ctrl_c()` future re-created on
/// every loop iteration only sees signals delivered while it exists, so a
/// SIGINT landing between iterations (on a flush tick, say) was swallowed and
/// the collector ran on until its probe exited.
struct ShutdownSignal {
    interrupt: Signal,
    terminate: Signal,
}

impl ShutdownSignal {
    /// Installed once, before any probe starts, so a signal that lands while
    /// taps are coming up is held for the capture loop rather than killing the
    /// process with its probes still attached.
    fn install() -> Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).context("installing the SIGINT handler")?,
            terminate: signal(SignalKind::terminate()).context("installing the SIGTERM handler")?,
        })
    }

    async fn requested(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }
}

/// The Python resolved AGENTSIGHT_PATH, then SSLSNIFF_PATH ("back-compat:
/// older env name"), then a repo-relative bin/agentsight. Dropping the last two
/// would mean `make fetch-agentsight` downloads a binary that a bare `railmon`
/// then cannot find.
fn resolve_probe_path(explicit: Option<String>) -> String {
    if let Some(path) = explicit.filter(|p| !p.is_empty()) {
        return path;
    }
    for key in ["AGENTSIGHT_PATH", "SSLSNIFF_PATH"] {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                return value;
            }
        }
    }
    let local = std::path::Path::new("bin/agentsight");
    if local.exists() {
        return local.display().to_string();
    }
    "/usr/local/bin/agentsight".to_string()
}

/// How long a request may wait for its response, or None for ever.
/// Clamped like `--flush-interval`, for the same reasons.
fn pending_timeout(args: &Args) -> Option<Duration> {
    let seconds = if args.pending_timeout.is_finite() {
        args.pending_timeout.clamp(0.0, 86_400.0)
    } else {
        600.0
    };
    (seconds > 0.0).then(|| Duration::from_secs_f64(seconds))
}

/// Says when exchanges could not be paired, so a capture that forwards
/// nothing is never silent about why (DR-186, datrail/railmon#70). At most
/// one line a minute, and only when a count moved.
#[derive(Default)]
struct PairingReport {
    expired: u64,
    unmatched_reported: u64,
    expired_reported: u64,
    last: Option<std::time::Instant>,
}

impl PairingReport {
    const EVERY: Duration = Duration::from_secs(60);

    fn note_expired(&mut self, count: usize) {
        self.expired += count as u64;
    }

    /// `unmatched` is the running total across live pairers. A tap that stops
    /// takes its count with it, so the baseline only falls; responses counted
    /// in the minute before a tap stops can go unreported. A diagnostic, so
    /// that under-count is accepted.
    fn maybe_log(&mut self, unmatched: u64, timeout: Option<Duration>) {
        if self.last.is_some_and(|last| last.elapsed() < Self::EVERY) {
            return;
        }
        self.log(unmatched, timeout);
    }

    /// Logs whatever moved since the last line, rate limit or not: at exit.
    fn log(&mut self, unmatched: u64, timeout: Option<Duration>) {
        self.unmatched_reported = self.unmatched_reported.min(unmatched);
        if unmatched == self.unmatched_reported && self.expired == self.expired_reported {
            return;
        }
        let mut parts = Vec::new();
        let new_expired = self.expired - self.expired_reported;
        if new_expired > 0 {
            parts.push(format!(
                "{new_expired} request(s) got no response within {}s and were forwarded as incomplete",
                timeout.unwrap_or_default().as_secs_f64()
            ));
        }
        let new_unmatched = unmatched - self.unmatched_reported;
        if new_unmatched > 0 {
            parts.push(format!("{new_unmatched} response(s) matched no request"));
        }
        log::warn!(
            "{}. The probe reports threads, not connections, so a reply streamed while another \
             HTTP connection on the same thread is active can be lost (datrail/railmon#70).",
            parts.join("; ")
        );
        self.unmatched_reported = unmatched;
        self.expired_reported = self.expired;
        self.last = Some(std::time::Instant::now());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let target_manifest = if let Some(path) = args.target_manifest.as_deref() {
        let manifest = identity::TargetManifest::load(path)?;
        log::info!(
            "validated {} keyed targets for {}/{}",
            manifest.agents.len(),
            manifest.sandbox.host_id,
            manifest.sandbox.sandbox_name
        );
        Some(manifest)
    } else {
        None
    };

    if args.print_resolved_targets {
        let manifest = target_manifest
            .as_ref()
            .expect("clap requires --target-manifest with --print-resolved-targets");
        println!(
            "{}",
            serde_json::to_string(&manifest.resolve_all_summary())
                .context("serializing resolved targets")?
        );
        return Ok(());
    }

    // The webhook's credential is checked, and a first one produced, before
    // anything is captured: a collector that cannot authenticate would
    // otherwise look alive while every batch it sends is refused (RM-F2).
    let credential = match args.webhook.as_deref() {
        Some(_) => {
            let mut credential = auth::Credential::from_env().context("RAIL_AUTH_MODE")?;
            credential
                .authorization()
                .await
                .context("producing the webhook credential RAIL_AUTH_MODE names")?;
            log::info!("webhook credential: RAIL_AUTH_MODE={}", credential.mode());
            credential
        }
        None => auth::Credential::None,
    };

    // Fail on a missing binary before opening sinks or claiming to capture:
    // the old failure mode was a collector that looked alive and produced
    // nothing.
    let agentsight = resolve_probe_path(args.agentsight.clone());
    if !std::path::Path::new(&agentsight).exists() {
        anyhow::bail!(
            "probe not found at {agentsight} — set --agentsight, AGENTSIGHT_PATH or SSLSNIFF_PATH, or run `make fetch-agentsight`"
        );
    }

    let mut shutdown = ShutdownSignal::install()?;

    // Clamped at both ends. is_finite() alone lets 1e30 through, and
    // Duration::from_secs_f64 panics above ~1.8e19; a NaN or a negative panics
    // too. An hour is well past any sensible flush cadence.
    let flush_interval = Duration::from_secs_f64(if args.flush_interval.is_finite() {
        args.flush_interval.clamp(0.0, 3600.0)
    } else {
        2.0
    });

    let session_id = args
        .session_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let capture_start = chrono::Utc::now().to_rfc3339();

    let mut sink = Sink::new(
        args.output.as_deref(),
        args.webhook.as_deref(),
        args.batch_size,
        flush_interval,
        &session_id,
        &capture_start,
    )
    .context("configuring output")?
    .with_credential(credential);

    // rail-center has no RuntimeInteraction endpoint: POST /v1/interactions
    // takes HttpInteractionPayload, which is the legacy-http shape. Posting the
    // other format gets a 202 and stores a row with no headers, so
    // match_interactions_to_agents can never find x-rail and agent_id stays
    // NULL — no error anywhere, just an interaction attributed to nobody. M1's
    // exit criterion is a captured interaction with a real agent_id, so this is
    // worth a warning rather than a silent success.
    if args.webhook.is_some() && matches!(args.output_format, OutputFormat::RuntimeInteraction) {
        log::warn!(
            "--output-format runtime-interaction has no endpoint in Rail Center; \
             POST /v1/interactions accepts the legacy-http shape and will store \
             these rows unattributed. Use --output-format legacy-http for the webhook."
        );
    }

    if sink.is_silent() {
        log::warn!("no --webhook and no --output: interactions will be counted but not stored");
    }

    if let Some(manifest) = target_manifest.as_ref() {
        let result = run_multi_target(
            &args,
            manifest,
            &agentsight,
            &session_id,
            &capture_start,
            &mut sink,
            flush_interval,
            &mut shutdown,
        )
        .await;
        sink.shutdown().await;
        log::info!("{} interaction(s) forwarded", sink.written());
        return result;
    }

    let filters = CaptureFilters {
        binary_path: args.binary_path.clone(),
        pid: args.pid,
        uid: args.uid,
        comm: args.comm.clone(),
        process_session: args.session,
    };

    log::info!("session {session_id}, agentsight at {}", agentsight);
    let (mut stream, stream_status) = pipeline::event_stream(&agentsight, &filters).await?;

    let mut pairer = Pairer::new();
    let pending_timeout = pending_timeout(&args);
    let mut report = PairingReport::default();
    let mut write_error: Option<anyhow::Error> = None;
    let mut stream_ended = false;
    let mut ticker = tokio::time::interval(flush_interval.max(Duration::from_millis(100)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // Biased so a pending event is always handled before the timer,
            // keeping the flush a lower priority than not losing data.
            biased;

            maybe_event = stream.next() => {
                let Some(event) = maybe_event else {
                    stream_ended = true;
                    break;
                };

                let emitted = match args.mode {
                    Mode::Raw => serde_json::to_value(&event).ok(),
                    Mode::Http => pairer
                        .accept(event.pid, &event.data, event.timestamp)
                        .map(|paired| match args.output_format {
                            OutputFormat::LegacyHttp => paired,
                            OutputFormat::RuntimeInteraction => interaction::to_runtime_interaction(
                                &paired,
                                Some(&session_id),
                                Some(&capture_start),
                                "railmon",
                            ),
                        }),
                };

                // Deliberately not `?`. Returning from here would skip
                // shutdown() and silently drop every interaction still buffered
                // for the webhook. A write failure is worth stopping for, but
                // only after the buffer has been flushed.
                if let Some(value) = emitted {
                    if let Err(error) = sink.emit(&value).await {
                        // Break rather than `?`: returning here would skip
                        // shutdown() and drop the buffered batch. The error is
                        // carried out and surfaced after the flush.
                        log::error!("writing interaction: {error}");
                        write_error = Some(error);
                        break;
                    }
                }
            }

            _ = ticker.tick() => {
                if let (Mode::Http, Some(timeout)) = (&args.mode, pending_timeout) {
                    let expired = pairer.expire(std::time::Instant::now(), timeout);
                    report.note_expired(expired.len());
                    for paired in expired {
                        let value = match args.output_format {
                            OutputFormat::LegacyHttp => paired,
                            OutputFormat::RuntimeInteraction => interaction::to_runtime_interaction(
                                &paired,
                                Some(&session_id),
                                Some(&capture_start),
                                "railmon",
                            ),
                        };
                        if let Err(error) = sink.emit(&value).await {
                            log::error!("writing interaction: {error}");
                            write_error = Some(error);
                            break;
                        }
                    }
                    if write_error.is_some() {
                        break;
                    }
                }
                report.maybe_log(pairer.unmatched_responses(), pending_timeout);
                sink.flush_if_due().await
            }

            _ = shutdown.requested() => {
                log::info!("interrupted");
                break;
            }
        }
    }

    report.log(pairer.unmatched_responses(), pending_timeout);
    sink.shutdown().await;
    let outstanding = pairer.outstanding();
    log::info!("{} interaction(s) forwarded", sink.written());
    if outstanding > 0 {
        // Worth saying: a request with no response is normal at shutdown, but a
        // large number of them means the pairing key is wrong for this agent.
        log::info!("{outstanding} request(s) had no response at exit");
    }

    if let Some(error) = write_error {
        return Err(error);
    }

    // Drop the stream before awaiting the probe's status. The oneshot sender
    // lives inside the stream's state and is only fired while something polls
    // it, so leaving the loop on a shutdown signal would otherwise block here
    // for ever — and `kill_on_drop` would never fire, leaving the probe running with its
    // eBPF programs attached, which is what makes the *next* run fail to
    // attach. Dropping it closes the channel; the `_` arm below treats that as
    // "no status to report", which is correct for an interrupted capture.
    drop(stream);

    // Attaching an eBPF probe is the common runtime failure here — it needs
    // CAP_BPF and a matching kernel. Exiting 0 after it fails makes Docker,
    // systemd and k8s all read the collector as healthy, so nothing restarts
    // and nothing alerts. Report the probe's own status instead.
    match stream_status.await {
        Ok(Some(status)) if !status.success() => {
            anyhow::bail!("probe exited with {status}")
        }
        // The stream ended by itself yet the probe never reported: the
        // stream was dropped under the probe, which only the analyzer-panic
        // guard does (DR-129). Capture has stopped, so say so in the exit code.
        Err(_) if stream_ended => {
            anyhow::bail!("capture stopped: an analyzer failed on captured traffic (see log)")
        }
        // A dropped sender otherwise means we left the loop before the probe's
        // output ended, which is what a shutdown signal does. Not a failure.
        _ => Ok(()),
    }
}

struct TargetRuntime {
    agent_ref: identity::AgentRef,
    process: identity::ProcessIncarnation,
    pairer: Pairer,
}

/// A tap on a process session that more than one declared target claims.
/// Design doc §5: such a process's events are marked `ambiguous` and land in
/// the unattributed queue, rather than going unseen. Its rows name no agent,
/// and neither colliding target gets a tap of its own.
struct SharedTap {
    /// Every declared target the session's processes collided with, sorted.
    candidates: Vec<String>,
    /// The distinct incarnations the colliding locators resolved to inside
    /// this session, sorted by PID. Pinned like a target's: the tap stops
    /// as soon as any of them exits or its PID is reused. Discovery only
    /// accepts a session leader, so this holds one incarnation in practice;
    /// more is handled defensively.
    incarnations: Vec<identity::ProcessIncarnation>,
    reason: String,
    /// The AgentSight `--binary-path` the probe was started with; a new one
    /// needs a new probe.
    binary_path: Option<String>,
    pairer: Pairer,
}

impl SharedTap {
    fn is_live(&self) -> bool {
        self.incarnations.iter().all(|process| process.is_live())
    }

    /// Stamps the pinned incarnation when the session holds exactly one.
    /// With several (defensive: see `incarnations`), the event's own PID is
    /// not re-read from `/proc` to pick one (§4.4), so the row carries no
    /// process at all.
    fn stamp(&self, paired: &mut serde_json::Value) {
        if let [process] = self.incarnations.as_slice() {
            paired["target_pid"] = serde_json::json!(process.pid);
            paired["process_start_time_ticks"] = serde_json::json!(process.start_time_ticks);
        }
    }

    fn row(
        &self,
        paired: &serde_json::Value,
        session_id: &str,
        capture_start: &str,
    ) -> serde_json::Value {
        interaction::to_ambiguous_runtime_interaction(
            paired,
            Some(session_id),
            Some(capture_start),
            "railmon",
            &self.candidates,
            &self.reason,
        )
    }
}

/// What the latest discovery says a session's shared tap should look like.
#[derive(Debug, PartialEq, Eq)]
struct SharedPlan {
    candidates: Vec<String>,
    incarnations: Vec<identity::ProcessIncarnation>,
    reason: String,
    binary_path: Option<String>,
}

/// Groups every `Ambiguous` outcome by the process session its locator
/// resolved to: one shared tap per session, since two session-scoped taps
/// on one session would capture every event twice.
fn plan_shared_taps(
    manifest: &identity::TargetManifest,
    outcomes: &[identity::DiscoveryOutcome],
    default_binary_path: Option<&String>,
) -> BTreeMap<u32, SharedPlan> {
    let mut plans: BTreeMap<u32, SharedPlan> = BTreeMap::new();
    let mut binary_paths: BTreeMap<u32, Vec<Option<String>>> = BTreeMap::new();
    for (index, outcome) in outcomes.iter().enumerate() {
        let identity::DiscoveryOutcome::Ambiguous {
            reason,
            process,
            colliding,
        } = outcome
        else {
            continue;
        };
        let plan = plans
            .entry(process.session_id)
            .or_insert_with(|| SharedPlan {
                candidates: Vec::new(),
                incarnations: Vec::new(),
                reason: reason.clone(),
                binary_path: None,
            });
        plan.candidates
            .push(manifest.agents[index].agent_key.clone());
        plan.candidates.extend(
            colliding
                .iter()
                .map(|&other| manifest.agents[other].agent_key.clone()),
        );
        if !plan.incarnations.contains(process) {
            plan.incarnations.push(*process);
        }
        binary_paths.entry(process.session_id).or_default().push(
            manifest.agents[index]
                .capture
                .as_ref()
                .and_then(|capture| capture.binary_path.clone())
                .or_else(|| default_binary_path.cloned()),
        );
    }
    for (session, plan) in plans.iter_mut() {
        plan.candidates.sort();
        plan.candidates.dedup();
        plan.incarnations.sort_by_key(|process| process.pid);
        let mut paths = binary_paths.remove(session).unwrap_or_default();
        paths.sort();
        paths.dedup();
        // Targets in one session that name different binaries still share
        // one tap; fall back to the collector-wide default for it.
        plan.binary_path = match paths.as_slice() {
            [only] => only.clone(),
            _ => default_binary_path.cloned(),
        };
    }
    plans
}

/// A tap's key in the one `StreamMap` every running tap feeds: a declared
/// target by manifest index, or a shared tap by process session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TapSlot {
    Target(usize),
    Shared(u32),
}

enum TargetStreamItem {
    Event(agentsight_capture::Event),
    Ended(Result<Option<std::process::ExitStatus>, tokio::sync::oneshot::error::RecvError>),
}

type TargetStream = Pin<Box<dyn Stream<Item = TargetStreamItem> + Send>>;

/// How often a target whose locator currently doesn't resolve (not_found,
/// ambiguous, or just exited) gets another discovery attempt. Fixed rather
/// than truly exponential — "bounded backoff" (design doc §5) mainly needs to
/// rule out a busy-loop; a flat interval already does that.
const TARGET_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Spawns one tap scoped to a pinned incarnation's process session, and
/// wraps its event/exit streams into one `TargetStreamItem` stream keyed
/// later by `TapSlot` in a `StreamMap`. Used both at startup and to restart
/// a tap that previously stopped; `label` only names it in errors.
async fn spawn_session_tap(
    agentsight: &str,
    binary_path: Option<String>,
    session_id: u32,
    label: &str,
) -> Result<TargetStream> {
    let filters = CaptureFilters {
        binary_path,
        pid: None,
        uid: None,
        comm: None,
        process_session: Some(session_id),
    };
    let (stream, status) = pipeline::event_stream(agentsight, &filters)
        .await
        .with_context(|| format!("starting tap for {label}"))?;
    let tagged = stream
        .map(TargetStreamItem::Event)
        .chain(futures::stream::once(async move {
            TargetStreamItem::Ended(status.await)
        }));
    Ok(Box::pin(tagged))
}

/// Drains a stopping target's still-pending requests and emits each as an
/// incomplete interaction, so a request that was captured is never silently
/// lost just because its response never arrived before the tap stopped
/// (design doc §4.4).
async fn flush_target_incomplete(
    target: &mut TargetRuntime,
    registered: &identity::RegisteredAgents,
    session_id: &str,
    capture_start: &str,
    sink: &mut Sink,
) -> Result<()> {
    let pending = target.pairer.flush_incomplete();
    emit_target_incomplete(target, pending, registered, session_id, capture_start, sink).await
}

/// Emits a target's incomplete interactions, attributed like its paired ones.
async fn emit_target_incomplete(
    target: &TargetRuntime,
    incomplete: Vec<serde_json::Value>,
    registered: &identity::RegisteredAgents,
    session_id: &str,
    capture_start: &str,
    sink: &mut Sink,
) -> Result<()> {
    for mut paired in incomplete {
        paired["target_pid"] = serde_json::json!(target.process.pid);
        paired["process_start_time_ticks"] = serde_json::json!(target.process.start_time_ticks);
        let value = interaction::to_attributed_runtime_interaction(
            &paired,
            Some(session_id),
            Some(capture_start),
            "railmon",
            Some((&target.agent_ref, registered)),
        );
        sink.emit(&value).await?;
    }
    Ok(())
}

/// A shared tap's counterpart to `flush_target_incomplete`: its pending
/// requests are reported too, still as `ambiguous`.
async fn flush_shared_incomplete(
    tap: &mut SharedTap,
    session_id: &str,
    capture_start: &str,
    sink: &mut Sink,
) -> Result<()> {
    let pending = tap.pairer.flush_incomplete();
    emit_shared_incomplete(tap, pending, session_id, capture_start, sink).await
}

async fn emit_shared_incomplete(
    tap: &SharedTap,
    incomplete: Vec<serde_json::Value>,
    session_id: &str,
    capture_start: &str,
    sink: &mut Sink,
) -> Result<()> {
    for mut paired in incomplete {
        tap.stamp(&mut paired);
        sink.emit(&tap.row(&paired, session_id, capture_start))
            .await?;
    }
    Ok(())
}

/// Stops one running target: flushes its pending requests as incomplete and
/// drops its tap stream (which kills the tap), leaving the slot `None` so the
/// retry tick re-resolves it. A no-op for a target that is already down.
async fn stop_target(
    slot: &mut Option<TargetRuntime>,
    stream_map: &mut StreamMap<TapSlot, TargetStream>,
    index: usize,
    registered: &identity::RegisteredAgents,
    session_id: &str,
    capture_start: &str,
    sink: &mut Sink,
) -> Result<()> {
    stream_map.remove(&TapSlot::Target(index));
    match slot.take() {
        Some(mut target) => {
            flush_target_incomplete(&mut target, registered, session_id, capture_start, sink).await
        }
        None => Ok(()),
    }
}

/// Stops one shared tap the same way `stop_target` stops a target's.
async fn stop_shared(
    shared: &mut BTreeMap<u32, SharedTap>,
    stream_map: &mut StreamMap<TapSlot, TargetStream>,
    process_session: u32,
    session_id: &str,
    capture_start: &str,
    sink: &mut Sink,
) -> Result<()> {
    stream_map.remove(&TapSlot::Shared(process_session));
    match shared.remove(&process_session) {
        Some(mut tap) => flush_shared_incomplete(&mut tap, session_id, capture_start, sink).await,
        None => Ok(()),
    }
}

/// Brings the running shared taps in line with the latest discovery: a tap
/// whose session no longer collides, or whose incarnations or probe binary
/// path changed, is stopped; one whose colliding targets or reason merely
/// changed keeps running with the new audit; a newly colliding session gets
/// one. The caller stops any
/// running target on a planned session first, and starts targets' own taps
/// only after this, so the two never share a session.
async fn reconcile_shared_taps(
    agentsight: &str,
    plans: BTreeMap<u32, SharedPlan>,
    shared: &mut BTreeMap<u32, SharedTap>,
    stream_map: &mut StreamMap<TapSlot, TargetStream>,
    session_id: &str,
    capture_start: &str,
    sink: &mut Sink,
) -> Result<()> {
    let stale: Vec<u32> = shared
        .iter()
        .filter(|(process_session, tap)| {
            plans.get(process_session).is_none_or(|plan| {
                plan.incarnations != tap.incarnations || plan.binary_path != tap.binary_path
            })
        })
        .map(|(process_session, _)| *process_session)
        .collect();
    for process_session in stale {
        log::info!("session {process_session} no longer collides as it did; stopping its shared ambiguous tap");
        stop_shared(
            shared,
            stream_map,
            process_session,
            session_id,
            capture_start,
            sink,
        )
        .await?;
    }
    for (process_session, plan) in plans {
        if let Some(tap) = shared.get_mut(&process_session) {
            // Same session, processes and probe: at most who claims them, or
            // why they collide, moved. Restarting would flush in-flight
            // requests as incomplete, so later rows just carry the new audit.
            if tap.candidates != plan.candidates {
                log::info!(
                    "session {process_session} is now claimed by targets {}",
                    plan.candidates.join(", ")
                );
                tap.candidates = plan.candidates;
            }
            tap.reason = plan.reason;
            continue;
        }
        let label = format!(
            "targets {} sharing session {process_session}",
            plan.candidates.join(", ")
        );
        match spawn_session_tap(
            agentsight,
            plan.binary_path.clone(),
            process_session,
            &label,
        )
        .await
        {
            Ok(stream) => {
                log::warn!(
                    "{label} collide ({}); capturing that session as ambiguous, attributed to none of them",
                    plan.reason
                );
                stream_map.insert(TapSlot::Shared(process_session), stream);
                shared.insert(
                    process_session,
                    SharedTap {
                        candidates: plan.candidates,
                        incarnations: plan.incarnations,
                        reason: plan.reason,
                        binary_path: plan.binary_path,
                        pairer: Pairer::new(),
                    },
                );
            }
            Err(error) => {
                log::warn!("{label} collide but the shared tap failed to start: {error:#}")
            }
        }
    }
    Ok(())
}

/// Re-reads the keyed registration state behind `--registration-state` and
/// logs only what changed — a new mapping size, or a new set of unusable
/// files — so a 5s refresh does not repeat the same warning forever.
fn refresh_registered_agents(
    args: &Args,
    manifest: &identity::TargetManifest,
    registered: &mut identity::RegisteredAgents,
    problems: &mut Vec<String>,
) {
    let Some(base) = args.registration_state.as_deref() else {
        return;
    };
    let (next, next_problems) = identity::load_registered_agents(manifest, base);
    if next_problems != *problems {
        for problem in &next_problems {
            log::warn!("ignoring registration state for ticket-claim resolution: {problem}");
        }
    }
    if next != *registered {
        log::info!(
            "{} of {} keyed target(s) have a registered agent_id for ticket-claim resolution",
            next.len(),
            manifest.agents.len()
        );
    }
    *registered = next;
    *problems = next_problems;
}

/// The collector no longer exits when every target is simultaneously down
/// (it keeps retrying discovery instead), which means an operator watching
/// only the process's exit code would never learn that capture went fully
/// idle. Logs the edge, not every retry tick, so this stays quiet as long as
/// at least one tap — a target's or a shared one — is running.
fn log_target_availability_transition(
    targets: &[Option<TargetRuntime>],
    shared: &BTreeMap<u32, SharedTap>,
    all_targets_down: &mut bool,
) {
    let now = targets.iter().all(Option::is_none) && shared.is_empty();
    if now && !*all_targets_down {
        log::warn!(
            "every declared target is currently down; capture is idle and will keep retrying discovery every {}s",
            TARGET_RETRY_INTERVAL.as_secs()
        );
    } else if !now && *all_targets_down {
        log::info!("a target resolved again; capture is no longer idle");
    }
    *all_targets_down = now;
}

// Eight, one over clippy's default: each is state main() already owns and
// shares with the single-target path; bundling them would only rename it.
#[allow(clippy::too_many_arguments)]
async fn run_multi_target(
    args: &Args,
    manifest: &identity::TargetManifest,
    agentsight: &str,
    session_id: &str,
    capture_start: &str,
    sink: &mut Sink,
    flush_interval: Duration,
    shutdown: &mut ShutdownSignal,
) -> Result<()> {
    if matches!(args.mode, Mode::Raw) {
        anyhow::bail!(
            "keyed capture requires --mode http; raw events have no attribution envelope"
        );
    }
    if !matches!(args.output_format, OutputFormat::RuntimeInteraction) {
        anyhow::bail!("keyed capture requires --output-format runtime-interaction");
    }
    if args.pid.is_some() || args.uid.is_some() || args.comm.is_some() || args.session.is_some() {
        anyhow::bail!(
            "--pid, --uid, --comm and --session cannot be combined with --target-manifest"
        );
    }

    if let Some(path) = args.registration_state.as_deref() {
        if !path.is_absolute() {
            anyhow::bail!("--registration-state {} is not absolute", path.display());
        }
    }
    let mut registration_problems = Vec::new();
    let mut registered = identity::RegisteredAgents::default();
    refresh_registered_agents(args, manifest, &mut registered, &mut registration_problems);
    if registered.len() == 0 {
        if let Some(path) = args.registration_state.as_deref() {
            // An empty mapping from a mistyped path otherwise logs nothing
            // and looks identical to "no key has registered yet".
            log::info!(
                "no keyed target has registration state at {}.<agent_key> yet; ticket claims stay unresolved until one does",
                path.display()
            );
        }
    }

    let outcomes = manifest.resolve_all();
    // Indexed by each declared agent's position in `manifest.agents`, which
    // never changes for the life of this run. `None` means "not currently
    // capturing" — either never resolved, or resolved and then stopped —
    // and is retried on `retry_ticker` rather than ending the whole run.
    let mut targets: Vec<Option<TargetRuntime>> = Vec::with_capacity(manifest.agents.len());
    // Sessions whose process more than one target claims, keyed by process
    // session; their colliding targets stay `None` above.
    let mut shared: BTreeMap<u32, SharedTap> = BTreeMap::new();
    let mut stream_map: StreamMap<TapSlot, TargetStream> = StreamMap::new();
    reconcile_shared_taps(
        agentsight,
        plan_shared_taps(manifest, &outcomes, args.binary_path.as_ref()),
        &mut shared,
        &mut stream_map,
        session_id,
        capture_start,
        sink,
    )
    .await?;
    let mut any_available = false;
    for (index, (target, outcome)) in manifest.agents.iter().zip(outcomes).enumerate() {
        match outcome {
            identity::DiscoveryOutcome::Available(process) => {
                let binary_path = target
                    .capture
                    .as_ref()
                    .and_then(|capture| capture.binary_path.clone())
                    .or_else(|| args.binary_path.clone());
                // A tap-spawn failure for one target (e.g. the probe binary
                // failed to exec) is treated the same way here as it is on
                // retry below: log and leave this target down rather than
                // aborting every other target that resolved and started
                // cleanly.
                let label = format!("'{}'", target.agent_key);
                let stream =
                    match spawn_session_tap(agentsight, binary_path, process.session_id, &label)
                        .await
                    {
                        Ok(stream) => stream,
                        Err(error) => {
                            log::warn!(
                                "target '{}' resolved but its tap failed to start: {error:#}",
                                target.agent_key
                            );
                            targets.push(None);
                            continue;
                        }
                    };
                stream_map.insert(TapSlot::Target(index), stream);
                targets.push(Some(TargetRuntime {
                    agent_ref: manifest.agent_ref(target),
                    process,
                    pairer: Pairer::new(),
                }));
                any_available = true;
            }
            identity::DiscoveryOutcome::NotFound(reason) => {
                log::warn!("target '{}' not found: {reason}", target.agent_key);
                targets.push(None);
            }
            identity::DiscoveryOutcome::Ambiguous { reason, .. } => {
                log::warn!("target '{}' is ambiguous: {reason}", target.agent_key);
                targets.push(None);
            }
        }
    }
    if !any_available && shared.is_empty() {
        anyhow::bail!("no declared agent resolved to a capturable process");
    }

    let mut ticker = tokio::time::interval(flush_interval.max(Duration::from_millis(100)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut retry_ticker = tokio::time::interval(TARGET_RETRY_INTERVAL);
    retry_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut write_error = None;
    let mut all_targets_down = false;
    let pending_timeout = pending_timeout(args);
    let mut report = PairingReport::default();
    'capture: loop {
        tokio::select! {
            biased;
            // `StreamMap::poll_next` returns `Ready(None)` whenever the map
            // is empty (every target currently down), which would otherwise
            // make this branch always-ready and starve the other branches —
            // hence the guard.
            next = stream_map.next(), if !stream_map.is_empty() => {
                let Some((slot, item)) = next else { continue };
                match (slot, item) {
                    (TapSlot::Target(index), TargetStreamItem::Event(event)) => {
                        let Some(target) = targets[index].as_mut() else { continue };
                        if !target.process.is_live() {
                            // The pinned incarnation is gone (exited, or its
                            // PID/session was reused by an unrelated
                            // process) but this stream is still bound to that
                            // session filter, so its events are no longer
                            // trustworthy. Never re-read /proc to relabel a
                            // queued event (design doc §4.4/§5) — stop
                            // trusting this stream instead of trying to.
                            log::warn!(
                                "target '{}' exited or its PID was reused; stopping its tap and flushing pending requests as incomplete",
                                target.agent_ref.agent_key
                            );
                            if let Err(error) = stop_target(
                                &mut targets[index], &mut stream_map, index, &registered, session_id, capture_start, sink,
                            ).await {
                                write_error = Some(error);
                                break 'capture;
                            }
                            log_target_availability_transition(&targets, &shared, &mut all_targets_down);
                            continue;
                        }
                        // The tap was bound to the target's process session.
                        // Stamp the already pinned root incarnation now,
                        // before the interaction enters the sink's
                        // asynchronous webhook queue.
                        if let Some(mut paired) = target.pairer.accept(event.pid, &event.data, event.timestamp) {
                            paired["target_pid"] = serde_json::json!(target.process.pid);
                            paired["process_start_time_ticks"] = serde_json::json!(target.process.start_time_ticks);
                            let value = interaction::to_attributed_runtime_interaction(
                                &paired,
                                Some(session_id),
                                Some(capture_start),
                                "railmon",
                                Some((&target.agent_ref, &registered)),
                            );
                            if let Err(error) = sink.emit(&value).await {
                                write_error = Some(error);
                                break 'capture;
                            }
                        }
                    }
                    (TapSlot::Shared(process_session), TargetStreamItem::Event(event)) => {
                        let Some(tap) = shared.get_mut(&process_session) else { continue };
                        // Same rule as a target's tap: once a pinned
                        // incarnation is gone, this session's events are no
                        // longer the ones that collided.
                        if !tap.is_live() {
                            log::warn!(
                                "a process in shared session {process_session} exited or its PID was reused; stopping its ambiguous tap"
                            );
                            if let Err(error) = stop_shared(
                                &mut shared, &mut stream_map, process_session, session_id, capture_start, sink,
                            ).await {
                                write_error = Some(error);
                                break 'capture;
                            }
                            log_target_availability_transition(&targets, &shared, &mut all_targets_down);
                            continue;
                        }
                        if let Some(mut paired) = tap.pairer.accept(event.pid, &event.data, event.timestamp) {
                            tap.stamp(&mut paired);
                            if let Err(error) = sink.emit(&tap.row(&paired, session_id, capture_start)).await {
                                write_error = Some(error);
                                break 'capture;
                            }
                        }
                    }
                    (slot, TargetStreamItem::Ended(status)) => {
                        let detail = match status {
                            Ok(Some(status)) => status.to_string(),
                            Ok(None) => "unknown exit status".into(),
                            Err(error) => error.to_string(),
                        };
                        let stopped = match slot {
                            TapSlot::Target(index) => {
                                if let Some(target) = targets[index].as_ref() {
                                    log::warn!(
                                        "target '{}' tap ended ({detail}); flushing pending requests as incomplete, will retry discovery",
                                        target.agent_ref.agent_key
                                    );
                                }
                                stop_target(
                                    &mut targets[index], &mut stream_map, index, &registered, session_id, capture_start, sink,
                                ).await
                            }
                            TapSlot::Shared(process_session) => {
                                log::warn!(
                                    "shared ambiguous tap on session {process_session} ended ({detail}); will retry discovery"
                                );
                                stop_shared(
                                    &mut shared, &mut stream_map, process_session, session_id, capture_start, sink,
                                ).await
                            }
                        };
                        if let Err(error) = stopped {
                            write_error = Some(error);
                            break 'capture;
                        }
                        log_target_availability_transition(&targets, &shared, &mut all_targets_down);
                    }
                }
            }
            // A target that is currently down — not_found, ambiguous, or its
            // tap just stopped — is never dropped for good: retry its
            // locator on a bounded interval and restart its tap the moment
            // it resolves again. The restarted process keeps the same
            // `agent_key` and gets a new, freshly pinned incarnation (design
            // doc §4.4). Discovery re-runs only while some target is down, so
            // a running target is disturbed only when that retry finds
            // another target claiming its process too (below); a locator
            // rewritten while every target runs is not re-read.
            _ = retry_ticker.tick() => {
                // Registration usually lands after capture starts (the scanner
                // runs on its own interval), so the ticket-claim mapping is
                // re-read here rather than fixed at startup.
                refresh_registered_agents(args, manifest, &mut registered, &mut registration_problems);
                // A target that exits quietly produces no further events, so
                // the per-event liveness check above never fires for it and
                // its tap would stay bound to a dead session forever. Sweep
                // every running target's pinned incarnation here too.
                for (index, slot) in targets.iter_mut().enumerate() {
                    let Some(target) = slot.as_ref() else { continue };
                    if target.process.is_live() {
                        continue;
                    }
                    log::warn!(
                        "target '{}' exited or its PID was reused; stopping its tap and flushing pending requests as incomplete",
                        target.agent_ref.agent_key
                    );
                    if let Err(error) = stop_target(
                        slot, &mut stream_map, index, &registered, session_id, capture_start, sink,
                    ).await {
                        write_error = Some(error);
                        break 'capture;
                    }
                }
                let dead: Vec<u32> = shared
                    .iter()
                    .filter(|(_, tap)| !tap.is_live())
                    .map(|(process_session, _)| *process_session)
                    .collect();
                for process_session in dead {
                    log::warn!(
                        "a process in shared session {process_session} exited or its PID was reused; stopping its ambiguous tap"
                    );
                    if let Err(error) = stop_shared(
                        &mut shared, &mut stream_map, process_session, session_id, capture_start, sink,
                    ).await {
                        write_error = Some(error);
                        break 'capture;
                    }
                }
                if targets.iter().any(Option::is_none) {
                    let outcomes = manifest.resolve_all();
                    let plans = plan_shared_taps(manifest, &outcomes, args.binary_path.as_ref());
                    // A running target whose own locator now collides with
                    // another's stops, and its session goes to a shared
                    // ambiguous tap below (design doc §5). One whose
                    // locator names another process stops, and the loop
                    // below restarts it there in this same pass. One whose
                    // locator names nothing keeps its tap (a PID file being
                    // rewritten, a cgroup briefly holding a child) unless
                    // another target now claims its session: that one's
                    // tap must not run beside it.
                    let claimed: HashSet<u32> = outcomes
                        .iter()
                        .enumerate()
                        .filter_map(|(index, outcome)| match outcome {
                            // A tap about to start there: a target that is
                            // down, or one moving onto this process.
                            identity::DiscoveryOutcome::Available(process)
                                if targets[index].as_ref().is_none_or(|running| running.process != *process) =>
                            {
                                Some(process.session_id)
                            }
                            _ => None,
                        })
                        .chain(plans.keys().copied())
                        .collect();
                    for index in 0..targets.len() {
                        let Some(target) = targets[index].as_ref() else { continue };
                        match &outcomes[index] {
                            identity::DiscoveryOutcome::Available(process) if *process == target.process => continue,
                            identity::DiscoveryOutcome::Ambiguous { reason, .. } => log::warn!(
                                "target '{}' now collides with another target ({reason}); its traffic is captured as ambiguous",
                                target.agent_ref.agent_key
                            ),
                            identity::DiscoveryOutcome::Available(_) => log::warn!(
                                "target '{}' locator now names another process; moving its tap there",
                                target.agent_ref.agent_key
                            ),
                            _ if claimed.contains(&target.process.session_id) => log::warn!(
                                "target '{}' locator no longer names its running process, which another target now claims; stopping its tap",
                                target.agent_ref.agent_key
                            ),
                            _ => continue,
                        }
                        if let Err(error) = stop_target(
                            &mut targets[index], &mut stream_map, index, &registered, session_id, capture_start, sink,
                        ).await {
                            write_error = Some(error);
                            break 'capture;
                        }
                    }
                    if let Err(error) = reconcile_shared_taps(
                        agentsight,
                        plans,
                        &mut shared,
                        &mut stream_map,
                        session_id,
                        capture_start,
                        sink,
                    ).await {
                        write_error = Some(error);
                        break 'capture;
                    }
                    for (index, outcome) in outcomes.into_iter().enumerate() {
                        if targets[index].is_some() {
                            continue;
                        }
                        let identity::DiscoveryOutcome::Available(process) = outcome else {
                            continue;
                        };
                        let target = &manifest.agents[index];
                        let binary_path = target
                            .capture
                            .as_ref()
                            .and_then(|capture| capture.binary_path.clone())
                            .or_else(|| args.binary_path.clone());
                        let label = format!("'{}'", target.agent_key);
                        match spawn_session_tap(agentsight, binary_path, process.session_id, &label).await {
                            Ok(stream) => {
                                log::info!("target '{}' resolved again; tap restarted", target.agent_key);
                                stream_map.insert(TapSlot::Target(index), stream);
                                targets[index] = Some(TargetRuntime {
                                    agent_ref: manifest.agent_ref(target),
                                    process,
                                    pairer: Pairer::new(),
                                });
                            }
                            Err(error) => log::warn!(
                                "target '{}' resolved again but its tap failed to start: {error:#}",
                                target.agent_key
                            ),
                        }
                    }
                }
                log_target_availability_transition(&targets, &shared, &mut all_targets_down);
            }
            _ = ticker.tick() => {
                if let Some(timeout) = pending_timeout {
                    let now = std::time::Instant::now();
                    for target in targets.iter_mut().flatten() {
                        let expired = target.pairer.expire(now, timeout);
                        report.note_expired(expired.len());
                        if let Err(error) = emit_target_incomplete(
                            target, expired, &registered, session_id, capture_start, sink,
                        ).await {
                            write_error = Some(error);
                            break 'capture;
                        }
                    }
                    for tap in shared.values_mut() {
                        let expired = tap.pairer.expire(now, timeout);
                        report.note_expired(expired.len());
                        if let Err(error) = emit_shared_incomplete(tap, expired, session_id, capture_start, sink).await {
                            write_error = Some(error);
                            break 'capture;
                        }
                    }
                }
                let unmatched = targets.iter().flatten().map(|t| t.pairer.unmatched_responses()).sum::<u64>()
                    + shared.values().map(|t| t.pairer.unmatched_responses()).sum::<u64>();
                report.maybe_log(unmatched, pending_timeout);
                sink.flush_if_due().await
            }
            _ = shutdown.requested() => break 'capture,
        }
    }

    let unmatched = targets
        .iter()
        .flatten()
        .map(|t| t.pairer.unmatched_responses())
        .sum::<u64>()
        + shared
            .values()
            .map(|t| t.pairer.unmatched_responses())
            .sum::<u64>();
    report.log(unmatched, pending_timeout);
    if let Some(error) = write_error {
        return Err(error);
    }
    // Every remaining active tap's requests are flushed the same way a
    // mid-run exit is: a pending request that never got a response before
    // the process stopped capturing is reported, not silently discarded.
    for target in targets.iter_mut().flatten() {
        flush_target_incomplete(target, &registered, session_id, capture_start, sink).await?;
    }
    for tap in shared.values_mut() {
        flush_shared_incomplete(tap, session_id, capture_start, sink).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity::{DiscoveryOutcome, ProcessIncarnation};

    fn manifest() -> identity::TargetManifest {
        serde_yaml::from_str(
            r#"manifest_version: 1
sandbox: {host_id: h, sandbox_name: s, access: {kind: docker, container: c}}
agents:
  - {agent_key: planner, discovery: {pid_file: /run/p.pid}, capture: {binary_path: /usr/bin/node}}
  - {agent_key: executor, discovery: {pid_file: /run/e.pid}, capture: {binary_path: /usr/bin/node}}
  - {agent_key: reviewer, discovery: {pid_file: /run/r.pid}, capture: {binary_path: /usr/bin/python3}}
  - {agent_key: writer, discovery: {pid_file: /run/w.pid}}
"#,
        )
        .unwrap()
    }

    fn process(pid: u32, session_id: u32, uid: u32) -> ProcessIncarnation {
        ProcessIncarnation {
            pid,
            start_time_ticks: u64::from(pid) * 10,
            session_id,
            uid,
        }
    }

    fn ambiguous(process: ProcessIncarnation, colliding: Vec<usize>) -> DiscoveryOutcome {
        DiscoveryOutcome::Ambiguous {
            reason: "collides".into(),
            process,
            colliding,
        }
    }

    #[test]
    fn one_shared_tap_per_colliding_session_naming_every_colliding_target() {
        let manifest = manifest();
        let default = "/usr/bin/default".to_string();
        // planner and executor share one incarnation; reviewer shares their
        // uid from a session of its own; writer is unaffected.
        let outcomes = vec![
            ambiguous(process(10, 10, 1000), vec![1, 2]),
            ambiguous(process(10, 10, 1000), vec![0, 2]),
            ambiguous(process(20, 20, 1000), vec![0, 1]),
            DiscoveryOutcome::Available(process(30, 30, 3000)),
        ];
        let plans = plan_shared_taps(&manifest, &outcomes, Some(&default));
        assert_eq!(plans.keys().copied().collect::<Vec<_>>(), vec![10, 20]);
        let all = vec![
            "executor".to_string(),
            "planner".to_string(),
            "reviewer".to_string(),
        ];
        assert_eq!(plans[&10].candidates, all);
        assert_eq!(plans[&10].incarnations, vec![process(10, 10, 1000)]);
        assert_eq!(plans[&10].binary_path.as_deref(), Some("/usr/bin/node"));
        assert_eq!(plans[&20].candidates, all);
        assert_eq!(plans[&20].binary_path.as_deref(), Some("/usr/bin/python3"));
    }

    #[test]
    fn a_session_with_several_incarnations_or_binaries_keeps_them_all() {
        let manifest = manifest();
        let default = "/usr/bin/default".to_string();
        let outcomes = vec![
            ambiguous(process(12, 10, 1000), vec![2]),
            DiscoveryOutcome::NotFound("gone".into()),
            ambiguous(process(11, 10, 2000), vec![0]),
            DiscoveryOutcome::NotFound("gone".into()),
        ];
        let plans = plan_shared_taps(&manifest, &outcomes, Some(&default));
        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[&10].candidates,
            vec!["planner".to_string(), "reviewer".to_string()]
        );
        assert_eq!(
            plans[&10].incarnations,
            vec![process(11, 10, 2000), process(12, 10, 1000)]
        );
        // Different binaries in one session: the collector-wide default.
        assert_eq!(plans[&10].binary_path.as_deref(), Some("/usr/bin/default"));
    }

    #[test]
    fn no_collision_plans_no_shared_tap() {
        let outcomes = vec![
            DiscoveryOutcome::Available(process(10, 10, 1000)),
            DiscoveryOutcome::Available(process(20, 20, 2000)),
            DiscoveryOutcome::NotFound("gone".into()),
            DiscoveryOutcome::NotFound("gone".into()),
        ];
        assert!(plan_shared_taps(&manifest(), &outcomes, None).is_empty());
    }
}
