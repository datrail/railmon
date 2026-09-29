//! RailMon — the runtime-interaction collector.
//!
//! Spawns AgentSight, pairs the HTTP it reconstructs into interactions,
//! attributes each one to an agent from its `x-rail` ticket, and forwards them.
//!
//! The CLI is deliberately unchanged from the Python it replaces: existing
//! compose files, run scripts and the container entrypoint pass these flags,
//! and a port that quietly renamed them would break every caller for no gain.

mod identity;
mod interaction;
mod pipeline;
mod sink;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use futures::{Stream, StreamExt};
use pipeline::{CaptureFilters, Pairer};
use sink::Sink;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;
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

    /// Session id recorded on every interaction. Generated when not given.
    #[arg(long)]
    session_id: Option<String>,
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

    // Fail on a missing binary before opening sinks or claiming to capture:
    // the old failure mode was a collector that looked alive and produced
    // nothing.
    let agentsight = resolve_probe_path(args.agentsight.clone());
    if !std::path::Path::new(&agentsight).exists() {
        anyhow::bail!(
            "probe not found at {agentsight} — set --agentsight, AGENTSIGHT_PATH or SSLSNIFF_PATH, or run `make fetch-agentsight`"
        );
    }

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
    .context("configuring output")?;

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
        process_session: None,
    };

    log::info!("session {session_id}, agentsight at {}", agentsight);
    let (mut stream, stream_status) = pipeline::event_stream(&agentsight, &filters).await?;

    let mut pairer = Pairer::new();
    let mut write_error: Option<anyhow::Error> = None;
    let mut ticker = tokio::time::interval(flush_interval.max(Duration::from_millis(100)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // Biased so a pending event is always handled before the timer,
            // keeping the flush a lower priority than not losing data.
            biased;

            maybe_event = stream.next() => {
                let Some(event) = maybe_event else { break };

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

            _ = ticker.tick() => sink.flush_if_due().await,

            _ = tokio::signal::ctrl_c() => {
                log::info!("interrupted");
                break;
            }
        }
    }

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
    // it, so leaving the loop via ctrl_c would otherwise block here for ever —
    // and `kill_on_drop` would never fire, leaving the probe running with its
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
        // A dropped sender means we left the loop before the probe's output
        // ended, which is what ctrl_c does. Not a failure.
        _ => Ok(()),
    }
}

struct TargetRuntime {
    agent_ref: identity::AgentRef,
    process: identity::ProcessIncarnation,
    pairer: Pairer,
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

/// Spawns one target's tap, scoped to its pinned incarnation's process
/// session, and wraps its event/exit streams into one `TargetStreamItem`
/// stream keyed later by manifest index in a `StreamMap`. Used both at
/// startup and to restart a target whose tap previously stopped.
async fn spawn_target_tap(
    agentsight: &str,
    binary_path: Option<String>,
    process: identity::ProcessIncarnation,
    agent_key: &str,
) -> Result<TargetStream> {
    let filters = CaptureFilters {
        binary_path,
        pid: None,
        uid: None,
        comm: None,
        process_session: Some(process.session_id),
    };
    let (stream, status) = pipeline::event_stream(agentsight, &filters)
        .await
        .with_context(|| format!("starting tap for '{agent_key}'"))?;
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
    session_id: &str,
    capture_start: &str,
    sink: &mut Sink,
) -> Result<()> {
    for mut paired in target.pairer.flush_incomplete() {
        paired["target_pid"] = serde_json::json!(target.process.pid);
        paired["process_start_time_ticks"] = serde_json::json!(target.process.start_time_ticks);
        let value = interaction::to_attributed_runtime_interaction(
            &paired,
            Some(session_id),
            Some(capture_start),
            "railmon",
            Some(&target.agent_ref),
        );
        sink.emit(&value).await?;
    }
    Ok(())
}

/// Stops one running target: flushes its pending requests as incomplete and
/// drops its tap stream (which kills the tap), leaving the slot `None` so the
/// retry tick re-resolves it. A no-op for a target that is already down.
async fn stop_target(
    slot: &mut Option<TargetRuntime>,
    stream_map: &mut StreamMap<usize, TargetStream>,
    index: usize,
    session_id: &str,
    capture_start: &str,
    sink: &mut Sink,
) -> Result<()> {
    stream_map.remove(&index);
    match slot.take() {
        Some(mut target) => {
            flush_target_incomplete(&mut target, session_id, capture_start, sink).await
        }
        None => Ok(()),
    }
}

/// The collector no longer exits when every target is simultaneously down
/// (it keeps retrying discovery instead), which means an operator watching
/// only the process's exit code would never learn that capture went fully
/// idle. Logs the edge, not every retry tick, so this stays quiet as long as
/// at least one target is running.
fn log_target_availability_transition(
    targets: &[Option<TargetRuntime>],
    all_targets_down: &mut bool,
) {
    let now = targets.iter().all(Option::is_none);
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

async fn run_multi_target(
    args: &Args,
    manifest: &identity::TargetManifest,
    agentsight: &str,
    session_id: &str,
    capture_start: &str,
    sink: &mut Sink,
    flush_interval: Duration,
) -> Result<()> {
    if matches!(args.mode, Mode::Raw) {
        anyhow::bail!(
            "keyed capture requires --mode http; raw events have no attribution envelope"
        );
    }
    if !matches!(args.output_format, OutputFormat::RuntimeInteraction) {
        anyhow::bail!("keyed capture requires --output-format runtime-interaction");
    }
    if args.pid.is_some() || args.uid.is_some() || args.comm.is_some() {
        anyhow::bail!("--pid, --uid and --comm cannot be combined with --target-manifest");
    }

    let outcomes = manifest.resolve_all();
    // Indexed by each declared agent's position in `manifest.agents`, which
    // never changes for the life of this run. `None` means "not currently
    // capturing" — either never resolved, or resolved and then stopped —
    // and is retried on `retry_ticker` rather than ending the whole run.
    let mut targets: Vec<Option<TargetRuntime>> = Vec::with_capacity(manifest.agents.len());
    let mut stream_map: StreamMap<usize, TargetStream> = StreamMap::new();
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
                let stream =
                    match spawn_target_tap(agentsight, binary_path, process, &target.agent_key)
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
                stream_map.insert(index, stream);
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
            identity::DiscoveryOutcome::Ambiguous(reason) => {
                log::warn!("target '{}' is ambiguous: {reason}", target.agent_key);
                targets.push(None);
            }
        }
    }
    if !any_available {
        anyhow::bail!("no declared agent resolved to a capturable process");
    }

    let mut ticker = tokio::time::interval(flush_interval.max(Duration::from_millis(100)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut retry_ticker = tokio::time::interval(TARGET_RETRY_INTERVAL);
    retry_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut write_error = None;
    let mut all_targets_down = false;
    'capture: loop {
        tokio::select! {
            biased;
            // `StreamMap::poll_next` returns `Ready(None)` whenever the map
            // is empty (every target currently down), which would otherwise
            // make this branch always-ready and starve the other branches —
            // hence the guard.
            next = stream_map.next(), if !stream_map.is_empty() => {
                let Some((index, item)) = next else { continue };
                match item {
                    TargetStreamItem::Event(event) => {
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
                                &mut targets[index], &mut stream_map, index, session_id, capture_start, sink,
                            ).await {
                                write_error = Some(error);
                                break 'capture;
                            }
                            log_target_availability_transition(&targets, &mut all_targets_down);
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
                                Some(&target.agent_ref),
                            );
                            if let Err(error) = sink.emit(&value).await {
                                write_error = Some(error);
                                break 'capture;
                            }
                        }
                    }
                    TargetStreamItem::Ended(status) => {
                        let detail = match status {
                            Ok(Some(status)) => status.to_string(),
                            Ok(None) => "unknown exit status".into(),
                            Err(error) => error.to_string(),
                        };
                        if let Some(target) = targets[index].as_ref() {
                            log::warn!(
                                "target '{}' tap ended ({detail}); flushing pending requests as incomplete, will retry discovery",
                                target.agent_ref.agent_key
                            );
                        }
                        if let Err(error) = stop_target(
                            &mut targets[index], &mut stream_map, index, session_id, capture_start, sink,
                        ).await {
                            write_error = Some(error);
                            break 'capture;
                        }
                        log_target_availability_transition(&targets, &mut all_targets_down);
                    }
                }
            }
            // A target that is currently down — not_found, ambiguous, or its
            // tap just stopped — is never dropped for good: retry its
            // locator on a bounded interval and restart its tap the moment
            // it resolves again. The restarted process keeps the same
            // `agent_key` and gets a new, freshly pinned incarnation (design
            // doc §4.4): none of the other running targets are disturbed.
            _ = retry_ticker.tick() => {
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
                        slot, &mut stream_map, index, session_id, capture_start, sink,
                    ).await {
                        write_error = Some(error);
                        break 'capture;
                    }
                }
                if targets.iter().any(Option::is_none) {
                    let outcomes = manifest.resolve_all();
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
                        match spawn_target_tap(agentsight, binary_path, process, &target.agent_key).await {
                            Ok(stream) => {
                                log::info!("target '{}' resolved again; tap restarted", target.agent_key);
                                stream_map.insert(index, stream);
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
                    log_target_availability_transition(&targets, &mut all_targets_down);
                }
            }
            _ = ticker.tick() => sink.flush_if_due().await,
            _ = tokio::signal::ctrl_c() => break 'capture,
        }
    }

    if let Some(error) = write_error {
        return Err(error);
    }
    // Every remaining active target's requests are flushed the same way a
    // mid-run exit is: a pending request that never got a response before
    // the process stopped capturing is reported, not silently discarded.
    for target in targets.iter_mut().flatten() {
        flush_target_incomplete(target, session_id, capture_start, sink).await?;
    }
    Ok(())
}
