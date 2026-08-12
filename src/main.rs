//! RailMon — the runtime-interaction collector.
//!
//! Spawns AgentSight, pairs the HTTP it reconstructs into interactions,
//! attributes each one to an agent from its `x-rail` ticket, and forwards them.
//!
//! The CLI is deliberately unchanged from the Python it replaces: existing
//! compose files, run scripts and the container entrypoint pass these flags,
//! and a port that quietly renamed them would break every caller for no gain.

mod interaction;
mod pipeline;
mod sink;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use futures::StreamExt;
use pipeline::{CaptureFilters, Pairer};
use sink::Sink;
use std::path::PathBuf;
use std::time::Duration;

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

    /// Path to the agentsight binary.
    #[arg(
        long,
        alias = "sslsniff",
        env = "AGENTSIGHT_PATH",
        default_value = "/usr/local/bin/agentsight"
    )]
    agentsight: String,

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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    // Fail on a missing binary before opening sinks or claiming to capture:
    // the old failure mode was a collector that looked alive and produced
    // nothing.
    if !std::path::Path::new(&args.agentsight).exists() {
        anyhow::bail!(
            "agentsight not found at {} — set --agentsight or AGENTSIGHT_PATH, or run `make fetch-agentsight`",
            args.agentsight
        );
    }

    let mut sink = Sink::new(
        args.output.as_deref(),
        args.webhook.as_deref(),
        args.batch_size,
        Duration::from_secs_f64(args.flush_interval),
    )
    .context("configuring output")?;

    if sink.is_silent() {
        log::warn!("no --webhook and no --output: interactions will be counted but not stored");
    }

    let session_id = args
        .session_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let capture_start = chrono::Utc::now().to_rfc3339();

    let filters = CaptureFilters {
        binary_path: args.binary_path.clone(),
        pid: args.pid,
        uid: args.uid,
        comm: args.comm.clone(),
    };

    log::info!("session {session_id}, agentsight at {}", args.agentsight);
    let mut stream = pipeline::event_stream(&args.agentsight, &filters).await?;

    let mut pairer = Pairer::new();
    let mut ticker = tokio::time::interval(Duration::from_secs_f64(args.flush_interval.max(0.1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // Biased so a pending event is always handled before the timer,
            // keeping the flush a lower priority than not losing data.
            biased;

            maybe_event = stream.next() => {
                let Some(event) = maybe_event else { break };

                let emitted = match args.mode {
                    Mode::Raw => Some(serde_json::to_value(&event)?),
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

                if let Some(value) = emitted {
                    sink.emit(&value).await?;
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
    Ok(())
}
