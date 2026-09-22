//! A local OpenAI-compatible HTTP proxy in front of PPQ.AI's attested TEE
//! models. Attests the enclave on startup (and again as the key ages or is
//! rejected), then serves `/v1/models` and `/v1/chat/completions` on
//! localhost with every completion sealed to the attested key.

mod attested;
mod backend;
mod server;

use attested::{Attested, Attester, ReattestPolicy};
use clap::Parser;
use futures::FutureExt;
use ppq_tee::PpqClient;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Address to serve the OpenAI-compatible API on.
    #[arg(long, env = "PPQ_PROXY_LISTEN", default_value = "127.0.0.1:8090")]
    listen: SocketAddr,

    /// File holding the PPQ API key (trailing whitespace ignored). Takes
    /// precedence over the `PPQ_API_KEY` environment variable.
    #[arg(long, env = "PPQ_API_KEY_FILE")]
    api_key_file: Option<PathBuf>,

    /// PPQ API base URL.
    #[arg(long, env = "PPQ_BASE_URL", default_value = ppq_tee::client::DEFAULT_BASE_URL)]
    base_url: String,

    /// Re-attest the enclave once the current attestation is this old, even
    /// if nothing has failed (e.g. "1h", "30m").
    #[arg(long, env = "PPQ_REATTEST_AFTER", default_value = "1h", value_parser = humantime::parse_duration)]
    reattest_after: Duration,
}

#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error("no API key: pass --api-key-file or set PPQ_API_KEY")]
    NoApiKey,
    #[error("reading API key file {path}: {source}")]
    ReadApiKey {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("API key is empty")]
    EmptyApiKey,
    #[error("initial attestation failed: {0}")]
    Attest(#[from] ppq_tee::Error),
    #[error("binding {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("serving: {0}")]
    Serve(std::io::Error),
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // `Display`, not the `Debug` a `Result`-returning `main` would
            // print: "no API key: pass --api-key-file ..." beats "NoApiKey".
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), StartupError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,tower_http=info"
                    .parse()
                    .expect("static filter parses")
            }),
        )
        .init();

    let args = Args::parse();
    let api_key = load_api_key(args.api_key_file.as_deref()).await?;

    let base_url = args.base_url.clone();
    let attest: Attester<PpqClient> = Box::new(move || {
        let api_key = api_key.clone();
        let base_url = base_url.clone();
        async move {
            let client = PpqClient::builder()
                .api_key(api_key)
                .base_url(base_url)
                .build()
                .await?;
            let a = client.attestation();
            tracing::info!(
                domain = %a.domain,
                measurement = %hex_prefix(&a.measurement),
                "attested the enclave"
            );
            Ok(client)
        }
        .boxed()
    });
    let policy = ReattestPolicy {
        reattest_after: args.reattest_after,
        ..ReattestPolicy::default()
    };
    let client = Arc::new(Attested::new(attest, policy).await?);

    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .map_err(|source| StartupError::Bind {
            addr: args.listen,
            source,
        })?;
    tracing::info!(listen = %args.listen, base_url = %args.base_url, "serving the OpenAI-compatible API");
    axum::serve(listener, server::router(client))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(StartupError::Serve)
}

/// The file wins over the environment so a systemd credential cannot be
/// silently shadowed by a stray variable.
async fn load_api_key(file: Option<&std::path::Path>) -> Result<String, StartupError> {
    let raw =
        match file {
            Some(path) => tokio::fs::read_to_string(path).await.map_err(|source| {
                StartupError::ReadApiKey {
                    path: path.to_path_buf(),
                    source,
                }
            })?,
            None => std::env::var("PPQ_API_KEY").map_err(|_| StartupError::NoApiKey)?,
        };
    let key = raw.trim();
    if key.is_empty() {
        return Err(StartupError::EmptyApiKey);
    }
    Ok(key.to_string())
}

/// The first eight bytes of a measurement, enough to recognise a deployment in
/// a log line without printing 96 hex characters.
fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler installs on linux");
    // Both arms are cancel-safe: dropping a pending `ctrl_c`/`recv` future
    // loses nothing, the signal is simply delivered to whoever listens next.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    tracing::info!("shutdown signal received; finishing in-flight requests");
}
