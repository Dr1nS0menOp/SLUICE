//! The Sluice control plane (`sluice up`, ADR 0005).
//!
//! It runs Vector as a child process, receives a sampled tap of every source, and every cycle
//! re-analyzes the rolling window: recipes are shadowed, promoted once proven long enough, and
//! rolled back the moment a proof fails. Each change rewrites Vector's configuration, which Vector
//! reloads on its own. If the control plane stops, Vector keeps running the last configuration.

mod archive;
mod config;
mod control;
mod error;
mod routes;
mod status;
#[cfg(test)]
mod tests;
mod ui;
mod window;

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sluice_autopilot::{RecipeBook, Transition};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};

pub use crate::config::{LiveSourceConfig, PromotionConfig, ServerConfig, WindowConfig};
pub use crate::control::Rules;
use crate::control::Shared;
pub use crate::error::ServerError;
pub use crate::status::{
    CycleStatus, RuleInfo, SourceHealth, Status, TemplateDetail, TemplateStatus, TransitionRecord,
};

/// The environment variable from which `sluice` reads the control plane's bearer token. Vector
/// gets it through a secret backend (a file only this user can read), never through its config.
pub const CONTROL_TOKEN_ENV: &str = "SLUICE_CONTROL_TOKEN";

/// The shortest control token accepted.
pub const MIN_CONTROL_TOKEN_LEN: usize = 32;

/// Runs the control plane and Vector until Ctrl-C, or until Vector exits.
///
/// With `control_token`, every route but `/healthz` requires `Authorization: Bearer <token>`.
/// Without one, the control plane only listens on a loopback address: anyone who can post to
/// `/tap` shapes the sample the proofs run on.
///
/// # Errors
///
/// Returns [`ServerError`] if the listener, the configuration or Vector cannot be set up, if the
/// control plane would listen beyond loopback without a token, or if Vector exits on its own.
pub async fn up(
    config: ServerConfig,
    rules: Rules,
    book: RecipeBook,
    control_token: Option<String>,
) -> Result<(), ServerError> {
    check_config(&config, control_token.as_deref())?;
    let listener = TcpListener::bind(&config.listen)
        .await
        .map_err(|e| ServerError::Io(format!("cannot listen on {}: {e}", config.listen)))?;
    for dir in [&config.archive_dir, &config.data_dir] {
        std::fs::create_dir_all(dir)
            .map_err(|e| ServerError::Io(format!("{}: {e}", dir.display())))?;
    }
    let shared = Arc::new(Shared::new(config, rules, book, control_token));
    shared.write_secrets()?;
    shared.write_initial_config()?;
    let mut vector = spawn_vector(&shared.config)?;
    tracing::info!(listen = %shared.config.listen, "control plane listening");

    let server = axum::serve(listener, routes::router(Arc::clone(&shared)));
    let control = control_loop(Arc::clone(&shared), vector.id());
    tokio::select! {
        result = server => result.map_err(|e| ServerError::Io(e.to_string()))?,
        () = control => {}
        status = vector.wait() => {
            return Err(ServerError::Vector(format!("exited unexpectedly ({status:?})")));
        }
        () = shutdown_signal() => tracing::info!("shutting down"),
    }
    stop_vector(&mut vector).await
}

/// Checks a configuration without starting anything: the safety checks `up` makes, and the
/// Vector configuration it would start with (every source passing through). Returns that
/// configuration, for `vector validate`.
///
/// # Errors
///
/// As [`up`], for everything short of binding and starting Vector.
pub fn check(
    config: ServerConfig,
    rules: Rules,
    book: RecipeBook,
    control_token: Option<String>,
) -> Result<String, ServerError> {
    check_config(&config, control_token.as_deref())?;
    Shared::new(config, rules, book, control_token).initial_config()
}

fn check_config(config: &ServerConfig, control_token: Option<&str>) -> Result<(), ServerError> {
    check_exposure(&config.listen, control_token)?;
    if config.vector_secrets.contains_key(control::SECRET_BACKEND) {
        return Err(ServerError::Refused(format!(
            "vector_secrets: the name `{}` is reserved for Sluice",
            control::SECRET_BACKEND
        )));
    }
    Ok(())
}

/// Refuses a short token, and a non-loopback listen address without a token.
fn check_exposure(listen: &str, token: Option<&str>) -> Result<(), ServerError> {
    if let Some(token) = token {
        if token.chars().count() < MIN_CONTROL_TOKEN_LEN {
            return Err(ServerError::Refused(format!(
                "{CONTROL_TOKEN_ENV} must be at least {MIN_CONTROL_TOKEN_LEN} characters"
            )));
        }
        return Ok(());
    }
    let loopback = listen.parse::<std::net::SocketAddr>().map_or_else(
        |_| listen.starts_with("localhost:"),
        |a| a.ip().is_loopback(),
    );
    if loopback {
        Ok(())
    } else {
        Err(ServerError::Refused(format!(
            "listen {listen} is reachable beyond this host: set {CONTROL_TOKEN_ENV} (at least \
             {MIN_CONTROL_TOKEN_LEN} characters), or listen on 127.0.0.1"
        )))
    }
}

/// Resolves on Ctrl-C (SIGINT) or SIGTERM, the signal systemd and container runtimes send.
async fn shutdown_signal() {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::warn!(%error, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
}

/// How long Vector gets to flush its sinks, the archive above all, before it is killed.
const VECTOR_GRACE: Duration = Duration::from_secs(60);

/// Stops Vector gracefully (SIGTERM) so buffered events reach the archive and destinations; kills
/// it only if it does not exit within [`VECTOR_GRACE`].
async fn stop_vector(vector: &mut Child) -> Result<(), ServerError> {
    if let Some(pid) = vector
        .id()
        .and_then(|p| i32::try_from(p).ok())
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        if tokio::time::timeout(VECTOR_GRACE, vector.wait())
            .await
            .is_ok()
        {
            return Ok(());
        }
        tracing::warn!("Vector did not stop in time; killing it");
    }
    vector
        .kill()
        .await
        .map_err(|e| ServerError::Vector(format!("cannot stop: {e}")))
}

fn spawn_vector(config: &ServerConfig) -> Result<Child, ServerError> {
    Command::new(&config.vector_binary)
        .arg("--config")
        .arg(&config.vector_config)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            ServerError::Vector(format!(
                "cannot start {}: {e}",
                config.vector_binary.display()
            ))
        })
}

/// Runs a cycle every `cycle_secs` on a blocking thread, and makes Vector reload whenever the
/// configuration changed. A failed cycle keeps the previous configuration and is reported in
/// the status.
async fn control_loop(shared: Arc<Shared>, vector_pid: Option<u32>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(shared.config.cycle_secs.max(1)));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let worker = Arc::clone(&shared);
        let result = tokio::task::spawn_blocking(move || worker.run_cycle(unix_now())).await;
        match result {
            Ok(Ok(report)) => {
                log_transitions(&report.transitions);
                if report.config_changed {
                    reload_vector(vector_pid);
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(%error, "cycle failed; previous configuration stays in force");
                let mut status = shared
                    .status
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                status.last_error = Some(error.to_string());
            }
            Err(error) => {
                tracing::error!(%error, "cycle panicked; previous configuration stays in force");
            }
        }
    }
}

/// Asks Vector to reload its configuration (SIGHUP). File watching is not used: an atomic
/// rename replaces the inode a watcher follows, so reloads would be missed.
fn reload_vector(pid: Option<u32>) {
    let pid = pid
        .and_then(|p| i32::try_from(p).ok())
        .and_then(rustix::process::Pid::from_raw);
    let Some(pid) = pid else {
        tracing::warn!("cannot signal Vector: no process id");
        return;
    };
    match rustix::process::kill_process(pid, rustix::process::Signal::HUP) {
        Ok(()) => tracing::info!("asked Vector to reload"),
        Err(error) => tracing::warn!(%error, "cannot signal Vector to reload"),
    }
}

fn log_transitions(transitions: &[Transition]) {
    for transition in transitions {
        match transition {
            Transition::Shadowing(t) => tracing::info!(template = %t, "recipe proven, in shadow"),
            Transition::Promoted(t) => tracing::info!(template = %t, "recipe promoted: enforced"),
            Transition::Demoted(t) => {
                tracing::warn!(template = %t, "recipe in shadow failed a proof");
            }
            Transition::RolledBack(t) => {
                tracing::warn!(template = %t, "enforced recipe ROLLED BACK");
            }
        }
    }
}

/// The current time in Unix seconds (the control plane is the one place that reads the clock).
pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
