//! `sluice up`, `sluice status` and `sluice mcp`: the commands that talk to the live system.

use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde_json::Value;
use sluice_autopilot::RecipeBook;
use sluice_core::event::Timestamp;
use sluice_rules::SigmaRules;
use sluice_server::{Rules, ServerConfig, Status};
use sluice_synth::{SynthConfig, generate};

use crate::cli::{McpArgs, StatusArgs, UpArgs};
use crate::input;

pub(crate) fn up(args: &UpArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    // Apply YAML merge keys (`<<: *anchor`) first; serde does not resolve them on its own.
    let mut yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text)
        .with_context(|| format!("parsing {}", args.config.display()))?;
    yaml.apply_merge()
        .with_context(|| format!("resolving merge keys in {}", args.config.display()))?;
    let config: ServerConfig = serde_yaml_ng::from_value(yaml)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let rules = Rules {
        sigma: SigmaRules::parse(
            read(args.rules.as_deref(), &["yml", "yaml"])?
                .iter()
                .map(String::as_str),
        )?,
        wazuh: input::wazuh(args.wazuh_rules.as_deref(), args.wazuh_decoders.as_deref())?,
    };
    if args.check {
        let sources = config.sources.len();
        let destinations = config.destinations.len();
        let vector = sluice_server::check(config, rules, RecipeBook::embedded()?, control_token())?;
        print!("{vector}");
        eprintln!(
            "configuration ok: {sources} sources, {destinations} destinations; the Vector \
             configuration above is what `sluice up` starts with"
        );
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    if args.demo_traffic {
        let targets = demo_targets(&config)?;
        thread::spawn(move || demo_traffic(&targets));
    }
    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    runtime.block_on(sluice_server::up(
        config,
        rules,
        RecipeBook::embedded()?,
        control_token(),
    ))?;
    Ok(())
}

pub(crate) fn status(args: &StatusArgs) -> Result<()> {
    let url = format!("http://{}/status", args.listen);
    let mut request = ureq::get(&url);
    if let Some(token) = control_token() {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let body = request
        .call()
        .with_context(|| format!("is `sluice up` running? GET {url}"))?
        .body_mut()
        .read_to_string()?;
    let status: Status = serde_json::from_str(&body).context("reading the status")?;
    let Some(last) = &status.last_cycle else {
        println!("No cycle has run yet. Window: {:?}", status.window);
        return Ok(());
    };
    println!("cycles      {}", status.cycles);
    println!(
        "last cycle  {} events, {} templates, {} → {} bytes, alerts {} = {} {}",
        last.events,
        last.templates,
        last.bytes_in,
        last.bytes_out,
        last.alerts_full,
        last.alerts_forwarded,
        if last.proven { "✓" } else { "✗" }
    );
    let count = |stage: &str| status.templates.iter().filter(|t| t.stage == stage).count();
    println!(
        "recipes     {} enforced, {} in shadow",
        count("enforced"),
        count("shadow")
    );
    for record in status.history.iter().rev().take(10) {
        println!("  {} {} {}", utc(record.at), record.kind, record.template);
    }
    if let Some(error) = &status.last_error {
        println!("last error  {error}");
    }
    Ok(())
}

pub(crate) fn mcp(args: McpArgs) -> Result<()> {
    let config = sluice_mcp::McpConfig {
        control_plane: args.listen,
        control_token: control_token(),
        archive: args.archive,
        allow_replay: args.allow_replay,
    };
    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    match args.http {
        None => runtime.block_on(sluice_mcp::serve_stdio(config))?,
        Some(listen) => {
            let token = std::env::var("SLUICE_MCP_TOKEN")
                .context("`--http` needs the bearer token in SLUICE_MCP_TOKEN")?;
            if token.chars().count() < sluice_mcp::MIN_TOKEN_LEN {
                return Err(sluice_mcp::McpError::Token(sluice_mcp::MIN_TOKEN_LEN).into());
            }
            let options = sluice_mcp::HttpOptions {
                listen,
                token,
                allowed_hosts: args.allowed_hosts,
            };
            eprintln!("serving MCP at http://{listen}/mcp");
            runtime.block_on(sluice_mcp::serve_http(config, options))?;
        }
    }
    Ok(())
}

/// The control plane's bearer token from the environment, if one is set.
fn control_token() -> Option<String> {
    std::env::var(sluice_server::CONTROL_TOKEN_ENV)
        .ok()
        .filter(|t| !t.is_empty())
}

/// Unix seconds as UTC wall time, for people reading `sluice status`.
fn utc(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0).map_or_else(
        || at.to_string(),
        |t| t.format("%Y-%m-%d %H:%M:%SZ").to_string(),
    )
}

fn read(dir: Option<&Path>, extensions: &[&str]) -> Result<Vec<String>> {
    match dir {
        Some(dir) => Ok(input::files(dir, extensions)?
            .into_iter()
            .map(|(_, text)| text)
            .collect()),
        None => Ok(Vec::new()),
    }
}

/// `(source id, URL)` of every `http_server` source in the configuration.
fn demo_targets(config: &ServerConfig) -> Result<Vec<(String, String)>> {
    let targets: Vec<(String, String)> = config
        .sources
        .iter()
        .filter(|s| s.vector["type"] == "http_server")
        .filter_map(|s| {
            let address = s.vector["address"].as_str()?;
            Some((s.source.id.to_string(), format!("http://{address}/")))
        })
        .collect();
    if targets.is_empty() {
        bail!("--demo-traffic needs sources with `vector: {{type: http_server, address: ...}}`");
    }
    Ok(targets)
}

/// Every 10 seconds, posts ten seconds' worth of synthetic traffic (stamped now, three times the
/// demo hour's rate) to each source, once Vector's sources accept connections.
fn demo_traffic(targets: &[(String, String)]) {
    wait_for_sources(targets);
    let mut seed = 0u64;
    loop {
        seed = seed.wrapping_add(1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let sample = generate(&SynthConfig {
            seed,
            start: Timestamp(i64::try_from(now).unwrap_or(0)),
            duration_secs: 10,
            scale_percent: 300,
        });
        for (source, url) in targets {
            let body: String = sample
                .events
                .iter()
                .filter(|e| e.source.as_str() == source)
                .map(|e| Value::Object(e.fields.clone()).to_string() + "\n")
                .collect();
            if let Err(error) = ureq::post(url).send(&body) {
                eprintln!("demo traffic to {source}: {error}");
            }
        }
        thread::sleep(Duration::from_secs(10));
    }
}

/// Waits up to 30 s until every source's address accepts a TCP connection (Vector starts after
/// the control plane).
fn wait_for_sources(targets: &[(String, String)]) {
    let addresses: Vec<std::net::SocketAddr> = targets
        .iter()
        .filter_map(|(_, url)| {
            let host = url.strip_prefix("http://")?.trim_end_matches('/');
            // A wildcard listen address is reached through loopback.
            host.replace("0.0.0.0", "127.0.0.1").parse().ok()
        })
        .collect();
    for _ in 0..60 {
        let ready = addresses.iter().all(|address| {
            std::net::TcpStream::connect_timeout(address, Duration::from_millis(200)).is_ok()
        });
        if ready {
            return;
        }
        thread::sleep(Duration::from_millis(500));
    }
}
