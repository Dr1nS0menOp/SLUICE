//! `sluice agent`: the Vector configuration for a collection agent on a host.

use anyhow::{Context, Result};
use sluice_vector::windows::{self, Central};

use crate::cli::{AgentArgs, AgentPlatform};

pub(crate) fn agent(args: &AgentArgs) -> Result<()> {
    match args.platform {
        AgentPlatform::Windows => {
            let central = Central {
                security: &args.to,
                events: args.events_to.as_deref(),
            };
            let yaml = windows::agent_config(&args.channels, central, &args.data_dir)?;
            println!(
                "# `sluice agent windows`: Vector configuration for a Windows host (Vector 0.59+,\n\
                 # `windows_event_log` source). Run it as a service (LocalSystem) to read Security.\n\
                 # Events leave the host as Vector reads them, Security to one URL, other channels\n\
                 # to the other. In the `sluice up` configuration, add a source for each URL; it\n\
                 # archives the original, then shapes it as the Sentinel table's record:\n\
                 #\n\
                 #   sources:\n\
                 #     - id: windows-security\n\
                 #       logsource: {{ product: windows, service: security }}\n\
                 #       format: {{ kind: json }}\n\
                 #       shape: sentinel_security_event\n\
                 #       vector: {{ type: http_server, address: 0.0.0.0:<port>,\n\
                 #                 decoding: {{ codec: json }}, framing: {{ method: newline_delimited }} }}\n\
                 #     - id: windows-events\n\
                 #       logsource: {{ product: windows }}\n\
                 #       shape: sentinel_windows_event\n\
                 #       …\n\
                 #\n\
                 # and give each Sentinel destination its stream and `sluice_sources`."
            );
            print!("{yaml}");
            if let (Some(path), Some(workspace)) = (&args.dcr, &args.workspace) {
                let dcr = windows::windows_dcr(&args.location, workspace);
                std::fs::write(path, serde_json::to_string_pretty(&dcr)? + "\n")
                    .with_context(|| format!("writing {}", path.display()))?;
                eprintln!(
                    "wrote {}: create it in Azure and grant the app registration Monitoring \
                     Metrics Publisher on it. Streams: {} (SecurityEvent), {} (WindowsEvent).",
                    path.display(),
                    windows::SECURITY_EVENT_STREAM,
                    windows::WINDOWS_EVENT_STREAM
                );
            }
        }
    }
    Ok(())
}
