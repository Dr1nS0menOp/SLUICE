//! In proposal mode (ADR 0022) Sluice does not choose what Vector runs: the operator deploys a
//! reviewed proposal to `vector_config`. What Sluice does is check it. Every cycle, the running
//! configuration's programs are read back and proven on the window, profile by profile. A
//! configuration that proves is (re)loaded; one that does not, or that Sluice cannot read, is
//! replaced at once by the safe configuration, which saves nothing. Switching savings off only
//! ever sends the SIEM more data, so Sluice may do it without asking.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::PoisonError;

use sluice_core::alert::{Engines, RuleEngine};
use sluice_core::event::Event;
use sluice_core::proof::prove;

use crate::control::{Profile, Shared, lock, write_atomic};
use crate::error::ServerError;
use crate::status::TransitionRecord;

/// The last running configuration Sluice proved, kept so a restart can keep running it.
const PROVEN_COPY: &str = "sluice-proven.yaml";

impl Shared {
    fn proven_copy(&self) -> PathBuf {
        self.config.data_dir.join(PROVEN_COPY)
    }

    /// The configuration Vector starts with in proposal mode: the running one, if it is exactly
    /// the one Sluice last proved (the next cycle proves it again), otherwise the safe one.
    pub(crate) fn write_startup_config(&self) -> Result<(), ServerError> {
        let running = fs::read_to_string(&self.config.vector_config).ok();
        let proven = fs::read_to_string(self.proven_copy()).ok();
        match running {
            Some(running) if proven.as_ref() == Some(&running) => {
                tracing::info!("keeping the deployed configuration Sluice proved before");
                *lock(&self.running) = running;
                Ok(())
            }
            _ => {
                let safe = self.initial_config()?;
                write_atomic(&self.config.vector_config, &safe)?;
                *lock(&self.running) = safe;
                Ok(())
            }
        }
    }

    /// Proves the configuration Vector runs on this cycle's window. Returns whether Vector must
    /// reload: because the operator deployed a new, proven configuration, or because Sluice
    /// switched to the safe one.
    pub(crate) fn guard_running(&self, events: &[Event], now: i64) -> Result<bool, ServerError> {
        let deployed = fs::read_to_string(&self.config.vector_config).map_err(|e| {
            ServerError::Io(format!("{}: {e}", self.config.vector_config.display()))
        })?;
        let safe = self.initial_config()?;
        let mut running = lock(&self.running);
        if deployed == safe {
            let changed = *running != deployed;
            *running = deployed;
            self.set_running_status("safe configuration: nothing is saved");
            return Ok(changed);
        }
        let failure = self.prove_every_profile(&deployed, events).err();
        match failure {
            None => {
                let changed = *running != deployed;
                write_atomic(&self.proven_copy(), &deployed)?;
                *running = deployed;
                self.set_running_status("deployed configuration, proven on the last window");
                Ok(changed)
            }
            Some(reason) => {
                tracing::warn!(%reason, "the deployed configuration failed its proof; switching to the safe configuration");
                write_atomic(&self.config.vector_config, &safe)?;
                let _ = fs::remove_file(self.proven_copy());
                *running = safe;
                self.record_switch_off(now, &reason);
                Ok(true)
            }
        }
    }

    /// Proves every profile's programs in `deployed`, and that they are all its programs: a
    /// program Sluice cannot place (renamed, or from another profile layout) would run unproven.
    fn prove_every_profile(&self, deployed: &str, events: &[Event]) -> Result<(), String> {
        let tagged = self.profiles.len() > 1;
        let mut proven = BTreeSet::new();
        let mut programs = BTreeSet::new();
        for profile in &self.profiles {
            let read = self
                .prove_running(deployed, profile, events, tagged)
                .map_err(|why| format!("profile {}: {why}", profile.name))?;
            proven.extend(read.read);
            programs = read.programs;
        }
        let unproven: Vec<&String> = programs.difference(&proven).collect();
        if unproven.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "it runs programs Sluice does not prove ({})",
                unproven
                    .iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
    }

    /// Proves one profile's programs in `deployed` on `events`; the error says why not.
    fn prove_running(
        &self,
        deployed: &str,
        profile: &Profile,
        events: &[Event],
        tagged: bool,
    ) -> Result<sluice_vector::Deployed, String> {
        let name = tagged.then_some(profile.name.as_str());
        let read =
            sluice_vector::deployed(deployed, &self.sources, name).map_err(|e| e.to_string())?;
        let input = self.input(profile, events);
        let sigma = input
            .sigma
            .engine(input.sources)
            .map_err(|e| e.to_string())?;
        let mut engines: Vec<&dyn RuleEngine> = vec![&sigma];
        engines.extend(input.sentinel.and_then(|s| s.engine));
        let proof = prove(events, &Engines(engines), &read.reducer).map_err(|e| e.to_string())?;
        if proof.holds() {
            Ok(read)
        } else {
            Err(format!(
                "it changes detections ({} missing, {} extra alerts)",
                proof.missing.len(),
                proof.extra.len()
            ))
        }
    }

    fn set_running_status(&self, what: &str) {
        for profile in &self.profiles {
            let mut status = profile
                .status
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            status.running = Some(what.to_owned());
        }
    }

    fn record_switch_off(&self, now: i64, reason: &str) {
        let what = format!(
            "safe configuration since {now}: the deployed configuration failed its proof ({reason}); \
             every event is forwarded unchanged until a new proposal is deployed"
        );
        for profile in &self.profiles {
            let mut status = profile
                .status
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            status.running = Some(what.clone());
            status.push_history(TransitionRecord {
                at: now,
                kind: "switched_off".to_owned(),
                template: "*".to_owned(),
                actor: None,
                reason: Some(reason.to_owned()),
                acknowledged: false,
            });
        }
    }
}
