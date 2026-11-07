//! `sluice verify`: whether an analysis's plan still holds, on a newer sample and the rules the
//! SIEM runs now (ADR 0039).
//!
//! The configuration the plan was written as is proven again, on the new sample with the rules
//! of now, as `sluice prove` does; the rules are compared with those the plan was proven with;
//! and the new sample's savings are compared with the plan's.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::json;
use sluice_autopilot::{RecordedPlan, Verdict, Verification, VerifyInput, fingerprints};
use sluice_core::alert::{Engines, RuleEngine};

use crate::cli::VerifyArgs;
use crate::commands::rules_basis;
use crate::input;
use crate::stdout::out;

/// The exit code of a plan that is out of date: 2 is the usage error of the argument parser.
pub(crate) const OUT_OF_DATE: u8 = 3;

/// Runs the verification and prints it; the verdict decides the exit code.
pub(crate) fn verify(args: &VerifyArgs) -> Result<Verdict> {
    let plan_path = args.analysis.join("plan.json");
    let plan = read_plan(&plan_path)?;
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| args.analysis.join("vector.yaml"));
    let yaml = std::fs::read_to_string(&config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let sources = input::sources(&args.sources)?;
    let events = input::events(&args.input, &sources)?;
    let loaded = input::rule_sets(&args.sets, &args.sentinel_table)?;
    if loaded.requirements().is_empty() {
        bail!(
            "no rules to verify the plan against: give the rules your SIEM runs now, as for \
             `sluice analyze`"
        );
    }
    let sigma = loaded.sigma.engine(&sources)?;
    let kusto = match (&loaded.sentinel, &args.kusto) {
        (Some(rules), Some(url)) => Some(crate::engines::kusto(
            url,
            rules,
            &args.sentinel_table,
            &events,
        )?),
        _ => None,
    };
    let elasticsearch = match (&loaded.elastic, &args.elasticsearch) {
        (Some(rules), Some(url)) => Some(crate::engines::elasticsearch(url, rules)?),
        _ => None,
    };
    let mut engines: Vec<&dyn RuleEngine> = vec![&sigma];
    engines.extend(kusto.as_ref().map(|k| k as &dyn RuleEngine));
    engines.extend(elasticsearch.as_ref().map(|e| e as &dyn RuleEngine));
    let (proof, unreduced) = crate::prove::proof_of(&yaml, &sources, &events, &Engines(engines))
        .with_context(|| format!("proving {}", config_path.display()))?;

    let rules = fingerprints(loaded.requirements());
    let verification = sluice_autopilot::verify(VerifyInput {
        plan: &plan,
        rules: &rules,
        basis: rules_basis(&args.sets, args.rules_complete),
        proof: &proof,
        unreduced: &unreduced,
    });
    if args.json {
        let mut value = serde_json::to_value(&verification)?;
        value["plan"] = json!(plan_path.display().to_string());
        value["written_by"] = json!(plan.sluice);
        out!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        print(&plan_path, &plan, &verification, &args.input);
    }
    if verification.verdict != Verdict::DoesNotHold
        && verification.proof.note.is_some()
        && !args.allow_no_alerts
    {
        bail!(
            "{} Add a sample with the attacks your rules detect, or pass --allow-no-alerts.",
            sluice_autopilot::EMPTY_PROOF
        );
    }
    Ok(verification.verdict)
}

fn read_plan(path: &Path) -> Result<RecordedPlan> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading {} (--analysis is the directory `sluice analyze` wrote)",
            path.display()
        )
    })?;
    RecordedPlan::parse(&text).with_context(|| format!("reading {}", path.display()))
}

fn print(plan_path: &Path, plan: &RecordedPlan, verification: &Verification, input: &Path) {
    let Verification {
        verdict,
        reasons,
        proof,
        rules,
        savings,
        templates,
    } = verification;
    let by = plan
        .sluice
        .as_deref()
        .map_or_else(String::new, |v| format!(" (Sluice {v})"));
    out!("{}{by} on {}", plan_path.display(), input.display());
    out!(
        "  proof   {} alerts on full data, {} on forwarded data",
        proof.alerts_full,
        proof.alerts_forwarded
    );
    for alert in &proof.missing {
        out!("  missing {alert}");
    }
    for alert in &proof.extra {
        out!("  extra   {alert}");
    }
    if let Some(note) = proof.note {
        out!("  note    {note}");
    }
    if rules.recorded {
        out!(
            "  rules   {} new, {} read differently, {} gone since the plan",
            rules.added.len(),
            rules.changed.len(),
            rules.removed.len()
        );
        for rule in rules.added.iter().take(10) {
            out!("  new     {rule}");
        }
        for rule in rules.changed.iter().take(10) {
            out!("  changed {rule}");
        }
    }
    out!(
        "  ingest  {} → {} bytes ({:.1}% saved; {:.1}% on the plan's sample)",
        savings.total.bytes_in,
        savings.total.bytes_out,
        savings.saved_percent_now,
        savings.saved_percent_plan
    );
    out!(
        "  unknown {:.1}% of the bytes are of no kind of event the plan knows, and sent whole \
         ({:.1}% on the plan's sample)",
        savings.unknown_percent_now,
        savings.unknown_percent_plan
    );
    if !savings.unreduced_sources.is_empty() {
        out!(
            "  unplanned sources, sent whole: {}",
            savings.unreduced_sources.join(", ")
        );
    }
    for drift in templates.iter().take(10) {
        out!(
            "  less    {} {}: {:.1}% → {:.1}% saved ({} events)",
            drift.source,
            drift.template,
            drift.saved_percent_plan,
            drift.saved_percent_now,
            drift.events_now
        );
    }
    match verdict {
        Verdict::Holds => out!("  ✓ the plan holds"),
        Verdict::OutOfDate => out!("  ✗ the plan is out of date"),
        Verdict::DoesNotHold => out!("  ✗ the plan does not hold: a detection would change"),
    }
    for reason in reasons {
        out!("    - {reason}");
    }
}
