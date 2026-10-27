//! The subcommands.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use sluice_autopilot::{
    Elastic, Helpers, Input, Mode, RecipeBook, Report, RulesBasis, SavingsPlan, Sentinel, Settings,
    analyze as run_autopilot, render_html,
};
use sluice_core::advice::Advisor;
use sluice_core::alert::{EventRules, RuleEngine};
use sluice_rules::SigmaRules;
use sluice_synth::{SynthConfig, generate};
use sluice_vector::{Paths, vector_config};
use sluice_wazuh::{Http as WazuhHttp, Logtest, LogtestConfig};

use crate::cli::{AnalyzeArgs, DemoArgs, ModeArg, NativeTarget, RuleSets, RulesArgs, RulesCommand};
use crate::{ai, input, output};

/// The example rules the demo runs with, built into the binary.
const EXAMPLE_SIGMA: [&str; 3] = [
    include_str!("../../../examples/rules/sigma/windows.yml"),
    include_str!("../../../examples/rules/sigma/linux.yml"),
    include_str!("../../../examples/rules/sigma/network.yml"),
];

pub(crate) fn demo(args: &DemoArgs) -> Result<()> {
    let native = demo_native(args)?;
    let sample = generate(&SynthConfig {
        seed: args.seed,
        scale_percent: args.scale,
        ..SynthConfig::default()
    });
    let samples = args.out.join("samples");
    output::samples(&samples, &sample.sources, &sample.events)?;
    output::sources(&args.out.join("sluice.yaml"), &sample.sources)?;
    let sigma = SigmaRules::parse(EXAMPLE_SIGMA)?;
    println!(
        "Sluice demo: synthetic sample (seed {}, scale {}%)",
        args.seed, args.scale
    );
    let advisor = ai::advisor(&args.ai)?;
    run(
        Input {
            sources: &sample.sources,
            events: &sample.events,
            sigma: &sigma,
            wazuh: None,
            sentinel: None,
            elastic: None,
        },
        &RecipeBook::embedded()?,
        Helpers {
            advisor: advisor.as_ref().map(|a| a as &dyn Advisor),
            event_rules: None,
        },
        &args.out,
        // The demo's rules are its own: complete by construction.
        &Settings {
            rules: RulesBasis::SelfContained,
            modes: modes(&args.mode),
            ..Settings::default()
        },
        ReportExtras::default(),
        native,
    )?;
    println!(
        "Re-run on the same data: sluice analyze --input {} --sources {} --rules <dir>",
        samples.display(),
        args.out.join("sluice.yaml").display()
    );
    Ok(())
}

pub(crate) fn analyze(args: &AnalyzeArgs) -> Result<()> {
    let native = analyze_native(args)?;
    let sources = input::sources(&args.sources)?;
    let events = input::events(&args.input, &sources)?;
    let input::Loaded {
        sigma,
        wazuh,
        sentinel: sentinel_rules,
        elastic: elastic_rules,
    } = input::rule_sets(&args.sets, &args.sentinel_table)?;
    input::hint_undeclared_schemas(&sources, &sigma);
    let book = crate::recipes::recipe_book(args.recipes.as_deref())?;
    let advisor = ai::advisor(&args.ai)?;
    let logtest = logtest(args)?;
    let kusto = match (&sentinel_rules, &args.kusto) {
        (Some(rules), Some(url)) => Some(crate::engines::kusto(
            url,
            rules,
            &args.sentinel_table,
            &events,
        )?),
        _ => None,
    };
    let elasticsearch = match (&elastic_rules, &args.elasticsearch) {
        (Some(rules), Some(url)) => Some(crate::engines::elasticsearch(url, rules)?),
        _ => None,
    };
    let basis = if args.rules_complete {
        RulesBasis::Claimed
    } else if fetched_only(&args.sets) {
        RulesBasis::Fetched
    } else {
        RulesBasis::NotKnown
    };
    let inventory_notes: Vec<String> = args
        .sets
        .siem_dirs()
        .filter_map(crate::inventory::find_manifest)
        .flat_map(|m| m.not_modeled)
        .collect();
    run(
        Input {
            sources: &sources,
            events: &events,
            sigma: &sigma,
            wazuh: wazuh.as_ref(),
            sentinel: sentinel_rules.as_ref().map(|rules| Sentinel {
                rules,
                engine: kusto.as_ref().map(|k| k as &dyn RuleEngine),
            }),
            elastic: elastic_rules.as_ref().map(|rules| Elastic {
                rules,
                engine: elasticsearch.as_ref().map(|e| e as &dyn RuleEngine),
            }),
        },
        &book,
        Helpers {
            advisor: advisor.as_ref().map(|a| a as &dyn Advisor),
            event_rules: logtest.as_ref().map(|l| l as &dyn EventRules),
        },
        &args.out,
        &Settings {
            rules: basis,
            modes: modes(&args.mode),
            ..Settings::default()
        },
        ReportExtras {
            inventory_notes,
            no_examples: args.no_examples,
        },
        native,
    )
}

/// What `sluice demo --native` asks for, with the engine each target is proven in.
fn demo_native(args: &DemoArgs) -> Result<Native<'_>> {
    if args.native.contains(&NativeTarget::Sentinel) {
        bail!(
            "the demo has no Sentinel sample: --native sentinel is for sluice analyze, with \
             --kusto and --sentinel-table"
        );
    }
    Ok(Native {
        sentinel: None,
        elastic: engine(
            &args.native,
            NativeTarget::Elastic,
            args.elasticsearch.as_deref(),
            "--elasticsearch URL",
        )?,
        fluent_bit: engine(
            &args.native,
            NativeTarget::FluentBit,
            args.fluent_bit.as_deref(),
            "--fluent-bit CMD",
        )?,
        otel: engine(
            &args.native,
            NativeTarget::Otel,
            args.otel_collector.as_deref(),
            "--otel-collector CMD",
        )?,
    })
}

/// What `sluice analyze --native` asks for, with the engine each target is proven in. Checked
/// before anything is read, so a missing engine costs no analysis.
fn analyze_native(args: &AnalyzeArgs) -> Result<Native<'_>> {
    let wants = |target| args.native.contains(&target);
    // `--elasticsearch` has a second use: running the Elastic rules in the proof.
    if args.elasticsearch.is_some()
        && args.sets.elastic_rules.is_none()
        && !wants(NativeTarget::Elastic)
    {
        bail!(
            "--elasticsearch runs --elastic-rules in the proof or proves --native elastic \
             pipelines: give one of them"
        );
    }
    if wants(NativeTarget::Elastic) && args.elasticsearch.is_none() {
        bail!("--native elastic needs --elasticsearch URL");
    }
    if args.sentinel_dcr.is_some() && !wants(NativeTarget::Sentinel) {
        bail!(
            "--sentinel-dcr is only used by --native sentinel: add it, or leave --sentinel-dcr out"
        );
    }
    let sentinel = match args.kusto.as_deref() {
        Some(url) if wants(NativeTarget::Sentinel) && !args.sentinel_table.is_empty() => {
            Some(SentinelNative {
                url,
                specs: &args.sentinel_table,
                dcr: args.sentinel_dcr.as_deref(),
            })
        }
        _ if wants(NativeTarget::Sentinel) => {
            bail!("--native sentinel needs --kusto URL and --sentinel-table SOURCE=TABLE")
        }
        _ => None,
    };
    Ok(Native {
        sentinel,
        elastic: args
            .elasticsearch
            .as_deref()
            .filter(|_| wants(NativeTarget::Elastic)),
        fluent_bit: engine(
            &args.native,
            NativeTarget::FluentBit,
            args.fluent_bit.as_deref(),
            "--fluent-bit CMD",
        )?,
        otel: engine(
            &args.native,
            NativeTarget::Otel,
            args.otel_collector.as_deref(),
            "--otel-collector CMD",
        )?,
    })
}

/// The engine `flag` gives `target` in: needed when `--native` names the target, and refused
/// when it does not, since nothing else would use it.
fn engine<'a, T: ?Sized>(
    native: &[NativeTarget],
    target: NativeTarget,
    given: Option<&'a T>,
    flag: &str,
) -> Result<Option<&'a T>> {
    match (native.contains(&target), given) {
        (true, Some(engine)) => Ok(Some(engine)),
        (true, None) => bail!("--native {} needs {flag}", target.name()),
        (false, Some(_)) => bail!(
            "{flag} is only used by --native {}: add it, or leave the flag out",
            target.name()
        ),
        (false, None) => Ok(None),
    }
}

/// Whether rules were given and every set came from a complete `sluice rules fetch`. Sigma has
/// no SIEM API, so Sigma rules always need `--rules-complete`.
fn fetched_only(sets: &RuleSets) -> bool {
    sets.rules.is_none()
        && sets.siem_dirs().next().is_some()
        && sets.siem_dirs().all(crate::inventory::is_complete)
}

/// The Wazuh `logtest` client `--wazuh-api` asks for.
fn logtest(args: &AnalyzeArgs) -> Result<Option<Logtest>> {
    let Some(url) = &args.wazuh_api else {
        return Ok(None);
    };
    let password = std::env::var("WAZUH_API_PASSWORD")
        .context("--wazuh-api needs the API password in WAZUH_API_PASSWORD")?;
    let config = LogtestConfig {
        url: url.clone(),
        user: args.wazuh_user.clone().unwrap_or_default(),
        password,
    };
    Ok(Some(Logtest::new(
        config,
        WazuhHttp::new(args.wazuh_insecure),
    )))
}

pub(crate) fn rules(args: &RulesArgs) -> Result<()> {
    let sets = match &args.command {
        RulesCommand::Fetch(fetch) => return crate::inventory::fetch(fetch),
        RulesCommand::Requirements(sets) => sets,
    };
    let loaded = input::rule_sets(sets, &[])?;
    // Sentinel's and Elastic's loaders print their own problems.
    let mut problems: Vec<&sluice_core::problem::Problem> =
        loaded.sigma.problems().iter().collect();
    if let Some(wazuh) = &loaded.wazuh {
        problems.extend(wazuh.problems());
    }
    for problem in problems {
        eprintln!("warning: {problem}");
    }
    println!("{}", serde_json::to_string_pretty(&loaded.requirements())?);
    Ok(())
}

/// The kinds of saving `--mode` asks for.
fn modes(args: &[ModeArg]) -> BTreeSet<Mode> {
    args.iter()
        .map(|mode| match mode {
            ModeArg::Rules => Mode::Rules,
            ModeArg::Implied => Mode::Implied,
        })
        .collect()
}

/// The SIEMs' own ingestion to generate and prove code for.
#[derive(Default)]
struct Native<'a> {
    sentinel: Option<SentinelNative<'a>>,
    /// `--native elastic`: the Elasticsearch (`--elasticsearch`) to prove ingest pipelines in.
    elastic: Option<&'a str>,
    /// `--native fluent-bit`: the command that runs Fluent Bit (`--fluent-bit`), to prove Lua
    /// filters in.
    fluent_bit: Option<&'a Path>,
    /// `--native otel`: the command that runs the collector (`--otel-collector`), to prove
    /// transform statements in.
    otel: Option<&'a Path>,
}

/// What the report gets besides the analysis.
#[derive(Default)]
struct ReportExtras {
    /// What the fetched inventories say about rules without a query to read.
    inventory_notes: Vec<String>,
    /// `--no-examples`: leave the example events out.
    no_examples: bool,
}

/// What `--native sentinel` asks for.
struct SentinelNative<'a> {
    url: &'a str,
    specs: &'a [String],
    dcr: Option<&'a Path>,
}

fn run(
    input: Input<'_>,
    book: &RecipeBook,
    helpers: Helpers<'_>,
    out: &Path,
    settings: &Settings,
    extras: ReportExtras,
    native: Native<'_>,
) -> Result<()> {
    let Input {
        sources, events, ..
    } = input;
    let analysis =
        run_autopilot(input, book, settings, helpers).context("running the autopilot")?;
    let mut report = Report::new(&analysis, input);
    report.inventory_notes = extras.inventory_notes;
    if extras.no_examples {
        report.examples.clear();
    }

    let paths = Paths {
        input_dir: out.join("samples").display().to_string(),
        output_dir: out.join("vector-out").display().to_string(),
    };
    let config = vector_config(
        sources,
        &analysis.plans(),
        &analysis.data_plane,
        events,
        &paths,
    )?;
    let plan = SavingsPlan::new(&analysis, &report, sources);
    output::write(&out.join("plan.json"), &plan.to_json()?)?;
    output::write(&out.join("vector.yaml"), &config)?;
    output::write(&out.join("report.html"), &render_html(&report))?;
    output::write(
        &out.join("rules.json"),
        &(serde_json::to_string_pretty(&report.rule_rows)? + "\n"),
    )?;

    let contributions = sluice_autopilot::ai_recipes(&analysis);
    for contribution in &contributions {
        output::write(
            &out.join("ai-recipes").join(&contribution.path),
            &contribution.yaml,
        )?;
    }

    output::summary(&report, analysis.discovery.templates.len(), sources.len());
    if !contributions.is_empty() {
        println!(
            "  wrote   {} recipe(s) the AI proposed and the proof kept in {}: share them with \
             `sluice recipes contribute`",
            contributions.len(),
            out.join("ai-recipes").display()
        );
    }
    println!(
        "  wrote   {} (the advice), {} (the savings plan), {} and {} (every rule)",
        out.join("report.html").display(),
        out.join("plan.json").display(),
        out.join("vector.yaml").display(),
        out.join("rules.json").display()
    );
    if let Some(sentinel) = native.sentinel {
        crate::native::sentinel::sentinel(
            &analysis,
            input,
            sentinel.url,
            sentinel.specs,
            sentinel.dcr,
            out,
        )?;
    }
    if let Some(url) = native.elastic {
        crate::native::elastic::elastic(&analysis, input, url, out)?;
    }
    if let Some(command) = native.fluent_bit {
        crate::native::fluentbit::fluent_bit(&analysis, input, command, out)?;
    }
    if let Some(command) = native.otel {
        crate::native::otel::otel(&analysis, input, command, out)?;
    }
    Ok(())
}
