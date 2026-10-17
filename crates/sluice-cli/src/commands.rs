//! The subcommands.

use std::path::Path;

use anyhow::{Context, Result, bail};
use sluice_autopilot::{
    Elastic, Helpers, Input, RecipeBook, Report, RulesBasis, SavingsPlan, Sentinel, Settings,
    analyze as run_autopilot, render_html,
};
use sluice_core::advice::Advisor;
use sluice_core::alert::{EventRules, RuleEngine};
use sluice_rules::SigmaRules;
use sluice_synth::{SynthConfig, generate};
use sluice_vector::{Paths, vector_config};
use sluice_wazuh::{Http as WazuhHttp, Logtest, LogtestConfig};

use crate::cli::{AnalyzeArgs, DemoArgs, RecipesArgs, RecipesCommand, RulesArgs, RulesCommand};
use crate::{ai, input, output};

/// The example rules the demo runs with, built into the binary.
const EXAMPLE_SIGMA: [&str; 3] = [
    include_str!("../../../examples/rules/sigma/windows.yml"),
    include_str!("../../../examples/rules/sigma/linux.yml"),
    include_str!("../../../examples/rules/sigma/network.yml"),
];

pub(crate) fn demo(args: &DemoArgs) -> Result<()> {
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
            splunk: None,
        },
        &RecipeBook::embedded()?,
        Helpers {
            advisor: advisor.as_ref().map(|a| a as &dyn Advisor),
            event_rules: None,
        },
        &args.out,
        // The demo's rules are its own: complete by construction.
        RulesBasis::SelfContained,
        Vec::new(),
        Native {
            elastic: args
                .elasticsearch
                .as_deref()
                .filter(|_| args.elastic_native),
            fluent_bit: args
                .fluent_bit
                .as_deref()
                .filter(|_| args.fluent_bit_native),
            otel: args.otel_collector.as_deref().filter(|_| args.otel_native),
            ..Native::default()
        },
    )?;
    println!(
        "Re-run on the same data: sluice analyze --input {} --sources {} --rules <dir>",
        samples.display(),
        args.out.join("sluice.yaml").display()
    );
    Ok(())
}

pub(crate) fn analyze(args: &AnalyzeArgs) -> Result<()> {
    let sources = input::sources(&args.sources)?;
    let events = input::events(&args.input, &sources)?;
    let sigma_files = match &args.rules {
        Some(dir) => input::files(dir, &["yml", "yaml"])?,
        None => Vec::new(),
    };
    let sigma = SigmaRules::parse_with(
        sigma_files.iter().map(|(_, text)| text.as_str()),
        &input::sigma_pipelines(&args.sigma_pipeline)?,
    )?;
    input::hint_undeclared_schemas(&sources, &sigma);
    let wazuh = input::wazuh(args.wazuh_rules.as_deref(), args.wazuh_decoders.as_deref())?;
    let book = recipe_book(args.recipes.as_deref())?;
    let advisor = ai::advisor(&args.ai)?;
    let logtest = logtest(args)?;
    let sentinel_rules = input::sentinel(args.sentinel_rules.as_deref())?;
    let elastic_rules = input::elastic(args.elastic_rules.as_deref())?;
    let splunk_rules = input::splunk(args.splunk_rules.as_deref())?;
    let kusto = match (&sentinel_rules, &args.kusto) {
        (Some(rules), Some(url)) => Some(input::kusto(url, rules, &args.sentinel_table, &events)?),
        _ => None,
    };
    let elasticsearch = match (&elastic_rules, &args.elasticsearch) {
        (Some(rules), Some(url)) => Some(input::elasticsearch(url, rules)?),
        _ => None,
    };
    let basis = if args.rules_complete {
        RulesBasis::Claimed
    } else if fetched_only(args) {
        RulesBasis::Fetched
    } else {
        RulesBasis::NotKnown
    };
    let inventory_notes: Vec<String> =
        [args.wazuh_rules.as_deref(), args.sentinel_rules.as_deref()]
            .into_iter()
            .flatten()
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
            splunk: splunk_rules.as_ref(),
        },
        &book,
        Helpers {
            advisor: advisor.as_ref().map(|a| a as &dyn Advisor),
            event_rules: logtest.as_ref().map(|l| l as &dyn EventRules),
        },
        &args.out,
        basis,
        inventory_notes,
        Native {
            sentinel: args
                .kusto
                .as_deref()
                .filter(|_| args.sentinel_native)
                .map(|url| SentinelNative {
                    url,
                    specs: &args.sentinel_table,
                    dcr: args.sentinel_dcr.as_deref(),
                }),
            elastic: args
                .elasticsearch
                .as_deref()
                .filter(|_| args.elastic_native),
            fluent_bit: args
                .fluent_bit
                .as_deref()
                .filter(|_| args.fluent_bit_native),
            otel: args.otel_collector.as_deref().filter(|_| args.otel_native),
        },
    )
}

/// Whether rules were given and every set came from a complete `sluice rules fetch`. Sigma has
/// no SIEM API, so Sigma rules always need `--rules-complete`.
fn fetched_only(args: &AnalyzeArgs) -> bool {
    let given = [
        args.wazuh_rules.as_deref(),
        args.sentinel_rules.as_deref(),
        args.elastic_rules.as_deref(),
        args.splunk_rules.as_deref(),
    ];
    args.rules.is_none()
        && given.iter().any(Option::is_some)
        && given
            .iter()
            .flatten()
            .all(|dir| crate::inventory::is_complete(dir))
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

pub(crate) fn recipes(args: &RecipesArgs) -> Result<()> {
    match &args.command {
        None => {
            for (id, description) in RecipeBook::embedded()?.entries() {
                println!("{id:<60} {description}");
            }
        }
        Some(RecipesCommand::Schema) => print!("{}", RecipeBook::json_schema()),
        Some(RecipesCommand::Contribute { from, into }) => contribute(from, into)?,
        Some(RecipesCommand::Export { out }) => {
            if out.read_dir().is_ok_and(|mut d| d.next().is_some()) {
                bail!(
                    "{} is not empty; export into a new directory",
                    out.display()
                );
            }
            let files = RecipeBook::embedded_files();
            for (path, yaml) in files {
                output::write(&out.join(path), yaml)?;
            }
            output::write(&out.join(SCHEMA_FILE), &RecipeBook::json_schema())?;
            println!(
                "exported {} recipes and {SCHEMA_FILE} to {}; edit them and pass `--recipes {}`",
                files.len(),
                out.display(),
                out.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn rules(args: &RulesArgs) -> Result<()> {
    let (rules, wazuh_rules, wazuh_decoders, sentinel_rules, elastic_rules, splunk_rules) =
        match &args.command {
            RulesCommand::Fetch(fetch) => return crate::inventory::fetch(fetch),
            RulesCommand::Requirements {
                rules,
                wazuh_rules,
                wazuh_decoders,
                sentinel_rules,
                elastic_rules,
                splunk_rules,
            } => (
                rules,
                wazuh_rules,
                wazuh_decoders,
                sentinel_rules,
                elastic_rules,
                splunk_rules,
            ),
        };
    let mut requirements = Vec::new();
    let mut problems = Vec::new();
    if let Some(dir) = rules {
        let files = input::files(dir, &["yml", "yaml"])?;
        let sigma = SigmaRules::parse(files.iter().map(|(_, text)| text.as_str()))?;
        requirements.extend(sigma.requirements().iter().cloned());
        problems.extend(sigma.problems().iter().cloned());
    }
    if let Some(wazuh) = input::wazuh(wazuh_rules.as_deref(), wazuh_decoders.as_deref())? {
        requirements.extend(wazuh.requirements().iter().cloned());
        problems.extend(wazuh.problems().iter().cloned());
    }
    if let Some(sentinel) = input::sentinel(sentinel_rules.as_deref())? {
        requirements.extend(sentinel.requirements().iter().cloned());
    }
    if let Some(elastic) = input::elastic(elastic_rules.as_deref())? {
        requirements.extend(elastic.requirements().iter().cloned());
    }
    if let Some(splunk) = input::splunk(splunk_rules.as_deref())? {
        requirements.extend(splunk.requirements().iter().cloned());
    }
    for problem in &problems {
        eprintln!("warning: {problem}");
    }
    println!("{}", serde_json::to_string_pretty(&requirements)?);
    Ok(())
}

/// Copies the recipes in `from` into `into`, after checking that the recipe book takes them
/// next to the built-in ones (no duplicate id, valid reductions). An existing file is never
/// replaced.
fn contribute(from: &Path, into: &Path) -> Result<()> {
    let files = input::files(from, &["yml", "yaml"])?;
    if files.is_empty() {
        bail!("{} holds no recipes", from.display());
    }
    RecipeBook::embedded_with(
        files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str())),
    )
    .context("the recipes do not fit the recipe book")?;
    for (path, text) in &files {
        let relative = Path::new(path)
            .strip_prefix(from)
            .unwrap_or(Path::new(path));
        let target = into.join(relative);
        if target.exists() {
            bail!("{} exists; nothing was copied after it", target.display());
        }
        output::write(&target, text)?;
        println!("  wrote {}", target.display());
    }
    println!(
        "Review each recipe (its pattern and rationale come from your logs), then commit them \
         and open a pull request."
    );
    Ok(())
}

/// Where the recipe JSON Schema lives, in the repository and in an export.
const SCHEMA_FILE: &str = "recipe.schema.json";

fn recipe_book(extra: Option<&Path>) -> Result<RecipeBook> {
    let Some(dir) = extra else {
        return Ok(RecipeBook::embedded()?);
    };
    let files = input::files(dir, &["yml", "yaml"])?;
    Ok(RecipeBook::embedded_with(
        files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str())),
    )?)
}

/// The SIEMs' own ingestion to generate and prove code for.
#[derive(Default)]
struct Native<'a> {
    sentinel: Option<SentinelNative<'a>>,
    /// `--elastic-native`: the Elasticsearch (`--elasticsearch`) to prove ingest pipelines in.
    elastic: Option<&'a str>,
    /// `--fluent-bit-native`: the command that runs Fluent Bit (`--fluent-bit`), to prove Lua
    /// filters in.
    fluent_bit: Option<&'a Path>,
    /// `--otel-native`: the command that runs the collector (`--otel-collector`), to prove
    /// transform statements in.
    otel: Option<&'a Path>,
}

/// What `--sentinel-native` asks for.
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
    rules: RulesBasis,
    inventory_notes: Vec<String>,
    native: Native<'_>,
) -> Result<()> {
    let Input {
        sources, events, ..
    } = input;
    let settings = Settings {
        rules,
        ..Settings::default()
    };
    let analysis =
        run_autopilot(input, book, &settings, helpers).context("running the autopilot")?;
    let mut report = Report::new(&analysis, input);
    report.inventory_notes = inventory_notes;

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
        "  wrote   {} (the savings plan), {} and {}",
        out.join("plan.json").display(),
        out.join("vector.yaml").display(),
        out.join("report.html").display()
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
