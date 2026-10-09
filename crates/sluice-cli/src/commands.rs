//! The subcommands.

use std::path::Path;

use anyhow::{Context, Result, bail};
use sluice_autopilot::{
    Helpers, Input, RecipeBook, Report, Settings, analyze as run_autopilot, render_html,
};
use sluice_core::advice::Advisor;
use sluice_core::alert::EventRules;
use sluice_core::event::Event;
use sluice_core::source::Source;
use sluice_rules::{SigmaRules, WazuhRules};
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
        &sample.sources,
        &sample.events,
        &sigma,
        None,
        &RecipeBook::embedded()?,
        Helpers {
            advisor: advisor.as_ref().map(|a| a as &dyn Advisor),
            event_rules: None,
        },
        &args.out,
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
    let sigma = SigmaRules::parse(sigma_files.iter().map(|(_, text)| text.as_str()))?;
    let wazuh = match &args.wazuh_rules {
        Some(dir) => {
            let files = input::files(dir, &["xml"])?;
            Some(WazuhRules::parse(
                files.iter().map(|(_, text)| text.as_str()),
            )?)
        }
        None => None,
    };
    let book = recipe_book(args.recipes.as_deref())?;
    let advisor = ai::advisor(&args.ai)?;
    let logtest = logtest(args)?;
    run(
        &sources,
        &events,
        &sigma,
        wazuh.as_ref(),
        &book,
        Helpers {
            advisor: advisor.as_ref().map(|a| a as &dyn Advisor),
            event_rules: logtest.as_ref().map(|l| l as &dyn EventRules),
        },
        &args.out,
    )
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
    let RulesCommand::Requirements { rules, wazuh_rules } = &args.command;
    let mut requirements = Vec::new();
    let mut problems = Vec::new();
    if let Some(dir) = rules {
        let files = input::files(dir, &["yml", "yaml"])?;
        let sigma = SigmaRules::parse(files.iter().map(|(_, text)| text.as_str()))?;
        requirements.extend(sigma.requirements().iter().cloned());
        problems.extend(sigma.problems().iter().cloned());
    }
    if let Some(dir) = wazuh_rules {
        let files = input::files(dir, &["xml"])?;
        let wazuh = WazuhRules::parse(files.iter().map(|(_, text)| text.as_str()))?;
        requirements.extend(wazuh.requirements().iter().cloned());
    }
    for problem in &problems {
        eprintln!("warning: {problem}");
    }
    println!("{}", serde_json::to_string_pretty(&requirements)?);
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

fn run(
    sources: &[Source],
    events: &[Event],
    sigma: &SigmaRules,
    wazuh: Option<&WazuhRules>,
    book: &RecipeBook,
    helpers: Helpers<'_>,
    out: &Path,
) -> Result<()> {
    let input = Input {
        sources,
        events,
        sigma,
        wazuh,
    };
    let analysis = run_autopilot(input, book, &Settings::default(), helpers)
        .context("running the autopilot")?;
    let report = Report::new(&analysis, sigma, wazuh);

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
    output::write(&out.join("vector.yaml"), &config)?;
    output::write(&out.join("report.html"), &render_html(&report))?;

    output::summary(&report, analysis.discovery.templates.len(), sources.len());
    println!(
        "  wrote   {} and {}",
        out.join("vector.yaml").display(),
        out.join("report.html").display()
    );
    Ok(())
}
