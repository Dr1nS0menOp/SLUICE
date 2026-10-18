//! `sluice recipes`: the community recipes, their schema, and contributing new ones.

use std::path::Path;

use anyhow::{Context, Result, bail};
use sluice_autopilot::RecipeBook;

use crate::cli::{RecipesArgs, RecipesCommand};
use crate::{input, output};

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

/// The built-in recipes, with those in `extra` next to them (an edited one replaces the
/// built-in recipe with its id).
pub(crate) fn recipe_book(extra: Option<&Path>) -> Result<RecipeBook> {
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
