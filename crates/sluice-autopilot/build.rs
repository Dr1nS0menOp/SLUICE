//! Embeds the community recipes (`recipes/` at the repository root) into the crate, so the
//! `sluice` binary carries them without any files next to it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../recipes");
    println!("cargo::rerun-if-changed={}", root.display());

    let mut files = Vec::new();
    collect(&root, &mut files);
    files.sort();

    let mut out = String::from("/// Community recipes embedded at build time: (path, YAML).\n");
    out.push_str("pub(crate) const EMBEDDED: &[(&str, &str)] = &[\n");
    for file in &files {
        let relative = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .display()
            .to_string();
        let absolute = file.canonicalize().unwrap_or_else(|_| file.clone());
        writeln!(
            out,
            "    ({relative:?}, include_str!({:?})),",
            absolute.display().to_string()
        )
        .expect("writing to a String cannot fail");
    }
    out.push_str("];\n");

    let dest = Path::new(&env::var("OUT_DIR").unwrap_or_default()).join("embedded_recipes.rs");
    fs::write(dest, out).unwrap_or_else(|e| panic!("cannot write embedded recipes: {e}"));
}

fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        println!("cargo::rerun-if-changed={}", path.display());
        if path.is_dir() {
            collect(&path, files);
        } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            files.push(path);
        }
    }
}
