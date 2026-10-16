//! Turning `--llm` into an advisor.

use std::path::PathBuf;

use anyhow::{Result, bail};
use sluice_ai::{Anthropic, LanguageModel, LlmAdvisor, OpenAiCompatible};

use crate::cli::AiArgs;

/// The Claude model used when `--llm anthropic` names none.
const DEFAULT_CLAUDE: &str = "claude-opus-5-5";

/// The advisor `--llm` asks for, or `None` for `--llm none`.
pub(crate) fn advisor(args: &AiArgs) -> Result<Option<LlmAdvisor>> {
    let model: Box<dyn LanguageModel> = match args.llm.split_once(':') {
        None if args.llm == "none" => return Ok(None),
        None if args.llm == "anthropic" => Box::new(Anthropic::from_env(DEFAULT_CLAUDE)?),
        Some(("anthropic", model)) => Box::new(Anthropic::from_env(model)?),
        Some(("ollama", model)) => Box::new(OpenAiCompatible::ollama(model)),
        Some(("lmstudio", model)) => Box::new(OpenAiCompatible::lm_studio(model)),
        Some(("openai", rest)) => {
            let Some((base_url, model)) = rest.rsplit_once('#') else {
                bail!(
                    "--llm openai needs BASE_URL#MODEL, for example openai:http://localhost:8000/v1#qwen3"
                );
            };
            let key = std::env::var("OPENAI_API_KEY")
                .ok()
                .filter(|k| !k.is_empty());
            Box::new(OpenAiCompatible::new(
                model,
                base_url,
                key,
                sluice_ai::Http::default(),
            ))
        }
        _ => bail!(
            "unknown --llm {:?}; use none, anthropic[:MODEL], ollama:MODEL, lmstudio:MODEL or openai:BASE_URL#MODEL",
            args.llm
        ),
    };
    let cache = args.llm_cache.clone().or_else(default_cache);
    Ok(Some(LlmAdvisor::new(model, cache)))
}

fn default_cache() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(base.join("sluice").join("ai"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(llm: &str) -> Result<bool> {
        advisor(&AiArgs {
            llm: llm.to_owned(),
            llm_cache: Some(PathBuf::from("/nonexistent/cache")),
        })
        .map(|advisor| advisor.is_some())
    }

    #[test]
    fn local_and_compatible_models_need_no_key() {
        assert!(!parsed("none").unwrap());
        for llm in [
            "ollama:qwen3",
            "lmstudio:qwen3",
            "openai:http://localhost:8000/v1#qwen3",
            "openai:http://host/v1#a#b",
        ] {
            assert!(parsed(llm).unwrap(), "{llm}");
        }
    }

    #[test]
    fn unknown_or_incomplete_models_are_refused_with_the_choices() {
        let error = parsed("openai:http://localhost:8000/v1").unwrap_err();
        assert!(error.to_string().contains("BASE_URL#MODEL"), "{error}");
        for llm in ["gpt", "ollama", "claude:opus", ""] {
            let error = parsed(llm).unwrap_err().to_string();
            assert!(error.contains("use none, anthropic"), "{llm}: {error}");
        }
    }
}
