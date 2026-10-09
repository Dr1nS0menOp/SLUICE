//! A language model as an [`Advisor`], with a per-template answer cache.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use sluice_core::advice::{AdviceError, Advisor};
use sluice_core::event::Event;
use sluice_core::recipe::Recipe;
use sluice_core::template::Template;

use crate::model::LanguageModel;
use crate::prompt;
use crate::proposal::{self, Answer};

/// Asks a model about each template once, and remembers the answer.
///
/// Answers are cached as JSON per template, model and prompt version, so re-running an analysis
/// costs nothing and gives the same result. The cache stores the model's answer, not the recipe:
/// the recipe is rebuilt from it against the current template every time.
pub struct LlmAdvisor {
    model: Box<dyn LanguageModel>,
    cache: Option<PathBuf>,
}

impl LlmAdvisor {
    /// An advisor using `model`, caching answers in `cache` if given.
    #[must_use]
    pub fn new(model: Box<dyn LanguageModel>, cache: Option<PathBuf>) -> Self {
        Self { model, cache }
    }

    fn cache_file(&self, template: &Template) -> Option<PathBuf> {
        let name = format!(
            "{}-{}-v{}.json",
            template.id,
            self.model.name(),
            prompt::VERSION
        );
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.cache.as_ref().map(|dir| dir.join(safe))
    }

    fn answer(&self, template: &Template, samples: &[&Event]) -> Result<Value, AdviceError> {
        let file = self.cache_file(template);
        if let Some(cached) = file.as_ref().and_then(|f| fs::read_to_string(f).ok())
            && let Ok(value) = serde_json::from_str(&cached)
        {
            return Ok(value);
        }
        let fields: Vec<_> = samples.iter().map(|e| &e.fields).collect();
        let answer = self
            .model
            .complete(
                prompt::SYSTEM,
                &prompt::user(template, &fields),
                &proposal::schema(),
            )
            .map_err(|e| AdviceError(e.to_string()))?;
        if let Some(file) = file {
            // A cache that cannot be written only costs a repeated call later.
            let _ = fs::create_dir_all(file.parent().unwrap_or(&file))
                .and_then(|()| fs::write(&file, answer.to_string()));
        }
        Ok(answer)
    }
}

impl Advisor for LlmAdvisor {
    fn propose(
        &self,
        template: &Template,
        samples: &[&Event],
    ) -> Result<Option<Recipe>, AdviceError> {
        let value = self.answer(template, samples)?;
        let answer: Answer = serde_json::from_value(value)
            .map_err(|e| AdviceError(format!("invalid answer: {e}")))?;
        Ok(proposal::to_recipe(&answer, template, &self.model.name()))
    }
}
