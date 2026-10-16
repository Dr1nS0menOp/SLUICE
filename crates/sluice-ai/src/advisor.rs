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

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeSet;

    use serde_json::json;
    use sluice_core::field::FieldPath;
    use sluice_core::template::{TemplateShape, TemplateStats};

    use super::*;
    use crate::error::AiError;

    /// A model that counts its calls and gives one answer.
    struct Fake {
        answer: Result<Value, AiError>,
        calls: std::rc::Rc<Cell<usize>>,
    }

    impl LanguageModel for Fake {
        fn name(&self) -> String {
            "local:m/1".into()
        }

        fn complete(&self, _: &str, user: &str, _: &Value) -> Result<Value, AiError> {
            assert!(user.contains("<untrusted_samples>"));
            self.calls.set(self.calls.get() + 1);
            self.answer.clone()
        }
    }

    fn asking(
        answer: Result<Value, AiError>,
        cache: Option<PathBuf>,
    ) -> (LlmAdvisor, std::rc::Rc<Cell<usize>>) {
        let calls = std::rc::Rc::new(Cell::new(0));
        let model = Fake {
            answer,
            calls: std::rc::Rc::clone(&calls),
        };
        (LlmAdvisor::new(Box::new(model), cache), calls)
    }

    fn template(id: &str) -> Template {
        Template {
            id: id.into(),
            source: "s".into(),
            logsource: sluice_core::logsource::LogSource::default(),
            schema: sluice_core::schema::Schema::default(),
            pattern: "p".into(),
            shape: TemplateShape::Keyset {
                discriminators: vec![],
                paths: BTreeSet::new(),
                variants: vec![BTreeSet::new()],
            },
            fields: ["message", "host.name"]
                .into_iter()
                .map(FieldPath::from)
                .collect(),
            text_fields: BTreeSet::new(),
            stats: TemplateStats::default(),
        }
    }

    fn drop_message() -> Value {
        json!({
            "security_value": "low", "boilerplate_fields": ["message"], "summarize": false,
            "summary_keys": [], "rationale": "rendered text"
        })
    }

    fn cache(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sluice-ai-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn each_template_is_asked_once_and_the_answer_is_cached_under_a_safe_name() {
        let dir = cache("once");
        let (advisor, calls) = asking(Ok(drop_message()), Some(dir.clone()));
        let t = template("../win/4624");
        assert!(advisor.propose(&t, &[]).unwrap().is_some());
        assert!(advisor.propose(&t, &[]).unwrap().is_some());
        assert_eq!(calls.get(), 1);
        let files: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(
            files,
            [format!(".._win_4624-local_m_1-v{}.json", prompt::VERSION)]
        );

        assert!(advisor.propose(&template("other"), &[]).unwrap().is_some());
        assert_eq!(calls.get(), 2, "another template is asked");
    }

    #[test]
    fn an_unreadable_cache_entry_is_asked_again_and_no_cache_asks_every_time() {
        let dir = cache("corrupt");
        let (advisor, calls) = asking(Ok(drop_message()), Some(dir.clone()));
        let t = template("t");
        advisor.propose(&t, &[]).unwrap();
        let file = fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
        fs::write(&file, "{ not json").unwrap();
        advisor.propose(&t, &[]).unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(
            serde_json::from_str::<Value>(&fs::read_to_string(&file).unwrap()).unwrap(),
            drop_message(),
            "rewritten"
        );

        let (uncached, calls) = asking(Ok(drop_message()), None);
        uncached.propose(&t, &[]).unwrap();
        uncached.propose(&t, &[]).unwrap();
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn model_errors_and_answers_outside_the_schema_propose_nothing() {
        let (failing, _) = asking(Err(AiError::Truncated), None);
        assert!(failing.propose(&template("t"), &[]).is_err());
        let mut extra = drop_message();
        extra["apply_now"] = json!(true);
        let (invalid, _) = asking(Ok(extra), None);
        let error = invalid.propose(&template("t"), &[]).unwrap_err();
        assert!(error.0.contains("invalid answer"), "{error:?}");
    }
}
