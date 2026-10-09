//! A minimal reader for Wazuh rule files.
//!
//! Wazuh rule files are XML fragments: several top-level `<group>` elements and no root. We only
//! need each `<rule>`'s attributes and its direct children (tag, attributes, text), so the result
//! is that flat shape rather than a general DOM.

use std::collections::BTreeMap;

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::error::RulesError;

/// One `<rule>` element.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RawRule {
    pub(crate) attributes: BTreeMap<String, String>,
    pub(crate) children: Vec<RawChild>,
}

/// A direct child of a `<rule>`, such as `<field name="x">value</field>`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RawChild {
    pub(crate) tag: String,
    pub(crate) attributes: BTreeMap<String, String>,
    pub(crate) text: String,
}

/// Parses every `<rule>` in a rule file.
pub(crate) fn rules(xml: &str) -> Result<Vec<RawRule>, RulesError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut rules = Vec::new();
    let mut rule: Option<RawRule> = None;
    let mut child: Option<RawChild> = None;
    loop {
        let event = reader.read_event().map_err(|e| {
            RulesError::WazuhXml(format!("at byte {}: {e}", reader.buffer_position()))
        })?;
        match event {
            Event::Start(start) if rule.is_none() && start.name().as_ref() == "rule" => {
                rule = Some(RawRule {
                    attributes: attributes(&start)?,
                    children: Vec::new(),
                });
            }
            Event::Empty(start) if rule.is_none() && start.name().as_ref() == "rule" => {
                rules.push(RawRule {
                    attributes: attributes(&start)?,
                    children: Vec::new(),
                });
            }
            Event::Start(start) if rule.is_some() && child.is_none() => {
                child = Some(RawChild {
                    tag: name(&start),
                    attributes: attributes(&start)?,
                    text: String::new(),
                });
            }
            Event::Empty(start) if rule.is_some() && child.is_none() => {
                if let Some(rule) = rule.as_mut() {
                    rule.children.push(RawChild {
                        tag: name(&start),
                        attributes: attributes(&start)?,
                        text: String::new(),
                    });
                }
            }
            Event::Text(text) => {
                if let Some(child) = child.as_mut() {
                    child.text.push_str(&text.xml10_content());
                }
            }
            Event::CData(data) => {
                if let Some(child) = child.as_mut() {
                    child.text.push_str(&data.xml10_content());
                }
            }
            Event::GeneralRef(reference) => {
                if let Some(child) = child.as_mut() {
                    push_reference(&mut child.text, &reference);
                }
            }
            Event::End(end) => match end.name().as_ref() {
                "rule" => rules.extend(rule.take()),
                tag if child.as_ref().is_some_and(|c| c.tag == tag) => {
                    if let (Some(rule), Some(child)) = (rule.as_mut(), child.take()) {
                        rule.children.push(child);
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(rules)
}

fn name(start: &BytesStart<'_>) -> String {
    start.name().as_ref().to_owned()
}

fn attributes(start: &BytesStart<'_>) -> Result<BTreeMap<String, String>, RulesError> {
    start
        .attributes()
        .map(|attribute| {
            let attribute = attribute.map_err(|e| RulesError::WazuhXml(e.to_string()))?;
            let key = attribute.key.as_ref().to_owned();
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|e| RulesError::WazuhXml(e.to_string()))?;
            Ok((key, value.into_owned()))
        })
        .collect()
}

fn push_reference(text: &mut String, reference: &BytesRef<'_>) {
    if let Ok(Some(c)) = reference.resolve_char_ref() {
        text.push(c);
        return;
    }
    match reference.xml10_content().as_ref() {
        "lt" => text.push('<'),
        "gt" => text.push('>'),
        "amp" => text.push('&'),
        "quot" => text.push('"'),
        "apos" => text.push('\''),
        other => {
            text.push('&');
            text.push_str(other);
            text.push(';');
        }
    }
}
