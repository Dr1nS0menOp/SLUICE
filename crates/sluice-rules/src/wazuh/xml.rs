//! A minimal reader for Wazuh rule files.
//!
//! Wazuh rule files are XML fragments: several top-level `<group>` elements and no root. We only
//! need each `<rule>`'s attributes and its direct children (tag, attributes, text), so the result
//! is that flat shape rather than a general DOM.
//!
//! They are also not strict XML. Wazuh's own reader takes element text literally, so the stock
//! rules contain regexes such as `</\/\w+\>` and bare `&&`. [`lenient`] escapes every `<` that
//! does not start markup and every `&` that does not start an entity before parsing.

use std::collections::BTreeMap;

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::error::RulesError;

/// One `<rule>` or `<decoder>` element.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RawElement {
    pub(crate) attributes: BTreeMap<String, String>,
    pub(crate) children: Vec<RawChild>,
}

/// A direct child of the element, such as `<field name="x">value</field>`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RawChild {
    pub(crate) tag: String,
    pub(crate) attributes: BTreeMap<String, String>,
    pub(crate) text: String,
}

/// Parses every `<rule>` in a rule file.
pub(crate) fn rules(xml: &str) -> Result<Vec<RawElement>, RulesError> {
    elements(xml, "rule")
}

/// Parses every `<decoder>` in a decoder file.
pub(crate) fn decoders(xml: &str) -> Result<Vec<RawElement>, RulesError> {
    elements(xml, "decoder")
}

/// Parses every `element` and its direct children.
fn elements(xml: &str, element: &str) -> Result<Vec<RawElement>, RulesError> {
    let xml = lenient(xml);
    let mut reader = Reader::from_str(&xml);
    reader.config_mut().trim_text(true);
    let mut rules = Vec::new();
    let mut rule: Option<RawElement> = None;
    let mut child: Option<RawChild> = None;
    loop {
        let event = reader.read_event().map_err(|e| {
            RulesError::WazuhXml(format!("at byte {}: {e}", reader.buffer_position()))
        })?;
        match event {
            Event::Start(start) if rule.is_none() && start.name().as_ref() == element => {
                rule = Some(RawElement {
                    attributes: attributes(&start)?,
                    children: Vec::new(),
                });
            }
            Event::Empty(start) if rule.is_none() && start.name().as_ref() == element => {
                rules.push(RawElement {
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
                tag if tag == element => rules.extend(rule.take()),
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

/// Escapes `<` that does not open markup (`<name`, `</name`, `<!`, `<?`) and `&` that does not
/// open an entity (`&name;`, `&#…;`), the way Wazuh's reader treats them: as text.
fn lenient(xml: &str) -> std::borrow::Cow<'_, str> {
    let bytes = xml.as_bytes();
    let is_name_start = |b: u8| b.is_ascii_alphabetic() || b == b'_';
    let markup = |i: usize| match bytes.get(i + 1) {
        Some(b'!' | b'?') => true,
        Some(b'/') => bytes.get(i + 2).is_some_and(|b| is_name_start(*b)),
        Some(b) => is_name_start(*b),
        None => false,
    };
    let entity = |i: usize| {
        let rest = &bytes[i + 1..];
        // Entities are short: look no further than 32 bytes, so many bare `&` stay linear.
        let end = rest
            .iter()
            .take(33)
            .position(|b| *b == b';')
            .filter(|end| *end > 0);
        end.is_some_and(|end| {
            let body = &rest[..end];
            body.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'#')
        })
    };
    let needs = bytes
        .iter()
        .enumerate()
        .any(|(i, b)| (*b == b'<' && !markup(i)) || (*b == b'&' && !entity(i)));
    if !needs {
        return std::borrow::Cow::Borrowed(xml);
    }
    let mut out = String::with_capacity(xml.len() + 64);
    for (i, c) in xml.char_indices() {
        match c {
            '<' if !markup(i) => out.push_str("&lt;"),
            '&' if !entity(i) => out.push_str("&amp;"),
            other => out.push(other),
        }
    }
    std::borrow::Cow::Owned(out)
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
