use std::cell::RefCell;

use serde_json::json;

use super::*;

/// A manager with two rule files in two directories and one decoder file, answering in the
/// shapes of the Wazuh 4.12 spec. Records every URL.
struct Manager {
    rule_files: Vec<(String, String)>,
    urls: RefCell<Vec<String>>,
}

impl Manager {
    fn new() -> Self {
        Self {
            rule_files: vec![
                ("ruleset/rules".into(), "0095-sshd_rules.xml".into()),
                ("etc/rules".into(), "local_rules.xml".into()),
            ],
            urls: RefCell::new(Vec::new()),
        }
    }

    fn listing(files: &[(String, String)], url: &str) -> String {
        let param = |name: &str| -> usize {
            url.split(&format!("{name}="))
                .nth(1)
                .and_then(|o| o.split('&').next())
                .and_then(|o| o.parse().ok())
                .unwrap_or(0)
        };
        let page: Vec<_> = files
            .iter()
            .skip(param("offset"))
            .take(param("limit"))
            .map(|(dir, name)| json!({"filename": name, "relative_dirname": dir, "status": "enabled"}))
            .collect();
        json!({"data": {"affected_items": page, "total_affected_items": files.len()}, "error": 0})
            .to_string()
    }
}

impl Transport for Manager {
    fn send(
        &self,
        _method: &str,
        url: &str,
        _headers: &[(&str, String)],
        _body: Option<&str>,
    ) -> Result<(u16, String), WazuhError> {
        self.urls.borrow_mut().push(url.to_owned());
        let path = url.trim_start_matches("https://wazuh:55000");
        let body = if path.starts_with("/security/user/authenticate") {
            json!({"data": {"token": "jwt"}, "error": 0}).to_string()
        } else if path.starts_with("/rules/files?") {
            Self::listing(&self.rule_files, path)
        } else if path.starts_with("/decoders/files?") {
            Self::listing(
                &[("ruleset/decoders".into(), "0310-ssh_decoders.xml".into())],
                path,
            )
        } else if let Some(rest) = path.strip_prefix("/rules/files/") {
            format!("<group name=\"{rest}\"/>")
        } else if path.starts_with("/decoders/files/") {
            "<decoder name=\"sshd\"/>".to_owned()
        } else {
            return Ok((404, "{}".to_owned()));
        };
        Ok((200, body))
    }
}

fn run(manager: &Manager) -> Inventory {
    fetch(
        manager,
        "https://wazuh:55000/",
        "reader",
        "secret",
        "2026-10-14T00:00:00Z",
    )
    .unwrap()
}

#[test]
fn every_enabled_file_is_written_under_its_directory() {
    let inventory = run(&Manager::new());
    let paths: Vec<&str> = inventory.files.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        [
            "rules/ruleset/rules/0095-sshd_rules.xml",
            "rules/etc/rules/local_rules.xml",
            "decoders/ruleset/decoders/0310-ssh_decoders.xml",
        ]
    );
    assert!(inventory.manifest.complete);
    assert_eq!(inventory.manifest.system, "wazuh");
    assert_eq!(inventory.manifest.counts["rules"], 2);
    assert_eq!(inventory.manifest.counts["decoders"], 1);
}

#[test]
fn files_are_read_raw_with_their_directory_encoded() {
    let manager = Manager::new();
    run(&manager);
    assert!(manager.urls.borrow().iter().any(|u| u
        == "https://wazuh:55000/rules/files/local_rules.xml?raw=true&relative_dirname=etc%2Frules"));
}

#[test]
fn listings_are_paged_until_the_total() {
    let mut manager = Manager::new();
    manager.rule_files = (0..=PAGE)
        .map(|n| ("ruleset/rules".to_owned(), format!("{n:04}-rules.xml")))
        .collect();
    let inventory = run(&manager);
    assert_eq!(
        inventory.manifest.counts["rules"],
        usize::try_from(PAGE + 1).unwrap()
    );
    let listings = manager
        .urls
        .borrow()
        .iter()
        .filter(|u| u.contains("/rules/files?"))
        .count();
    assert_eq!(listings, 2);
}

#[test]
fn a_file_name_that_leaves_the_directory_is_skipped_and_the_inventory_incomplete() {
    let mut manager = Manager::new();
    manager
        .rule_files
        .push(("../../etc".into(), "passwd".into()));
    let inventory = run(&manager);
    assert!(!inventory.manifest.complete);
    assert!(inventory.files.iter().all(|(p, _)| !p.contains("..")));
    assert_eq!(inventory.manifest.not_modeled.len(), 1);
}

#[test]
fn an_error_from_the_api_fails_the_fetch() {
    struct Refusing;
    impl Transport for Refusing {
        fn send(
            &self,
            _: &str,
            _: &str,
            _: &[(&str, String)],
            _: Option<&str>,
        ) -> Result<(u16, String), WazuhError> {
            Ok((401, json!({"title": "Unauthorized"}).to_string()))
        }
    }
    assert!(matches!(
        fetch(&Refusing, "https://wazuh:55000", "u", "p", "t"),
        Err(WazuhError::Http(_))
    ));
}

#[test]
fn values_are_percent_encoded() {
    assert_eq!(encode("etc/rules"), "etc%2Frules");
    assert_eq!(encode("a b&c=d"), "a%20b%26c%3Dd");
    assert_eq!(encode("0010-rules_config.xml"), "0010-rules_config.xml");
}
