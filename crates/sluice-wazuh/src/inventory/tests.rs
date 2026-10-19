use std::cell::RefCell;
use std::collections::BTreeSet;

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
fn a_request_the_manager_refuses_for_its_rate_limit_is_sent_again_a_minute_later() {
    /// The manager, refusing each file request once with 429.
    struct Busy {
        manager: Manager,
        refused: RefCell<BTreeSet<String>>,
        pauses: RefCell<Vec<u64>>,
    }
    impl Transport for Busy {
        fn send(
            &self,
            method: &str,
            url: &str,
            headers: &[(&str, String)],
            body: Option<&str>,
        ) -> Result<(u16, String), WazuhError> {
            if url.contains("raw=true") && self.refused.borrow_mut().insert(url.to_owned()) {
                return Ok((429, json!({"title": "Too Many Requests"}).to_string()));
            }
            self.manager.send(method, url, headers, body)
        }
        fn pause(&self, seconds: u64) {
            self.pauses.borrow_mut().push(seconds);
        }
    }
    let busy = Busy {
        manager: Manager::new(),
        refused: RefCell::new(BTreeSet::new()),
        pauses: RefCell::new(Vec::new()),
    };
    let inventory = fetch(&busy, "https://wazuh:55000", "reader", "secret", "t").unwrap();
    assert_eq!(inventory.files.len(), 3, "every file arrives");
    assert_eq!(
        *busy.pauses.borrow(),
        [60, 60, 60],
        "a minute before each retry"
    );
}

#[test]
fn a_manager_that_keeps_refusing_for_its_rate_limit_fails_the_fetch() {
    /// A manager that never lets a file through.
    struct Saturated(RefCell<u32>);
    impl Transport for Saturated {
        fn send(
            &self,
            method: &str,
            url: &str,
            headers: &[(&str, String)],
            body: Option<&str>,
        ) -> Result<(u16, String), WazuhError> {
            if url.contains("raw=true") {
                *self.0.borrow_mut() += 1;
                return Ok((429, json!({"title": "Too Many Requests"}).to_string()));
            }
            Manager::new().send(method, url, headers, body)
        }
        fn pause(&self, _: u64) {}
    }
    let saturated = Saturated(RefCell::new(0));
    let error = fetch(&saturated, "https://wazuh:55000", "reader", "secret", "t").unwrap_err();
    assert!(error.to_string().contains("HTTP 429"), "{error}");
    assert_eq!(*saturated.0.borrow(), 4, "sent once, then three more times");
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
fn c3_a_listing_without_a_total_fails_instead_of_passing_as_complete() {
    struct NoTotal;
    impl Transport for NoTotal {
        fn send(
            &self,
            _: &str,
            url: &str,
            _: &[(&str, String)],
            _: Option<&str>,
        ) -> Result<(u16, String), WazuhError> {
            let body = if url.ends_with("/authenticate") {
                json!({"data": {"token": "jwt"}, "error": 0})
            } else {
                let page: Vec<_> = (0..PAGE)
                    .map(|n| json!({"filename": format!("{n}.xml"), "relative_dirname": "r"}))
                    .collect();
                json!({"data": {"affected_items": page}, "error": 0})
            };
            Ok((200, body.to_string()))
        }
    }
    assert!(matches!(
        fetch(&NoTotal, "https://wazuh:55000", "u", "p", "t"),
        Err(WazuhError::Invalid(m)) if m.contains("total")
    ));
}

#[test]
fn c3_a_listing_that_comes_up_short_fails() {
    struct Short;
    impl Transport for Short {
        fn send(
            &self,
            _: &str,
            url: &str,
            _: &[(&str, String)],
            _: Option<&str>,
        ) -> Result<(u16, String), WazuhError> {
            let body = if url.ends_with("/authenticate") {
                json!({"data": {"token": "jwt"}, "error": 0})
            } else if url.contains("offset=0") {
                json!({"data": {"affected_items": [{"filename": "a.xml", "relative_dirname": "r"}],
                    "total_affected_items": PAGE * 3}, "error": 0})
            } else {
                json!({"data": {"affected_items": [], "total_affected_items": PAGE * 3}, "error": 0})
            };
            Ok((200, body.to_string()))
        }
    }
    assert!(matches!(
        fetch(&Short, "https://wazuh:55000", "u", "p", "t"),
        Err(WazuhError::Invalid(m)) if m.contains("listed 1")
    ));
}

#[test]
fn a_listing_item_without_a_name_fails() {
    struct Nameless;
    impl Transport for Nameless {
        fn send(
            &self,
            _: &str,
            url: &str,
            _: &[(&str, String)],
            _: Option<&str>,
        ) -> Result<(u16, String), WazuhError> {
            let body = if url.ends_with("/authenticate") {
                json!({"data": {"token": "jwt"}, "error": 0})
            } else {
                json!({"data": {"affected_items": [{"relative_dirname": "r"}], "total_affected_items": 1}, "error": 0})
            };
            Ok((200, body.to_string()))
        }
    }
    assert!(matches!(
        fetch(&Nameless, "https://wazuh:55000", "u", "p", "t"),
        Err(WazuhError::Invalid(_))
    ));
}

#[test]
fn a_file_answered_with_a_json_error_fails_the_fetch() {
    struct ErrorFile;
    impl Transport for ErrorFile {
        fn send(
            &self,
            _: &str,
            url: &str,
            _: &[(&str, String)],
            _: Option<&str>,
        ) -> Result<(u16, String), WazuhError> {
            let path = url.trim_start_matches("https://wazuh:55000");
            let body = if path.ends_with("/authenticate") {
                json!({"data": {"token": "jwt"}, "error": 0}).to_string()
            } else if path.starts_with("/rules/files?") {
                Manager::listing(&[("etc/rules".into(), "local_rules.xml".into())], path)
            } else {
                json!({"error": 1, "message": "no such file"}).to_string()
            };
            Ok((200, body))
        }
    }
    assert!(matches!(
        fetch(&ErrorFile, "https://wazuh:55000", "u", "p", "t"),
        Err(WazuhError::Invalid(m)) if m.contains("local_rules.xml")
    ));
}

#[test]
fn an_empty_ruleset_is_complete_with_zero_counts() {
    let mut manager = Manager::new();
    manager.rule_files = vec![];
    let inventory = run(&manager);
    assert_eq!(inventory.manifest.counts["rules"], 0);
    assert!(inventory.manifest.complete);
}

#[test]
fn every_request_after_logging_in_carries_the_managers_token() {
    struct Checking {
        headers: RefCell<Vec<(String, String)>>,
    }
    impl Transport for Checking {
        fn send(
            &self,
            _: &str,
            url: &str,
            headers: &[(&str, String)],
            _: Option<&str>,
        ) -> Result<(u16, String), WazuhError> {
            self.headers
                .borrow_mut()
                .push((url.to_owned(), headers[0].1.clone()));
            let path = url.trim_start_matches("https://wazuh:55000");
            let body = if path.ends_with("/authenticate") {
                json!({"data": {"token": "jwt-from-manager"}, "error": 0}).to_string()
            } else if path.contains("/files?") {
                Manager::listing(&[], path)
            } else {
                return Ok((404, "{}".into()));
            };
            Ok((200, body))
        }
    }
    let checking = Checking {
        headers: RefCell::new(Vec::new()),
    };
    fetch(&checking, "https://wazuh:55000", "reader", "secret", "t").unwrap();
    let headers = checking.headers.borrow();
    assert_eq!(headers[0].1, crate::client::basic_auth("reader", "secret"));
    assert!(headers.len() > 1);
    for (url, header) in &headers[1..] {
        assert_eq!(header, "Bearer jwt-from-manager", "{url}");
    }
}

#[test]
fn an_authentication_answer_without_a_token_fails_the_fetch() {
    struct NoToken;
    impl Transport for NoToken {
        fn send(
            &self,
            _: &str,
            _: &str,
            _: &[(&str, String)],
            _: Option<&str>,
        ) -> Result<(u16, String), WazuhError> {
            Ok((200, json!({"data": {}, "error": 0}).to_string()))
        }
    }
    assert!(matches!(
        fetch(&NoToken, "https://wazuh:55000", "u", "p", "t"),
        Err(WazuhError::Invalid(m)) if m.contains("token")
    ));
}
