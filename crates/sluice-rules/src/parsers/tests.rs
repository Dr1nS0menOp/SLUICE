use super::*;

const PACK: &str = r"
id: test/kv
description: a test pack
logsource: { product: test }
convention: sigma
patterns:
  - regex: 'src=(?P<src>\S+)(?: dst=(?P<dst>\S+))?'
    fields:
      src: src_ip
      dst: [dst_ip, DestinationIp]
examples:
  - line: 'src=10.0.0.1 dst=10.0.0.2'
    fields: { src_ip: 10.0.0.1, dst_ip: 10.0.0.2, DestinationIp: 10.0.0.2 }
  - line: 'src=10.0.0.3'
    fields: { src_ip: 10.0.0.3, dst_ip: ~ }
";

fn book(files: &[(&str, &str)]) -> Result<ParserBook, RulesError> {
    ParserBook::parse(files.iter().copied())
}

#[test]
fn every_built_in_pack_is_valid_and_parses_its_examples() {
    let book = ParserBook::embedded().expect("the built-in packs are valid");
    assert!(book.packs().count() >= 15, "{}", book.packs().count());
    for id in [
        "nginx/combined",
        "linux/auth",
        "pf/filterlog",
        "squid/native",
        "bind/query",
    ] {
        assert!(book.get(id).is_some(), "{id}");
    }
}

#[test]
fn a_line_gives_the_fields_of_the_first_pattern_that_matches_and_no_others() {
    let book = book(&[("kv.yaml", PACK)]).expect("valid");
    let pack = book.get("test/kv").expect("the pack");
    let both = pack.parse("x src=1.1.1.1 dst=2.2.2.2").expect("it parses");
    assert_eq!(both.get("dst_ip").map(String::as_str), Some("2.2.2.2"));
    assert_eq!(
        both.get("DestinationIp").map(String::as_str),
        Some("2.2.2.2")
    );
    let one = pack.parse("src=1.1.1.1").expect("it parses");
    assert_eq!(
        one.get("dst_ip"),
        None,
        "a group that took no part gives no field"
    );
    assert_eq!(pack.parse("nothing here"), None);
}

#[test]
fn a_pack_whose_example_does_not_parse_as_it_says_is_refused() {
    let wrong = PACK.replace("dst_ip: 10.0.0.2,", "dst_ip: 10.9.9.9,");
    let error = book(&[("kv.yaml", &wrong)])
        .expect_err("refused")
        .to_string();
    assert!(error.contains("gives dst_ip"), "{error}");
    let unmatched = PACK.replace("line: 'src=10.0.0.3'", "line: 'nothing'");
    assert!(book(&[("kv.yaml", &unmatched)]).is_err());
}

#[test]
fn a_field_from_a_group_the_pattern_lacks_or_an_escaped_quote_is_refused() {
    let missing = PACK.replace("src: src_ip", "source: src_ip");
    let error = book(&[("kv.yaml", &missing)])
        .expect_err("refused")
        .to_string();
    assert!(error.contains("no group source"), "{error}");
    let quoted = PACK.replace(r"src=(?P<src>\S+)", r"\'src=(?P<src>\S+)");
    assert!(book(&[("kv.yaml", &quoted)]).is_err());
}

#[test]
fn two_packs_with_one_id_or_an_unknown_field_are_refused() {
    assert!(book(&[("a.yaml", PACK), ("b.yaml", PACK)]).is_err());
    let typo = PACK.replace("convention:", "conventon:");
    assert!(book(&[("kv.yaml", &typo)]).is_err());
}

#[test]
fn a_pack_includes_the_patterns_and_examples_of_others_after_its_own() {
    let other = PACK
        .replace("test/kv", "test/other")
        .replace("src=", "from=");
    let both = r"
id: test/both
description: both
logsource: {}
convention: sigma
include: [test/kv, test/other]
";
    let book = book(&[("both.yaml", both), ("kv.yaml", PACK), ("o.yaml", &other)]).expect("valid");
    let pack = book.get("test/both").expect("the pack");
    assert_eq!(pack.parser.patterns.len(), 2);
    assert!(pack.parse("from=1.1.1.1").is_some());
    assert!(pack.parse("src=1.1.1.1").is_some());
    let unknown = both.replace("test/other", "test/none");
    assert!(ParserBook::parse([("both.yaml", unknown.as_str()), ("kv.yaml", PACK)]).is_err());
}

#[test]
fn a_source_gets_the_pack_it_names_and_an_unknown_one_is_an_error() {
    let book = book(&[("kv.yaml", PACK)]).expect("valid");
    let source = |parser: &str| -> Source {
        serde_json::from_value(serde_json::json!({
            "id": "fw", "logsource": {}, "schema": "sigma",
            "format": {"kind": "text", "field": "message", "parser": parser},
        }))
        .expect("a source")
    };
    let mut sources = vec![source("test/kv")];
    book.resolve(&mut sources).expect("resolved");
    assert_eq!(
        sources[0].format.parser().map(|p| p.id.as_str()),
        Some("test/kv")
    );
    let mut unknown = vec![source("test/none")];
    let error = book.resolve(&mut unknown).expect_err("unknown").to_string();
    assert!(error.contains("names the parser test/none"), "{error}");
}

#[test]
fn a_named_but_unresolved_pack_parses_nothing() {
    let source: Source = serde_json::from_value(serde_json::json!({
        "id": "fw", "logsource": {},
        "format": {"kind": "text", "field": "message", "parser": "test/kv"},
    }))
    .expect("a source");
    assert_eq!(source.format.parser(), None);
    let back = serde_json::to_value(&source.format).expect("serializes");
    assert_eq!(
        back["parser"], "test/kv",
        "the name is written back as it was given"
    );
}
