use std::fmt::Write as _;

use sluice_core::predicate::MatchOp;

use super::*;
use crate::splunk::conf;

fn derived(props: &str, transforms: &str) -> Derived {
    Derived::new(&conf::conf(props), &conf::conf(transforms))
}

fn equals(field: &str, value: &str) -> Predicate {
    Predicate::Field(FieldTest {
        field: FieldPath::new(field),
        op: MatchOp::Equals,
        values: vec![value.to_owned()],
        case_sensitive: false,
    })
}

fn fields(reads: &Reads) -> Vec<&str> {
    reads.fields.iter().map(FieldPath::as_str).collect()
}

#[test]
fn c3_a_test_on_an_alias_tests_what_it_copies() {
    let derived = derived(
        "[XmlWinEventLog]\nFIELDALIAS-user = TargetUserName AS user \"Sub Name\" ASNEW subject\n",
        "",
    );
    let reads = derived.apply(spl::read("user=bob"));
    assert_eq!(
        reads.prefilter,
        Predicate::any([equals("user", "bob"), equals("TargetUserName", "bob")])
    );
    assert_eq!(fields(&reads), ["TargetUserName", "user"]);
    assert_eq!(
        derived.apply(spl::read("subject=x")).prefilter,
        Predicate::any([equals("subject", "x"), equals("Sub Name", "x")])
    );
}

#[test]
fn c3_a_test_on_a_computed_field_matches_every_event() {
    let derived = derived(
        "[s]\nEVAL-action = if(EventCode==4625, \"failure\", \"success\")\n\
         LOOKUP-vendor = products product_id AS ProviderGuid OUTPUT vendor_product\n",
        "",
    );
    let reads = derived.apply(spl::read("action=failure user=x"));
    assert_eq!(reads.prefilter, equals("user", "x"));
    assert!(fields(&reads).contains(&"EventCode"));
    let reads = derived.apply(spl::read("vendor_product=Sysmon"));
    assert_eq!(reads.prefilter, Predicate::Always);
    assert_eq!(fields(&reads), ["ProviderGuid", "vendor_product"]);
}

#[test]
fn c3_an_extracted_field_reads_the_raw_event() {
    let derived = derived(
        "[s]\nEXTRACT-pid = pid=(?<pid>\\d+)(?<=x)\nREPORT-kv = user_kv\n",
        "[user_kv]\nREGEX = u=(\\w+)\nFORMAT = account::$1\n",
    );
    for search in ["pid=4", "account=root"] {
        let reads = derived.apply(spl::read(search));
        assert_eq!(reads.prefilter, Predicate::Always, "{search}");
        assert!(reads.raw, "{search}");
    }
    // An alias of an extracted field is made too.
    let derived = derived_alias_of_extracted();
    assert_eq!(derived.apply(spl::read("u=1")).prefilter, Predicate::Always);
}

fn derived_alias_of_extracted() -> Derived {
    derived(
        "[s]\nEXTRACT-a = (?P<a>\\w+) in message\nFIELDALIAS-u = a AS u\n",
        "",
    )
}

#[test]
fn an_extraction_from_a_field_reads_that_field_and_the_raw_event() {
    let reads = derived_alias_of_extracted().apply(spl::read("x=1 | table u"));
    assert!(fields(&reads).contains(&"message"));
    assert!(reads.raw);
}

#[test]
fn c3_names_the_data_decides_widen_every_test() {
    for (props, transforms) in [
        (
            "[s]\nREPORT-kv = kv\n",
            "[kv]\nREGEX = (\\w+)=(\\w+)\nFORMAT = $1::$2\n",
        ),
        ("[s]\nEXTRACT-kv = (?<_KEY_1>\\w+)=(?<_VAL_1>\\w+)\n", ""),
        ("[s]\nLOOKUP-all = assets ip\n", ""),
        ("[s]\nREPORT-x = missing\n", ""),
    ] {
        let derived = derived(props, transforms);
        assert!(derived.dynamic.is_some(), "{props}");
        let reads = derived.apply(spl::read("a=1"));
        assert_eq!(reads.prefilter, Predicate::Always, "{props}");
        assert!(reads.raw);
    }
}

#[test]
fn delimited_transforms_name_their_fields() {
    let derived = derived(
        "[s]\nREPORT-d = d\n",
        "[d]\nDELIMS = \",\"\nFIELDS = \"f1\", f2\nSOURCE_KEY = field:line\n",
    );
    let reads = derived.apply(spl::read("f2=x"));
    assert_eq!(reads.prefilter, Predicate::Always);
    assert!(fields(&reads).contains(&"line"));
    assert!(!reads.raw);
}

#[test]
fn without_props_a_search_is_read_as_it_is() {
    let reads = spl::read("a=1 | stats count by b");
    assert_eq!(Derived::default().apply(reads.clone()), reads);
}

#[test]
fn words_keep_quoted_spaces_and_commas_together() {
    assert_eq!(words(r#""Sub Name" AS x, y"#), ["Sub Name", "AS", "x", "y"]);
    assert_eq!(words(r#"a,"b, c""#), ["a", "b, c"]);
    assert_eq!(words("  a   b "), ["a", "b"]);
}

#[test]
fn a_lookup_makes_only_its_outputs_from_its_inputs() {
    let derived = derived(
        "[s]\nLOOKUP-v = products product_id AS ProviderGuid OUTPUT vendor AS vendor_product \
         category\n",
        "",
    );
    let made: Vec<&str> = derived.made.keys().map(String::as_str).collect();
    assert_eq!(made, ["category", "vendor_product"]);
    assert!(derived.made["category"].contains("ProviderGuid"));
    // An input is read as it is.
    assert_eq!(
        derived.apply(spl::read("ProviderGuid=x")).prefilter,
        equals("ProviderGuid", "x")
    );
}

#[test]
fn an_extraction_names_its_groups_and_only_one_word_after_in() {
    let derived = derived(
        "[s]\nEXTRACT-a = pid=(?<pid>\\d+)(?<=x)(?<!y) in two words\n",
        "",
    );
    let made: Vec<&str> = derived.made.keys().map(String::as_str).collect();
    assert_eq!(made, ["pid"]);
    assert!(
        !derived.made["pid"].contains("two words"),
        "` in ` with more words after it is part of the regex"
    );
}

#[test]
fn a_transform_from_metadata_reads_the_raw_event_and_named_formats_are_not_dynamic() {
    let derived = derived(
        "[s]\nREPORT-m = m\n",
        "[m]\nSOURCE_KEY = _meta\nREGEX = (\\w+)\nFORMAT = user::$1 host::$1\n",
    );
    assert_eq!(derived.dynamic, None);
    let made: Vec<&str> = derived.made.keys().map(String::as_str).collect();
    assert_eq!(made, ["host", "user"]);
    assert!(derived.made["user"].contains("_raw"));
    let reads = derived.apply(spl::read("x=1 | table user"));
    assert!(reads.raw);
}

/// `FIELDALIAS`es `a0 AS a1`, … `a{n-1} AS a{n}`: `a{n}` copies through `n` hops.
fn chain(n: usize) -> Derived {
    let mut props = String::new();
    for i in 0..n {
        let _ = writeln!(props, "FIELDALIAS-{i} = a{i} AS a{}", i + 1);
    }
    derived(&format!("[s]\n{props}"), "")
}

#[test]
fn alias_chains_are_followed_to_a_limit_and_cycles_end() {
    let within = chain(MAX_DEPTH).apply(spl::read(&format!("a{MAX_DEPTH}=1")));
    assert_ne!(within.prefilter, Predicate::Always, "{within:?}");
    assert!(!within.raw);
    assert!(within.fields.contains(&FieldPath::new("a0")));
    let beyond = chain(MAX_DEPTH + 1).apply(spl::read(&format!("a{}=1", MAX_DEPTH + 1)));
    assert_eq!(beyond.prefilter, Predicate::Always);
    assert!(
        beyond.raw,
        "a chain too long counts as reading the raw event"
    );
    let cycle = derived("[s]\nFIELDALIAS-a = x AS y\nFIELDALIAS-b = y AS x\n", "");
    let reads = cycle.apply(spl::read("x=1"));
    assert_eq!(reads.prefilter, Predicate::Always);
}
