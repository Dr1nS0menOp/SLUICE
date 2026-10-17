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
