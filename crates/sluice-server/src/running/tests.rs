//! What Vector runs in proposal mode: kept only when proven, otherwise the safe configuration.

use std::fs;
use std::path::Path;

use crate::control::{Shared, lock};
use crate::tests::{scratch, shared};

fn running_status(shared: &Shared) -> String {
    shared
        .profile(None)
        .unwrap()
        .status
        .read()
        .unwrap()
        .running
        .clone()
        .unwrap_or_default()
}

fn last_switch_off(shared: &Shared) -> String {
    let status = shared.profile(None).unwrap().status.read().unwrap().clone();
    let last = status.history.last().expect("a transition");
    assert_eq!(last.kind, "switched_off");
    last.reason.clone().unwrap_or_default()
}

fn proven_copy(dir: &Path) -> std::path::PathBuf {
    dir.join("data").join(super::PROVEN_COPY)
}

#[test]
fn startup_keeps_the_deployed_configuration_only_if_sluice_proved_exactly_it() {
    let dir = scratch("startup");
    let shared = shared(&dir);
    let safe = shared.initial_config().unwrap();
    let vector = dir.join("vector.yaml");

    shared.write_startup_config().unwrap();
    assert_eq!(
        fs::read_to_string(&vector).unwrap(),
        safe,
        "nothing deployed"
    );
    assert_eq!(*lock(&shared.running), safe);

    let proven = format!("{safe}\n# reviewed\n");
    fs::create_dir_all(dir.join("data")).unwrap();
    fs::write(proven_copy(&dir), &proven).unwrap();
    fs::write(&vector, &proven).unwrap();
    shared.write_startup_config().unwrap();
    assert_eq!(
        fs::read_to_string(&vector).unwrap(),
        proven,
        "kept as it is"
    );
    assert_eq!(*lock(&shared.running), proven);

    fs::write(&vector, format!("{proven} ")).unwrap();
    shared.write_startup_config().unwrap();
    assert_eq!(
        fs::read_to_string(&vector).unwrap(),
        safe,
        "one byte off what was proven"
    );
    assert_eq!(*lock(&shared.running), safe);

    fs::remove_file(proven_copy(&dir)).unwrap();
    fs::write(&vector, &proven).unwrap();
    shared.write_startup_config().unwrap();
    assert_eq!(fs::read_to_string(&vector).unwrap(), safe, "nothing proven");
}

#[test]
fn the_safe_configuration_needs_no_proof_and_reloads_only_when_it_was_not_running() {
    let dir = scratch("safe-deployed");
    let shared = shared(&dir);
    shared.write_startup_config().unwrap();
    assert!(!shared.guard_running(&[], 1).unwrap(), "already running");
    assert!(running_status(&shared).contains("nothing is saved"));
    "something else".clone_into(&mut lock(&shared.running));
    assert!(
        shared.guard_running(&[], 2).unwrap(),
        "back to the safe one"
    );
}

#[test]
fn c5_a_configuration_sluice_cannot_read_is_switched_off() {
    for (i, broken) in [None, Some(&[0xff, 0xfe, b'x'][..])]
        .into_iter()
        .enumerate()
    {
        let dir = scratch(&format!("unreadable-{i}"));
        let shared = shared(&dir);
        shared.write_startup_config().unwrap();
        let safe = shared.initial_config().unwrap();
        let vector = dir.join("vector.yaml");
        match broken {
            None => fs::remove_file(&vector).unwrap(),
            Some(bytes) => fs::write(&vector, bytes).unwrap(),
        }
        assert!(shared.guard_running(&[], 1).unwrap(), "Vector reloads");
        assert_eq!(fs::read_to_string(&vector).unwrap(), safe, "{broken:?}");
        assert!(
            last_switch_off(&shared).contains("cannot read"),
            "{broken:?}"
        );
    }
}

#[test]
fn c5_a_configuration_that_is_not_sluices_is_switched_off_with_its_reason() {
    let dir = scratch("foreign");
    let shared = shared(&dir);
    shared.write_startup_config().unwrap();
    let safe = shared.initial_config().unwrap();
    let vector = dir.join("vector.yaml");
    fs::create_dir_all(dir.join("data")).unwrap();
    fs::write(proven_copy(&dir), "an older proven configuration").unwrap();
    fs::write(&vector, "transforms:\n  mine:\n    type: filter\n").unwrap();

    assert!(shared.guard_running(&[], 1).unwrap());
    assert_eq!(fs::read_to_string(&vector).unwrap(), safe);
    assert!(
        !proven_copy(&dir).exists(),
        "a restart must not bring it back"
    );
    let reason = last_switch_off(&shared);
    assert!(
        reason.contains("profile sigma") && reason.contains("not one Sluice generates"),
        "{reason}"
    );
    assert!(running_status(&shared).starts_with("safe configuration since 1"));
}
