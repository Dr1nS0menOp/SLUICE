//! Leaf paths of nested JSON objects.

use serde_json::{Map, Value};
use sluice_core::field::FieldPath;

/// Calls `visit` for every leaf of `object` with its dotted path. Arrays are leaves; empty
/// objects contribute nothing. This is exactly what VRL's `flatten` produces, so the data
/// plane's classifier sees the same key set as discovery.
pub(crate) fn for_each_leaf(object: &Map<String, Value>, visit: &mut impl FnMut(&str, &Value)) {
    let mut path = String::new();
    walk(object, &mut path, visit);
}

fn walk(object: &Map<String, Value>, path: &mut String, visit: &mut impl FnMut(&str, &Value)) {
    for (key, value) in object {
        let restore = path.len();
        if !path.is_empty() {
            path.push('.');
        }
        path.push_str(key);
        match value {
            Value::Object(inner) => walk(inner, path, visit),
            leaf => visit(path, leaf),
        }
        path.truncate(restore);
    }
}

/// Looks up a dotted path, descending into nested objects.
pub(crate) fn get<'a>(object: &'a Map<String, Value>, path: &FieldPath) -> Option<&'a Value> {
    let mut segments = path.segments();
    let mut current = object.get(segments.next()?)?;
    for segment in segments {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            other => panic!("not an object: {other}"),
        }
    }

    #[test]
    fn visits_leaves_with_dotted_paths() {
        let event =
            object(json!({"a": 1, "b": {"c": "x", "d": {"e": null}}, "f": [1, 2], "g": {}}));
        let mut seen = Vec::new();
        for_each_leaf(&event, &mut |path, _| seen.push(path.to_owned()));
        assert_eq!(seen, ["a", "b.c", "b.d.e", "f"]);
    }

    #[test]
    fn arrays_of_objects_and_keys_with_dots_are_leaves_as_written() {
        let event = object(json!({"list": [{"a": 1}], "x.y": 2, "deep": {"a": {"b": {"c": 3}}}}));
        let mut seen = Vec::new();
        for_each_leaf(&event, &mut |path, _| seen.push(path.to_owned()));
        assert_eq!(seen, ["deep.a.b.c", "list", "x.y"]);
    }

    #[test]
    fn an_empty_event_has_no_leaves() {
        let mut count = 0;
        for_each_leaf(&Map::new(), &mut |_, _| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn get_does_not_descend_into_arrays_or_scalars() {
        let event = object(json!({"list": [{"a": 1}], "n": 5}));
        assert_eq!(get(&event, &"list.a".into()), None);
        assert_eq!(get(&event, &"n.x".into()), None);
        assert_eq!(get(&event, &"".into()), None);
    }

    #[test]
    fn gets_nested_values() {
        let event = object(json!({"event": {"code": 4624}, "flat": "x"}));
        assert_eq!(get(&event, &"event.code".into()), Some(&json!(4624)));
        assert_eq!(get(&event, &"flat".into()), Some(&json!("x")));
        assert_eq!(get(&event, &"flat.deeper".into()), None);
        assert_eq!(get(&event, &"missing".into()), None);
    }
}
