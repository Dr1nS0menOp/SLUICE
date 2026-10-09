//! Stable template identifiers.
//!
//! Template ids end up in recipe caches, reports and community recipes, so they must not change
//! between runs, machines or compiler versions. `std`'s hasher gives no such promise, so we use
//! 64-bit FNV-1a, which is fixed by definition.

use sluice_core::ids::{SourceId, TemplateId};

/// 64-bit FNV-1a over a sequence of parts, each followed by a separator byte, so that
/// `["ab", "c"]` and `["a", "bc"]` hash differently.
pub(crate) fn fnv1a<'a>(parts: impl IntoIterator<Item = &'a str>) -> u64 {
    fnv1a_bytes(
        parts
            .into_iter()
            .flat_map(|part| part.bytes().chain([0x1f])),
    )
}

fn fnv1a_bytes(bytes: impl IntoIterator<Item = u8>) -> u64 {
    bytes.into_iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Builds `source:label:hash`, or `source:hash` when there is no label. The label makes ids
/// readable (`windows-security:4624:…`); the hash makes them unique.
pub(crate) fn template_id(source: &SourceId, label: &str, hash: u64) -> TemplateId {
    let short = format!("{hash:016x}");
    let short = &short[..12];
    if label.is_empty() {
        TemplateId::new(format!("{source}:{short}"))
    } else {
        TemplateId::new(format!("{source}:{label}:{short}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_matches_reference_vectors() {
        // From the FNV reference test suite (64-bit FNV-1a).
        assert_eq!(fnv1a_bytes(*b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_bytes(*b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_bytes(*b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn parts_are_separated() {
        assert_ne!(fnv1a(["ab", "c"]), fnv1a(["a", "bc"]));
    }

    #[test]
    fn ids_are_readable() {
        let source = SourceId::new("windows-security");
        assert_eq!(
            template_id(&source, "4624", 0x0123_4567_89ab_cdef).as_str(),
            "windows-security:4624:0123456789ab"
        );
        assert_eq!(
            template_id(&source, "", 1).as_str(),
            "windows-security:000000000000"
        );
    }
}
