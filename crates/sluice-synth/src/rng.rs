//! A small, frozen pseudo-random generator.
//!
//! Sluice's tests and demo depend on byte-identical synthetic data for a given seed. General
//! purpose crates such as `rand` don't promise stable output across versions, so we use
//! `SplitMix64` (Steele, Lea & Flood, 2014), whose output is fixed by its definition. It is not
//! cryptographic, and it doesn't need to be.

/// `SplitMix64` generator.
#[derive(Debug, Clone)]
pub(crate) struct Rng {
    state: u64,
}

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// An independent stream derived from this one and a label, so that the streams of different
    /// sources don't shift when one source changes how many numbers it draws.
    pub(crate) fn fork(&self, label: &str) -> Self {
        // FNV-1a over the label, mixed with the parent state.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in label.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let mut child = Self::new(self.state ^ hash);
        child.next_u64();
        child
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (Lemire's multiply-shift; its bias is negligible here). Returns 0 for
    /// `n == 0`.
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        let wide = u128::from(self.next_u64()) * u128::from(n);
        // The high 64 bits of a 64x64-bit product always fit in u64.
        u64::try_from(wide >> 64).unwrap_or(0)
    }

    /// A value in `low..=high`.
    pub(crate) fn between(&mut self, low: u64, high: u64) -> u64 {
        low + self.below(high.saturating_sub(low) + 1)
    }

    /// True with the given probability in percent.
    pub(crate) fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    /// A uniformly chosen element. `items` must not be empty: callers pass fixed fixture tables.
    pub(crate) fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let len = u64::try_from(items.len()).unwrap_or(u64::MAX);
        let index = usize::try_from(self.below(len)).unwrap_or(0);
        &items[index]
    }

    /// A lowercase hex string of `len` characters.
    pub(crate) fn hex(&mut self, len: usize) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        (0..len).map(|_| char::from(*self.pick(DIGITS))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_frozen_for_a_seed() {
        // Reference values of SplitMix64 for seed 0; if these change, every fixture changes.
        let mut rng = Rng::new(0);
        assert_eq!(rng.next_u64(), 0xe220_a839_7b1d_cdaf);
        assert_eq!(rng.next_u64(), 0x6e78_9e6a_a1b9_65f4);
    }

    #[test]
    fn forks_are_independent_of_each_other() {
        let root = Rng::new(42);
        let mut a = root.fork("a");
        let mut b = root.fork("b");
        assert_ne!(a.next_u64(), b.next_u64());
        assert_eq!(root.fork("a").next_u64(), Rng::new(42).fork("a").next_u64());
    }

    #[test]
    fn below_stays_in_range() {
        let mut rng = Rng::new(7);
        assert!((0..10_000).all(|_| rng.below(6) < 6));
        assert_eq!(rng.below(0), 0);
        assert!((0..1_000).all(|_| (3..=5).contains(&rng.between(3, 5))));
    }
}
