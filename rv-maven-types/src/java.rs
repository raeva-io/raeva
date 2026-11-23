//! Java's hashing, for orders Maven takes from a `HashMap` or `HashSet`.

/// Java's `String.hashCode`.
pub fn java_string_hash(text: &str) -> i32 {
    text.encode_utf16().fold(0i32, |hash, unit| {
        hash.wrapping_mul(31).wrapping_add(i32::from(unit))
    })
}

/// The order a `java.util.HashSet` made with the default capacity iterates
/// `items`, added in this order without repeats, whose `hashCode`s are
/// `hash`: by bucket, then in the order added.
pub fn java_set_order<T>(items: &mut [T], hash: impl Fn(&T) -> i32) {
    let mut buckets = 16usize;
    while items.len() * 4 > buckets * 3 {
        buckets *= 2;
    }
    items.sort_by_cached_key(|item| {
        let hash = hash(item) as u32;
        (hash ^ (hash >> 16)) as usize & (buckets - 1)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Java's `String.hashCode` and `HashSet` order, checked against
    /// OpenJDK 27.
    #[test]
    fn java_hashes_and_set_order() {
        assert_eq!(java_string_hash(""), 0);
        assert_eq!(java_string_hash("12"), 1569);
        assert_eq!(java_string_hash("hello world"), 1794106052);
        assert_eq!(java_string_hash("polygenelubricants"), i32::MIN);
        // new HashSet<>(); add("0".."19") iterates 0 1 10 11 ... as below.
        let mut ids: Vec<String> = (0..20).map(|i| i.to_string()).collect();
        java_set_order(&mut ids, |id| java_string_hash(id));
        assert_eq!(
            ids,
            [
                "11", "12", "13", "14", "15", "16", "17", "18", "19", "0", "1", "2", "3", "4", "5",
                "6", "7", "8", "9", "10"
            ]
        );
        // 100 entries resize the table to 256 buckets.
        let mut ids: Vec<String> = (0..100).map(|i| i.to_string()).collect();
        java_set_order(&mut ids, |id| java_string_hash(id));
        let expected = "88 89 90 91 92 93 94 95 96 97 10 98 11 99 12 13 14 15 16 17 18 19 0 1 2 3 \
                        4 5 6 7 8 9 20";
        assert_eq!(ids[..33].join(" "), expected);
        assert_eq!(
            ids[33..].join(" "),
            (21..88)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
}
