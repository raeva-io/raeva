//! The iteration order of a `java.util.HashMap<String, _>` that strings were
//! put into, each only if absent, as Maven's `DefaultVersionRangeResolver`
//! gathers the versions it lists.
//!
//! This follows OpenJDK's `HashMap` for that use alone: the default capacity
//! and load factor, resizes that split each bin into a low and a high list,
//! bins of nine or more that resize the table below 64 and become red-black
//! trees above it, and tree bins that a split leaves with six or fewer nodes
//! turned back into lists. Nothing is ever removed or put twice. A table
//! iterates bin by bin, each bin along its `next` links, which in a tree
//! start at the root and place a new node right after its tree parent.

use std::cmp::Ordering;

const DEFAULT_CAPACITY: usize = 16;
const TREEIFY_THRESHOLD: usize = 8;
const UNTREEIFY_THRESHOLD: usize = 6;
const MIN_TREEIFY_CAPACITY: usize = 64;

/// The indices of the distinct `keys` in the order the map iterates them,
/// each key at its first occurrence.
pub(super) fn iteration_order<'a>(keys: impl IntoIterator<Item = &'a str>) -> Vec<usize> {
    let mut map = JavaHashMap::default();
    let mut seen = foldhash::HashSet::default();
    for (index, key) in keys.into_iter().enumerate() {
        if seen.insert(key) {
            map.put(index, key);
        }
    }
    map.iter()
}

struct Node {
    hash: i32,
    key: Vec<u16>,
    index: usize,
    next: Option<usize>,
    tree: Option<Tree>,
}

#[derive(Clone, Copy, Default)]
struct Tree {
    parent: Option<usize>,
    left: Option<usize>,
    right: Option<usize>,
    red: bool,
}

#[derive(Default)]
struct JavaHashMap {
    nodes: Vec<Node>,
    table: Vec<Option<usize>>,
    threshold: usize,
}

/// `String.hashCode`, spread as `HashMap.hash` spreads it.
fn spread(key: &[u16]) -> i32 {
    let hash = (key.iter()).fold(0i32, |hash, &unit| {
        hash.wrapping_mul(31).wrapping_add(i32::from(unit))
    });
    hash ^ ((hash as u32) >> 16) as i32
}

impl JavaHashMap {
    fn put(&mut self, index: usize, key: &str) {
        let key: Vec<u16> = key.encode_utf16().collect();
        let hash = spread(&key);
        if self.table.is_empty() {
            self.resize();
        }
        let node = self.nodes.len();
        self.nodes.push(Node {
            hash,
            key,
            index,
            next: None,
            tree: None,
        });
        let bin = self.bin(hash);
        match self.table[bin] {
            None => self.table[bin] = Some(node),
            Some(head) if self.nodes[head].tree.is_some() => self.put_tree(head, node),
            Some(head) => {
                let mut last = head;
                let mut count = 1;
                while let Some(next) = self.nodes[last].next {
                    last = next;
                    count += 1;
                }
                self.nodes[last].next = Some(node);
                if count >= TREEIFY_THRESHOLD {
                    self.treeify_bin(bin);
                }
            }
        }
        if self.nodes.len() > self.threshold {
            self.resize();
        }
    }

    fn bin(&self, hash: i32) -> usize {
        hash as u32 as usize & (self.table.len() - 1)
    }

    fn resize(&mut self) {
        let old = std::mem::take(&mut self.table);
        let capacity = match old.len() {
            0 => DEFAULT_CAPACITY,
            capacity => capacity * 2,
        };
        self.threshold = capacity / 4 * 3;
        self.table = vec![None; capacity];
        for (bin, head) in old.into_iter().enumerate() {
            let Some(head) = head else { continue };
            if self.nodes[head].next.is_none() {
                let at = self.bin(self.nodes[head].hash);
                self.table[at] = Some(head);
                continue;
            }
            let tree = self.nodes[head].tree.is_some();
            let (mut low, mut high) = (Vec::new(), Vec::new());
            let mut at = Some(head);
            while let Some(node) = at {
                at = self.nodes[node].next;
                match self.nodes[node].hash as u32 as usize & (capacity / 2) {
                    0 => low.push(node),
                    _ => high.push(node),
                }
            }
            let both = !low.is_empty() && !high.is_empty();
            for (nodes, to) in [(low, bin), (high, bin + capacity / 2)] {
                let Some(&first) = nodes.first() else {
                    continue;
                };
                self.link(&nodes);
                self.table[to] = Some(first);
                if !tree {
                    continue;
                }
                if nodes.len() <= UNTREEIFY_THRESHOLD {
                    for &node in &nodes {
                        self.nodes[node].tree = None;
                    }
                } else if both {
                    self.treeify(to);
                }
            }
        }
    }

    /// Chains `nodes` along their `next` links in this order.
    fn link(&mut self, nodes: &[usize]) {
        for pair in nodes.windows(2) {
            self.nodes[pair[0]].next = Some(pair[1]);
        }
        if let Some(&last) = nodes.last() {
            self.nodes[last].next = None;
        }
    }

    fn treeify_bin(&mut self, bin: usize) {
        if self.table.len() < MIN_TREEIFY_CAPACITY {
            self.resize();
        } else {
            self.treeify(bin);
        }
    }

    /// Builds the red-black tree of a bin's nodes in `next` order and moves
    /// its root to the front.
    fn treeify(&mut self, bin: usize) {
        let mut at = self.table[bin];
        let mut root = None;
        while let Some(node) = at {
            at = self.nodes[node].next;
            self.nodes[node].tree = Some(Tree::default());
            let Some(top) = root else {
                root = Some(node);
                continue;
            };
            let parent = self.descend(top, node);
            self.tree_mut(node).parent = Some(parent);
            self.attach(parent, node);
            root = Some(self.balance_insertion(top, node));
        }
        if let Some(root) = root {
            self.move_root_to_front(root);
        }
    }

    fn put_tree(&mut self, root: usize, node: usize) {
        self.nodes[node].tree = Some(Tree::default());
        let parent = self.descend(root, node);
        self.attach(parent, node);
        self.nodes[node].next = self.nodes[parent].next;
        self.nodes[parent].next = Some(node);
        self.tree_mut(node).parent = Some(parent);
        let root = self.balance_insertion(root, node);
        self.move_root_to_front(root);
    }

    /// The node below which `node` belongs in the tree under `root`.
    fn descend(&self, root: usize, node: usize) -> usize {
        let mut at = root;
        loop {
            let next = match self.order(node, at) {
                Ordering::Less => self.tree(at).left,
                _ => self.tree(at).right,
            };
            match next {
                Some(next) => at = next,
                None => return at,
            }
        }
    }

    fn attach(&mut self, parent: usize, node: usize) {
        match self.order(node, parent) {
            Ordering::Less => self.tree_mut(parent).left = Some(node),
            _ => self.tree_mut(parent).right = Some(node),
        }
    }

    /// The tree's order: by spread hash, then as `String.compareTo` compares
    /// UTF-16 units. Distinct keys never compare equal.
    fn order(&self, a: usize, b: usize) -> Ordering {
        let (a, b) = (&self.nodes[a], &self.nodes[b]);
        a.hash.cmp(&b.hash).then_with(|| a.key.cmp(&b.key))
    }

    fn move_root_to_front(&mut self, root: usize) {
        let bin = self.bin(self.nodes[root].hash);
        let first = self.table[bin].expect("a tree bin");
        if first == root {
            return;
        }
        let mut before = first;
        while self.nodes[before].next != Some(root) {
            before = self.nodes[before].next.expect("the root is in its bin");
        }
        self.nodes[before].next = self.nodes[root].next;
        self.nodes[root].next = Some(first);
        self.table[bin] = Some(root);
    }

    fn tree(&self, node: usize) -> Tree {
        self.nodes[node].tree.expect("a tree node")
    }

    fn tree_mut(&mut self, node: usize) -> &mut Tree {
        self.nodes[node].tree.as_mut().expect("a tree node")
    }

    fn red(&self, node: Option<usize>) -> bool {
        node.is_some_and(|node| self.tree(node).red)
    }

    fn balance_insertion(&mut self, mut root: usize, mut x: usize) -> usize {
        self.tree_mut(x).red = true;
        loop {
            let Some(mut xp) = self.tree(x).parent else {
                self.tree_mut(x).red = false;
                return x;
            };
            let Some(mut xpp) = self.tree(xp).parent.filter(|_| self.tree(xp).red) else {
                return root;
            };
            let left = self.tree(xpp).left == Some(xp);
            let uncle = match left {
                true => self.tree(xpp).right,
                false => self.tree(xpp).left,
            };
            if let Some(uncle) = uncle.filter(|&uncle| self.red(Some(uncle))) {
                self.tree_mut(uncle).red = false;
                self.tree_mut(xp).red = false;
                self.tree_mut(xpp).red = true;
                x = xpp;
                continue;
            }
            let inner = match left {
                true => self.tree(xp).right == Some(x),
                false => self.tree(xp).left == Some(x),
            };
            if inner {
                x = xp;
                root = self.rotate(root, x, left);
                xp = self.tree(x).parent.expect("rotated below a parent");
                xpp = self.tree(xp).parent.expect("rotated below a grandparent");
            }
            self.tree_mut(xp).red = false;
            self.tree_mut(xpp).red = true;
            root = self.rotate(root, xpp, !left);
        }
    }

    /// `rotateLeft` when `left`, else `rotateRight`, returning the root.
    fn rotate(&mut self, mut root: usize, p: usize, left: bool) -> usize {
        let child = |tree: &Tree, left: bool| if left { tree.right } else { tree.left };
        let Some(r) = child(&self.tree(p), left) else {
            return root;
        };
        let inner = child(&self.tree(r), !left);
        match left {
            true => self.tree_mut(p).right = inner,
            false => self.tree_mut(p).left = inner,
        }
        if let Some(inner) = inner {
            self.tree_mut(inner).parent = Some(p);
        }
        let pp = self.tree(p).parent;
        self.tree_mut(r).parent = pp;
        match pp {
            None => {
                root = r;
                self.tree_mut(r).red = false;
            }
            Some(pp) if self.tree(pp).left == Some(p) => self.tree_mut(pp).left = Some(r),
            Some(pp) => self.tree_mut(pp).right = Some(r),
        }
        match left {
            true => self.tree_mut(r).left = Some(p),
            false => self.tree_mut(r).right = Some(p),
        }
        self.tree_mut(p).parent = Some(r);
        root
    }

    fn iter(&self) -> Vec<usize> {
        let mut order = Vec::with_capacity(self.nodes.len());
        for &head in &self.table {
            let mut at = head;
            while let Some(node) = at {
                order.push(self.nodes[node].index);
                at = self.nodes[node].next;
            }
        }
        order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The orders `test-fixtures/java-hash-map/HashMapOrder.java` recorded
    /// from a real `java.util.HashMap`.
    #[test]
    fn keys_iterate_as_in_java() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-fixtures/java-hash-map/cases.txt"
        );
        let text = std::fs::read_to_string(path).unwrap();
        let mut cases = 0;
        let mut lines = text.lines().filter(|line| !line.starts_with("# "));
        while let Some(name) = lines.next() {
            let keys = lines.next().and_then(|line| line.strip_prefix("keys: "));
            let order = lines.next().and_then(|line| line.strip_prefix("order:"));
            let (Some(keys), Some(order)) = (keys, order) else {
                panic!("{name}: a case is a name, keys and an order");
            };
            let order: Vec<usize> = (order.split_whitespace())
                .map(|index| index.parse().unwrap())
                .collect();
            assert_eq!(iteration_order(keys.split(' ')), order, "{name}");
            cases += 1;
        }
        assert!(cases > 70, "{cases} cases");
    }
}
