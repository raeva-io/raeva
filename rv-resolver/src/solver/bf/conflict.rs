//! Maven's conflict resolution, ported from maven-resolver 2.0.24 and
//! 1.9.25, which differ only in the hashes below: ConflictMarker,
//! ConflictIdSorter and ClassicConflictResolver with the nearest version
//! selector, JavaScopeSelector, SimpleOptionalitySelector and
//! JavaScopeDeriver, over the tree the collector built. Where Java's
//! `HashSet` iteration order decides, the order is reproduced.

use std::collections::VecDeque;

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use rv_maven_model::Scope;
use rv_maven_types::{MavenMode, Version, VersionReq, java_set_order, java_string_hash};

use crate::graph::CoordKey;

/// What the conflict resolution reads of a node and sets on a winner.
#[derive(Debug, Clone)]
pub(super) struct Entry {
    pub key: CoordKey,
    /// The artifacts a relocation led from, which join the group.
    pub relocations: Vec<CoordKey>,
    pub version: Version,
    /// The range or `[x]` pin the node was requested by.
    pub hard: Option<VersionReq>,
    pub scope: Scope,
    pub optional: bool,
    pub managed_scope: bool,
}

#[derive(Debug)]
pub(super) struct TreeNode {
    /// A list of [`Tree::lists`], which other nodes may share.
    pub children: usize,
    /// `None` for the root.
    pub entry: Option<Entry>,
}

/// Maven's dirty tree: node 0 is the root, and nodes refer to their
/// children through lists that a reused subtree or a cycle shares.
#[derive(Debug, Default)]
pub(super) struct Tree {
    pub nodes: Vec<TreeNode>,
    pub lists: Vec<Vec<usize>>,
}

/// No version of a group satisfies all of its hard constraints.
#[derive(Debug)]
pub(super) struct Unsolvable {
    /// A node of the group, the one whose constraint left no candidate.
    pub node: usize,
    /// The version the group had selected before that.
    pub selected: Option<usize>,
}

/// The groups a resolution formed and their winners.
#[derive(Debug)]
pub(super) struct Resolved {
    ids: Vec<Option<usize>>,
    winners: HashMap<usize, Option<usize>>,
}

impl Resolved {
    /// The winner of `node`'s group.
    pub(super) fn winner_of(&self, node: usize) -> Option<usize> {
        let id = self.ids.get(node).copied().flatten()?;
        self.winners.get(&id).copied().flatten()
    }

    /// Make `node` the winner of its group if the group has none. A group
    /// sorted before the cycle that holds its parents gathers nothing, and
    /// Maven keeps its nodes unmediated, each with its own version and
    /// scope; the first one left in the tree stands for them.
    pub(super) fn stand_in(&mut self, node: usize) {
        if let Some(id) = self.ids.get(node).copied().flatten()
            && let Some(winner @ None) = self.winners.get_mut(&id)
        {
            *winner = Some(node);
        }
    }
}

const ROOT: usize = 0;
/// The conflict id of the last pass, which no node has.
const NO_ID: usize = usize::MAX;

/// Resolve the conflicts of `tree` in place: each losing node leaves its
/// parent's list, and each winner takes the scope and optionality selected
/// for its group. The root's own dependencies take their scopes below
/// `root_scope`, as below a root dependency of that scope.
pub(super) fn resolve(
    tree: &mut Tree,
    root_scope: Scope,
    mode: MavenMode,
) -> Result<Resolved, Unsolvable> {
    let ids = mark(tree, mode);
    let sorted = sort(tree, &ids, mode);
    let mut state = State::new(tree, &ids, root_scope, mode);
    let mut cyclic: HashMap<usize, HashSet<usize>> = HashMap::new();
    for cycle in &sorted.cycles {
        for &id in cycle {
            cyclic.entry(id).or_default().extend(cycle.iter().copied());
        }
    }
    let mut last_winner = None;
    for &id in &sorted.order {
        state.prepare(id, cyclic.get(&id));
        state.gather(ROOT);
        state.finish();
        let mut winner = None;
        if !state.items.is_empty() {
            let won = state.select_version()?;
            let node = state.items[won].node;
            let scope = state.select_scope(won);
            let optional = state.select_optional();
            let entry = state.entry_mut(node);
            entry.scope = scope;
            entry.optional = optional;
            state.remove_losers(won);
            winner = Some(node);
        }
        state.resolved.insert(id, winner);
        last_winner = winner;
    }
    if !sorted.cycles.is_empty()
        && let Some(winner) = last_winner
    {
        state.prepare(NO_ID, None);
        state.gather(winner);
    }
    let winners = state.resolved;
    Ok(Resolved { ids, winners })
}

/// ConflictMarker's key hash: `Objects.hash(artifactId, groupId, extension,
/// classifier)`, or in resolver 1.9 the same from 17 with the classifier
/// before the extension.
fn key_hash(key: &CoordKey, mode: MavenMode) -> i32 {
    let (extension, classifier) = (
        key.packaging.as_deref().unwrap_or("jar"),
        key.classifier.as_deref().unwrap_or(""),
    );
    let (artifact, group) = (key.artifact_id.as_str(), key.group_id.as_str());
    let (start, parts) = match mode {
        MavenMode::Maven39 => (17, [artifact, group, classifier, extension]),
        MavenMode::Maven310 => (1, [artifact, group, extension, classifier]),
    };
    parts.iter().fold(start, |hash, part| {
        hash.wrapping_mul(31).wrapping_add(java_string_hash(part))
    })
}

/// ConflictMarker: the conflict id of each node, `None` for the root. A
/// node's artifact and the artifacts it relocated from share a group, and
/// groups that come to share an artifact merge into a new one.
fn mark(tree: &Tree, mode: MavenMode) -> Vec<Option<usize>> {
    struct Group {
        keys: Vec<CoordKey>,
    }
    enum Merged {
        First,
        Second,
        New(Vec<CoordKey>),
    }
    fn merge(first: &[CoordKey], second: &[CoordKey]) -> Merged {
        let contains = |all: &[CoordKey], part: &[CoordKey]| part.iter().all(|k| all.contains(k));
        if first.len() < second.len() {
            if contains(second, first) {
                return Merged::Second;
            }
        } else if contains(first, second) {
            return Merged::First;
        }
        let mut keys = first.to_vec();
        keys.extend(second.iter().filter(|k| !first.contains(k)).cloned());
        Merged::New(keys)
    }
    let mut groups: Vec<Group> = Vec::new();
    let mut by_key: HashMap<CoordKey, usize> = HashMap::new();
    let mut analyze = |entry: &Entry| {
        let mut keys = vec![entry.key.clone()];
        for relocation in &entry.relocations {
            if !keys.contains(relocation) {
                keys.push(relocation.clone());
            }
        }
        if keys.len() > 1 {
            java_set_order(&mut keys, |key| key_hash(key, mode));
        }
        let mut group: Option<usize> = None;
        let mut fix = false;
        let create = |groups: &mut Vec<Group>, keys: Vec<CoordKey>| {
            groups.push(Group { keys });
            groups.len() - 1
        };
        for key in &keys {
            let found = by_key.get(key).copied();
            if group == found {
                continue;
            }
            match (group, found) {
                (None, Some(found)) => match merge(&groups[found].keys, &keys) {
                    Merged::First => {
                        group = Some(found);
                        break;
                    }
                    Merged::Second => {
                        group = Some(create(&mut groups, keys.clone()));
                        fix = true;
                    }
                    Merged::New(merged) => {
                        group = Some(create(&mut groups, merged));
                        fix = true;
                    }
                },
                (Some(_), None) => fix = true,
                (Some(current), Some(found)) => {
                    match merge(&groups[found].keys, &groups[current].keys) {
                        Merged::First => {
                            group = Some(found);
                            fix = false;
                            break;
                        }
                        Merged::Second => {}
                        Merged::New(merged) => {
                            group = Some(create(&mut groups, merged));
                            fix = true;
                        }
                    }
                }
                (None, None) => unreachable!("equal"),
            }
        }
        let group = match group {
            Some(group) => group,
            None => {
                fix = true;
                create(&mut groups, keys)
            }
        };
        if fix {
            for key in groups[group].keys.clone() {
                by_key.insert(key, group);
            }
        }
    };
    let count = tree.nodes.len();
    let mut visited = vec![false; count];
    visited[ROOT] = true;
    let mut stack = vec![(ROOT, 0usize)];
    while let Some((node, next)) = stack.last_mut() {
        let list = &tree.lists[tree.nodes[*node].children];
        let Some(&child) = list.get(*next) else {
            stack.pop();
            continue;
        };
        *next += 1;
        if !std::mem::replace(&mut visited[child], true) {
            if let Some(entry) = &tree.nodes[child].entry {
                analyze(entry);
            }
            stack.push((child, 0));
        }
    }
    (tree.nodes.iter())
        .map(|node| {
            node.entry
                .as_ref()
                .and_then(|entry| by_key.get(&entry.key).copied())
        })
        .collect()
}

struct Sorted {
    order: Vec<usize>,
    cycles: Vec<Vec<usize>>,
}

/// ConflictIdSorter: the conflict ids in topological order, parents first,
/// a cycle broken at its nearest id, and the cycles a depth-first walk
/// finds.
fn sort(tree: &Tree, ids: &[Option<usize>], mode: MavenMode) -> Sorted {
    struct Id {
        id: usize,
        children: Vec<usize>,
        in_degree: i64,
        min_depth: usize,
    }
    // Indexes into `all`, in the order first found.
    let mut all: Vec<Id> = Vec::new();
    let mut index: HashMap<usize, usize> = HashMap::new();
    let mut visited = vec![false; tree.nodes.len()];
    visited[ROOT] = true;
    let mut stack = vec![(ROOT, None::<usize>, 0usize, 0usize)];
    while let Some((node, parent, depth, next)) = stack.last_mut() {
        let list = &tree.lists[tree.nodes[*node].children];
        let Some(&child) = list.get(*next) else {
            stack.pop();
            continue;
        };
        *next += 1;
        let (parent, depth) = (*parent, *depth + 1);
        let id = ids[child].expect("a dependency has a conflict id");
        let child_id = match index.get(&id) {
            Some(&at) => {
                // Pull the id and what it leads to up to `depth`.
                let mut lift = vec![(at, depth)];
                while let Some((at, depth)) = lift.pop() {
                    if depth < all[at].min_depth {
                        all[at].min_depth = depth;
                        lift.extend(all[at].children.iter().map(|&c| (c, depth + 1)));
                    }
                }
                at
            }
            None => {
                index.insert(id, all.len());
                all.push(Id {
                    id,
                    children: Vec::new(),
                    in_degree: 0,
                    min_depth: depth,
                });
                all.len() - 1
            }
        };
        if let Some(parent) = parent
            && !all[parent].children.contains(&child_id)
        {
            all[parent].children.push(child_id);
            all[child_id].in_degree += 1;
        }
        if !std::mem::replace(&mut visited[child], true) {
            stack.push((child, Some(child_id), depth, 0));
        }
    }
    let names: Vec<i32> = all
        .iter()
        // Resolver 1.9's conflict ids are `Integer`s, 2's `String`s.
        .map(|id| match mode {
            MavenMode::Maven39 => id.id as i32,
            MavenMode::Maven310 => java_string_hash(&id.id.to_string()),
        })
        .collect();
    for id in &mut all {
        java_set_order(&mut id.children, |&child| names[child]);
    }

    let mut order = Vec::with_capacity(all.len());
    let mut roots: VecDeque<usize> = VecDeque::new();
    let add = |roots: &mut VecDeque<usize>, all: &[Id], at: usize| {
        let depth = all[at].min_depth;
        let position = roots
            .iter()
            .rposition(|&other| all[other].min_depth <= depth)
            .map_or(0, |p| p + 1);
        roots.insert(position, at);
    };
    let process = |order: &mut Vec<usize>, roots: &mut VecDeque<usize>, all: &mut Vec<Id>| {
        while let Some(at) = roots.pop_front() {
            order.push(at);
            for c in 0..all[at].children.len() {
                let child = all[at].children[c];
                all[child].in_degree -= 1;
                if all[child].in_degree == 0 {
                    add(roots, all, child);
                }
            }
        }
    };
    for at in 0..all.len() {
        if all[at].in_degree <= 0 {
            add(&mut roots, &all, at);
        }
    }
    process(&mut order, &mut roots, &mut all);
    let cyclic = order.len() < all.len();
    while order.len() < all.len() {
        let mut nearest: Option<usize> = None;
        for at in 0..all.len() {
            if all[at].in_degree <= 0 {
                continue;
            }
            if nearest.is_none_or(|n| {
                all[at].min_depth < all[n].min_depth
                    || (all[at].min_depth == all[n].min_depth
                        && all[at].in_degree < all[n].in_degree)
            }) {
                nearest = Some(at);
            }
        }
        let nearest = nearest.expect("an id is left in a cycle");
        all[nearest].in_degree = 0;
        add(&mut roots, &all, nearest);
        process(&mut order, &mut roots, &mut all);
    }

    let mut cycles = Vec::new();
    if cyclic {
        let mut visited = vec![false; all.len()];
        let mut on_stack: HashMap<usize, usize> = HashMap::new();
        for start in 0..all.len() {
            // (id, next child, whether it entered the stack)
            let mut frames: Vec<(usize, usize)> = Vec::new();
            let mut enter = Some(start);
            loop {
                if let Some(at) = enter.take() {
                    if let Some(&depth) = on_stack.get(&at) {
                        cycles.push(
                            (on_stack.iter())
                                .filter(|(_, d)| **d >= depth)
                                .map(|(id, _)| all[*id].id)
                                .collect(),
                        );
                    } else {
                        on_stack.insert(at, on_stack.len());
                        if !std::mem::replace(&mut visited[at], true) {
                            frames.push((at, 0));
                        } else {
                            on_stack.remove(&at);
                        }
                    }
                }
                let Some((at, next)) = frames.last_mut() else {
                    break;
                };
                if let Some(&child) = all[*at].children.get(*next) {
                    *next += 1;
                    enter = Some(child);
                } else {
                    on_stack.remove(at);
                    frames.pop();
                }
            }
        }
    }
    Sorted {
        order: order.into_iter().map(|at| all[at].id).collect(),
        cycles,
    }
}

/// JavaScopeDeriver.
fn derive(parent: Scope, child: Scope) -> Scope {
    match (parent, child) {
        (_, Scope::System | Scope::Test) | (Scope::Compile | Scope::Empty, _) => child,
        (Scope::Test | Scope::Runtime, _) => parent,
        (Scope::System | Scope::Provided, _) => Scope::Provided,
        (Scope::Import | Scope::CompileOnly | Scope::Other(_), _) => Scope::Runtime,
    }
}

const OPTIONAL_TRUE: u8 = 1;
const OPTIONAL_FALSE: u8 = 2;
const CHANGE_SCOPE: u8 = 1;
const CHANGE_OPTIONAL: u8 = 2;

fn optionality(optional: bool) -> u8 {
    if optional {
        OPTIONAL_TRUE
    } else {
        OPTIONAL_FALSE
    }
}

struct Item {
    /// The list the node is in.
    parent: usize,
    node: usize,
    depth: usize,
    scopes: Vec<Scope>,
    optionalities: u8,
}

struct NodeInfo {
    min_depth: usize,
    scopes: Vec<Scope>,
    optionalities: u8,
    items: Vec<usize>,
}

struct State<'t> {
    tree: &'t mut Tree,
    ids: &'t [Option<usize>],
    root_scope: Scope,
    mode: MavenMode,
    current: usize,
    resolved: HashMap<usize, Option<usize>>,
    potential: HashSet<usize>,
    items: Vec<Item>,
    infos: HashMap<usize, NodeInfo>,
    stack: HashSet<usize>,
    parent_nodes: Vec<usize>,
    parent_scopes: Vec<Scope>,
    parent_optionals: Vec<bool>,
    parent_infos: Vec<Option<usize>>,
}

impl<'t> State<'t> {
    fn new(
        tree: &'t mut Tree,
        ids: &'t [Option<usize>],
        root_scope: Scope,
        mode: MavenMode,
    ) -> Self {
        Self {
            tree,
            ids,
            root_scope,
            mode,
            current: NO_ID,
            resolved: HashMap::new(),
            potential: HashSet::new(),
            items: Vec::new(),
            infos: HashMap::new(),
            stack: HashSet::new(),
            parent_nodes: Vec::new(),
            parent_scopes: Vec::new(),
            parent_optionals: Vec::new(),
            parent_infos: Vec::new(),
        }
    }

    fn entry(&self, node: usize) -> &Entry {
        self.tree.nodes[node].entry.as_ref().expect("a dependency")
    }

    fn entry_mut(&mut self, node: usize) -> &mut Entry {
        self.tree.nodes[node].entry.as_mut().expect("a dependency")
    }

    fn prepare(&mut self, id: usize, cyclic: Option<&HashSet<usize>>) {
        self.current = id;
        self.items.clear();
        self.infos.clear();
        if let Some(cyclic) = cyclic {
            self.potential.extend(cyclic.iter().copied());
        }
    }

    fn finish(&mut self) {
        let mut previous: Option<(usize, usize)> = None;
        for at in (0..self.items.len()).rev() {
            let parent = self.items[at].parent;
            let depth = match previous {
                Some((list, depth)) if list == parent => depth,
                _ => self.infos[&parent].min_depth + 1,
            };
            previous = Some((parent, depth));
            self.items[at].depth = depth;
        }
        self.potential.insert(self.current);
    }

    /// Gather the items of the current id below `start`, cutting the losers
    /// of ids already resolved out of their lists on the way.
    fn gather(&mut self, start: usize) {
        enum Visit {
            Keep,
            Cut,
            Enter(usize),
        }
        let visit = |state: &mut Self, node: usize| {
            let id = state.ids[node];
            if id == Some(state.current) {
                state.add(node);
                Visit::Keep
            } else if id.is_some_and(
                |id| matches!(state.resolved.get(&id), Some(Some(winner)) if *winner != node),
            ) {
                Visit::Cut
            } else if state.push(node, id) {
                Visit::Enter(state.tree.nodes[node].children)
            } else {
                Visit::Keep
            }
        };
        let Visit::Enter(list) = visit(self, start) else {
            return;
        };
        let mut frames = vec![(list, 0usize)];
        while let Some(&mut (list, ref mut next)) = frames.last_mut() {
            let Some(&child) = self.tree.lists[list].get(*next) else {
                frames.pop();
                self.pop();
                continue;
            };
            match visit(self, child) {
                Visit::Keep => *next += 1,
                Visit::Cut => {
                    self.tree.lists[list].remove(*next);
                }
                Visit::Enter(child_list) => {
                    *next += 1;
                    frames.push((child_list, 0));
                }
            }
        }
    }

    fn push(&mut self, node: usize, id: Option<usize>) -> bool {
        if let Some(id) = id
            && !self.potential.contains(&id)
        {
            return false;
        }
        let list = self.tree.nodes[node].children;
        if !self.stack.insert(list) {
            return false;
        }
        let depth = self.parent_nodes.len();
        let scope = self.derive_scope(node, id);
        let optional = self.derive_optional(node, id);
        let changes = match self.infos.get_mut(&list) {
            None => {
                self.infos.insert(
                    list,
                    NodeInfo {
                        min_depth: depth,
                        scopes: vec![scope],
                        optionalities: optionality(optional),
                        items: Vec::new(),
                    },
                );
                self.parent_infos.push(Some(list));
                None
            }
            Some(info) => {
                info.min_depth = info.min_depth.min(depth);
                let mut changes = 0;
                if !info.scopes.contains(&scope) {
                    info.scopes.push(scope);
                    changes |= CHANGE_SCOPE;
                }
                if info.optionalities & optionality(optional) == 0 {
                    info.optionalities |= optionality(optional);
                    changes |= CHANGE_OPTIONAL;
                }
                if changes == 0 {
                    self.stack.remove(&list);
                    return false;
                }
                self.parent_infos.push(None);
                Some(changes)
            }
        };
        self.parent_nodes.push(node);
        self.parent_scopes.push(scope);
        self.parent_optionals.push(optional);
        if let Some(changes) = changes {
            let items = self.infos[&list].items.clone();
            if changes & CHANGE_SCOPE != 0 {
                for &item in items.iter().rev() {
                    let scope = self.derive_scope(self.items[item].node, None);
                    if !self.items[item].scopes.contains(&scope) {
                        self.items[item].scopes.push(scope);
                    }
                }
            }
            if changes & CHANGE_OPTIONAL != 0 {
                for &item in items.iter().rev() {
                    let optional = self.derive_optional(self.items[item].node, None);
                    self.items[item].optionalities |= optionality(optional);
                }
            }
        }
        true
    }

    fn pop(&mut self) {
        self.parent_infos.pop();
        self.parent_scopes.pop();
        self.parent_optionals.pop();
        if let Some(node) = self.parent_nodes.pop() {
            self.stack.remove(&self.tree.nodes[node].children);
        }
    }

    fn add(&mut self, node: usize) {
        let (Some(&parent), Some(&Some(info))) =
            (self.parent_nodes.last(), self.parent_infos.last())
        else {
            return;
        };
        let scope = self.derive_scope(node, None);
        let optional = self.derive_optional(node, None);
        self.items.push(Item {
            parent: self.tree.nodes[parent].children,
            node,
            depth: 0,
            scopes: vec![scope],
            optionalities: optionality(optional),
        });
        let item = self.items.len() - 1;
        self.infos.get_mut(&info).expect("pushed").items.push(item);
    }

    fn derive_scope(&self, node: usize, id: Option<usize>) -> Scope {
        let Some(entry) = &self.tree.nodes[node].entry else {
            return self.root_scope;
        };
        if entry.managed_scope || id.is_some_and(|id| self.resolved.contains_key(&id)) {
            return entry.scope;
        }
        match self.parent_scopes.last() {
            Some(&parent) => derive(parent, entry.scope),
            None => entry.scope,
        }
    }

    fn derive_optional(&self, node: usize, id: Option<usize>) -> bool {
        let Some(entry) = &self.tree.nodes[node].entry else {
            return false;
        };
        if entry.optional || id.is_some_and(|id| self.resolved.contains_key(&id)) {
            return entry.optional;
        }
        self.parent_optionals.last().copied().unwrap_or(false)
    }

    /// ConfigurableVersionSelector with the nearest strategy: the nearest
    /// item every hard constraint accepts, a sibling of a higher version
    /// first, going back over the candidates when a constraint rejects the
    /// winner.
    fn select_version(&self) -> Result<usize, Unsolvable> {
        let version = |item: usize| &self.entry(self.items[item].node).version;
        let better = |candidate: usize, winner: usize| {
            if self.items[candidate].parent == self.items[winner].parent {
                version(candidate)
                    .cmp_in(version(winner), self.mode)
                    .is_gt()
            } else {
                self.items[candidate].depth < self.items[winner].depth
            }
        };
        let mut constraints: Vec<&VersionReq> = Vec::new();
        let mut spellings = HashSet::new();
        let accepts = |constraints: &[&VersionReq], item: usize| {
            constraints
                .iter()
                .all(|c| c.matches_in(version(item), self.mode))
        };
        let mut candidates: Vec<usize> = Vec::new();
        let mut winner: Option<usize> = None;
        for item in 0..self.items.len() {
            let mut backtrack = false;
            // Deduplicated by spelling, as each version of a range carries
            // the range: `VersionReq` equality is Maven 3.9's, where
            // `[alpha]` and `[0]` are one constraint.
            if let Some(hard) = &self.entry(self.items[item].node).hard {
                if spellings.insert(hard.to_string()) {
                    constraints.push(hard);
                }
                backtrack = winner.is_some_and(|w| !hard.matches_in(version(w), self.mode));
            }
            let acceptable = accepts(&constraints, item);
            if acceptable {
                candidates.push(item);
            }
            if backtrack {
                let selected = winner.map(|w| self.items[w].node);
                winner = None;
                candidates.retain(|&c| accepts(&constraints, c));
                for &c in &candidates {
                    if winner.is_none_or(|w| better(c, w)) {
                        winner = Some(c);
                    }
                }
                if winner.is_none() {
                    return Err(Unsolvable {
                        node: self.items[item].node,
                        selected,
                    });
                }
            } else if acceptable && winner.is_none_or(|w| better(item, w)) {
                winner = Some(item);
            }
        }
        winner.ok_or(Unsolvable {
            node: self.items[0].node,
            selected: None,
        })
    }

    /// JavaScopeSelector.
    fn select_scope(&self, winner: usize) -> Scope {
        let own = self.entry(self.items[winner].node).scope;
        if own == Scope::System {
            return own;
        }
        let mut scopes: Vec<Scope> = Vec::new();
        for item in &self.items {
            if item.depth <= 1 {
                return derive(self.root_scope, self.entry(item.node).scope);
            }
            for scope in &item.scopes {
                if !scopes.contains(scope) {
                    scopes.push(*scope);
                }
            }
        }
        if scopes.len() > 1 {
            scopes.retain(|&scope| scope != Scope::System);
        }
        if let [scope] = scopes[..] {
            return scope;
        }
        [Scope::Compile, Scope::Runtime, Scope::Provided, Scope::Test]
            .into_iter()
            .find(|scope| scopes.contains(scope))
            .unwrap_or(Scope::Empty)
    }

    /// SimpleOptionalitySelector.
    fn select_optional(&self) -> bool {
        let mut optional = true;
        for item in &self.items {
            if item.depth <= 1 {
                return self.entry(item.node).optional;
            }
            if item.optionalities & OPTIONAL_FALSE != 0 {
                optional = false;
            }
        }
        optional
    }

    fn remove_losers(&mut self, winner: usize) {
        let mut cursor: Option<(usize, usize)> = None;
        for at in 0..self.items.len() {
            if at == winner {
                continue;
            }
            let (parent, node) = (self.items[at].parent, self.items[at].node);
            let mut next = match cursor {
                Some((list, next)) if list == parent => next,
                _ => 0,
            };
            let list = &mut self.tree.lists[parent];
            while next < list.len() {
                if list[next] == node {
                    list.remove(next);
                    break;
                }
                next += 1;
            }
            cursor = Some((parent, next));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ConflictMarker's key hash, checked against OpenJDK 27.
    #[test]
    fn conflict_key_hash() {
        let key = CoordKey {
            group_id: "g".into(),
            artifact_id: "a".into(),
            packaging: None,
            classifier: None,
        };
        // Objects.hash("a", "g", "jar", ""), and resolver 1.9's own.
        assert_eq!(key_hash(&key, MavenMode::Maven310), 7166828);
        assert_eq!(key_hash(&key, MavenMode::Maven39), 18793554);
    }
}
