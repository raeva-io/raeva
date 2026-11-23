//! A plugin's `<configuration>`, kept as the element tree plexus-utils'
//! `Xpp3Dom` holds, and merged as `Xpp3Dom.mergeXpp3Dom` merges it.

use std::collections::{HashMap, VecDeque};

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, Visitor};

/// The `combine.children` attribute: `append` puts the recessive children
/// first and the dominant ones after them, instead of merging them by name.
const CHILDREN_MODE: &str = "combine.children";
/// The `combine.self` attribute: `override` keeps the dominant element as it
/// is, and `remove` on a child drops it where it meets a recessive one.
const SELF_MODE: &str = "combine.self";
/// How deep a `<configuration>` may nest. Maven sets no bound; real
/// configurations nest a few levels, and the merge, interpolation and drop
/// of a tree recurse once per level.
pub(crate) const MAX_DEPTH: usize = 64;

/// An element of a plugin `<configuration>`, with its attributes, its text
/// and its child elements in document order. The text is trimmed, as Maven
/// reads it, and kept only for an element without children.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfigNode {
    /// The element name, without a namespace prefix. Empty for the
    /// `<configuration>` element itself.
    pub name: String,
    /// The attributes, in document order.
    pub attributes: Vec<(String, String)>,
    /// The trimmed text of an element without child elements; `None` for
    /// an empty element.
    pub value: Option<String>,
    /// The child elements, in document order.
    pub children: Vec<ConfigNode>,
}

impl ConfigNode {
    /// The value of the attribute `name`.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The first child element named `name`.
    pub fn child(&self, name: &str) -> Option<&ConfigNode> {
        self.children.iter().find(|child| child.name == name)
    }

    /// The trimmed text of the first child element named `name`.
    pub fn child_value(&self, name: &str) -> Option<&str> {
        self.child(name).and_then(|child| child.value.as_deref())
    }

    /// Merge `recessive` into this dominant element as plexus-utils 3.6.0's
    /// `Xpp3Dom.mergeXpp3Dom` does, which Maven 3.9 applies to plugin and
    /// execution configurations.
    ///
    /// Unless this element says `combine.self="override"`, an empty value
    /// and absent attributes take the recessive ones, and children merge by
    /// name: the n-th dominant child of a name merges with the n-th
    /// recessive child of that name, a recessive child whose name the
    /// dominant element lacks is appended, and recessive children past the
    /// dominant ones of their name are dropped. With
    /// `combine.children="append"` the recessive children come first,
    /// unmerged, then the dominant ones. A dominant child marked
    /// `combine.self="remove"` is dropped where it meets a recessive child.
    pub(crate) fn merge_from(&mut self, recessive: &ConfigNode) {
        self.merge_inner(recessive, None);
    }

    fn merge_inner(&mut self, recessive: &ConfigNode, child_merge: Option<bool>) {
        if self.attribute(SELF_MODE) == Some("override") {
            return;
        }
        if is_empty(self.value.as_deref()) && !is_empty(recessive.value.as_deref()) {
            self.value.clone_from(&recessive.value);
        }
        for (key, value) in &recessive.attributes {
            match self.attributes.iter_mut().find(|(own, _)| own == key) {
                Some((_, own)) if is_empty(Some(own)) => own.clone_from(value),
                Some(_) => {}
                None => self.attributes.push((key.clone(), value.clone())),
            }
        }
        if recessive.children.is_empty() {
            return;
        }
        let merge_children =
            child_merge.unwrap_or_else(|| self.attribute(CHILDREN_MODE) != Some("append"));
        if !merge_children {
            let dominant = std::mem::take(&mut self.children);
            self.children = recessive.children.clone();
            self.children.extend(dominant);
            return;
        }
        // The n-th recessive child of a name pairs with the n-th dominant
        // child of that name; a name the dominant element lacks is appended.
        let mut own: HashMap<String, VecDeque<usize>> = HashMap::new();
        for (index, child) in self.children.iter().enumerate() {
            own.entry(child.name.clone()).or_default().push_back(index);
        }
        let mut removed = vec![false; self.children.len()];
        let mut appended = Vec::new();
        for recessive_child in &recessive.children {
            match own.get_mut(&recessive_child.name) {
                None => appended.push(recessive_child.clone()),
                Some(indexes) => {
                    let Some(index) = indexes.pop_front() else {
                        continue;
                    };
                    let dominant_child = &mut self.children[index];
                    if dominant_child.attribute(SELF_MODE) == Some("remove") {
                        removed[index] = true;
                    } else {
                        dominant_child.merge_inner(recessive_child, child_merge);
                    }
                }
            }
        }
        if removed.contains(&true) {
            let mut removed = removed.into_iter();
            self.children.retain(|_| !removed.next().unwrap_or(false));
        }
        self.children.extend(appended);
    }

    /// Apply `interpolate` to every attribute value and element text that
    /// holds an expression.
    pub(crate) fn interpolate_with<E>(
        &mut self,
        interpolate: &mut impl FnMut(&str) -> Result<String, E>,
    ) -> Result<(), E> {
        for (_, value) in &mut self.attributes {
            if value.contains("${") {
                *value = interpolate(value)?;
            }
        }
        if let Some(value) = &mut self.value
            && value.contains("${")
        {
            *value = interpolate(value)?;
        }
        for child in &mut self.children {
            child.interpolate_with(interpolate)?;
        }
        Ok(())
    }
}

/// `Xpp3Dom.isEmpty` of plexus-utils 3.6.0: absent or blank.
fn is_empty(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim_matches(|c| c <= ' ').is_empty())
}

impl<'de> serde::Deserialize<'de> for ConfigNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        NodeVisitor { depth: 0 }.deserialize(deserializer)
    }
}

/// Reads an element as quick-xml presents it to `deserialize_any`: a map of
/// `@name` attributes, `$text` runs and child elements under their names,
/// in document order, or a bare string for an element holding only text.
#[derive(Clone, Copy)]
struct NodeVisitor {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for NodeVisitor {
    type Value = ConfigNode;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<ConfigNode, D::Error> {
        if self.depth > MAX_DEPTH {
            return Err(de::Error::custom(format!(
                "a plugin configuration nests deeper than {MAX_DEPTH} elements"
            )));
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = ConfigNode;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a configuration element")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
        Ok(ConfigNode {
            value: Some(text.trim_matches(|c| c <= ' ').to_string()),
            ..ConfigNode::default()
        })
    }

    fn visit_string<E: de::Error>(self, text: String) -> Result<Self::Value, E> {
        self.visit_str(&text)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(ConfigNode::default())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut node = ConfigNode::default();
        let mut text = String::new();
        while let Some(key) = map.next_key::<String>()? {
            if key == "$text" || key == "$value" {
                text.push_str(&map.next_value::<String>()?);
            } else if let Some(attribute) = key.strip_prefix('@') {
                let value: String = map.next_value()?;
                node.attributes.push((attribute.to_string(), value));
            } else {
                let mut child = map.next_value_seed(NodeVisitor {
                    depth: self.depth + 1,
                })?;
                child.name = key;
                node.children.push(child);
            }
        }
        if node.children.is_empty() && !text.is_empty() {
            node.value = Some(text.trim_matches(|c| c <= ' ').to_string());
        }
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Holder {
        configuration: ConfigNode,
    }

    fn try_config(xml: &str) -> Result<ConfigNode, quick_xml::DeError> {
        let holder: Holder = quick_xml::de::from_str(&format!(
            "<plugin><configuration>{xml}</configuration></plugin>"
        ))?;
        Ok(holder.configuration)
    }

    fn config(xml: &str) -> ConfigNode {
        try_config(xml).unwrap()
    }

    /// The text of each element named `name` below `node`, in document
    /// order, as `name=value`.
    fn texts(node: &ConfigNode) -> Vec<String> {
        let mut out = Vec::new();
        fn walk(node: &ConfigNode, path: &str, out: &mut Vec<String>) {
            for child in &node.children {
                let path = format!("{path}/{}", child.name);
                if let Some(value) = &child.value {
                    out.push(format!("{path}={value}"));
                }
                walk(child, &path, out);
            }
        }
        walk(node, "", &mut out);
        out
    }

    #[test]
    fn reads_elements_attributes_and_text_in_order() {
        let node = config(
            "<release>17</release><compilerArgs combine.children='append'><arg> -Xlint </arg>\
             <arg>-parameters</arg></compilerArgs><empty/><release>18</release>",
        );
        assert_eq!(
            texts(&node),
            [
                "/release=17",
                "/compilerArgs/arg=-Xlint",
                "/compilerArgs/arg=-parameters",
                "/release=18"
            ]
        );
        let args = node.child("compilerArgs").unwrap();
        assert_eq!(args.attribute("combine.children"), Some("append"));
        assert_eq!(node.child("empty").unwrap().value, None);
    }

    /// Children merge by name and position; the recessive side fills only
    /// what the dominant side leaves empty and appends names it lacks, and
    /// its extra children of a shared name are dropped.
    #[test]
    fn merges_children_by_name_and_position() {
        let mut dominant =
            config("<paths><path><groupId>a</groupId></path></paths><release>17</release><skip/>");
        let recessive = config(
            "<paths><path><groupId>x</groupId><version>1</version></path>\
             <path><groupId>y</groupId></path></paths><skip>true</skip><debug>true</debug>",
        );
        dominant.merge_from(&recessive);
        assert_eq!(
            texts(&dominant),
            [
                "/paths/path/groupId=a",
                "/paths/path/version=1",
                "/release=17",
                "/skip=true",
                "/debug=true"
            ]
        );
    }

    #[test]
    fn combine_attributes_change_the_merge() {
        let recessive = config("<paths><path>p</path><path>q</path></paths>");
        let mut append = config("<paths combine.children='append'><path>c</path></paths>");
        append.merge_from(&recessive);
        assert_eq!(
            texts(&append),
            ["/paths/path=p", "/paths/path=q", "/paths/path=c"]
        );

        let mut keep = config("<paths combine.self='override'><path>c</path></paths>");
        keep.merge_from(&recessive);
        assert_eq!(texts(&keep), ["/paths/path=c"]);

        let mut remove = config("<paths><path combine.self='remove'/></paths><x>1</x>");
        remove.merge_from(&recessive);
        assert_eq!(texts(&remove), ["/x=1"]);
        assert!(remove.child("paths").unwrap().children.is_empty());
    }

    /// Hostile nesting fails the read instead of the stack.
    #[test]
    fn nesting_is_bounded() {
        let nested = |depth: usize| format!("{}x{}", "<a>".repeat(depth), "</a>".repeat(depth));
        assert!(try_config(&nested(MAX_DEPTH)).is_ok());
        let error = try_config(&nested(100_000)).unwrap_err().to_string();
        assert!(error.contains("nests deeper than 64"), "{error}");
    }

    /// Blank counts as empty, as in `Xpp3Dom.isEmpty`; a dominant child of
    /// many recessive names merges in one pass.
    #[test]
    fn blank_values_take_the_recessive_ones() {
        let mut dominant = config("<a k=' '> </a><b k='1'/>");
        dominant.merge_from(&config("<a k='r'>v</a><b k='2'/>"));
        let a = dominant.child("a").unwrap();
        assert_eq!(
            (a.value.as_deref(), a.attribute("k")),
            (Some("v"), Some("r"))
        );
        assert_eq!(dominant.child("b").unwrap().attribute("k"), Some("1"));

        let names = |prefix: &str| -> String {
            (0..20_000)
                .map(|n| format!("<{prefix}{n}>1</{prefix}{n}>"))
                .collect()
        };
        let mut wide = config(&names("d"));
        wide.merge_from(&config(&names("r")));
        assert_eq!(wide.children.len(), 40_000);
    }
}
