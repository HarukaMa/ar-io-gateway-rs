//! `ANS104_INDEX_FILTER`: which verified bundle items are written to the index.
//!
//! Follows upstream r85 filter JSON (`always`, `never`, `not`, `and`, `or`, `tags`,
//! `attributes.owner_address`) plus `blockHeight` with inclusive `min`/`max`, which
//! upstream lacks because its attributes only compare for equality.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::database::ObjectMetadata;

#[derive(Clone, Debug)]
pub struct IndexFilter {
    rule: Rule,
    source: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Rule {
    Always,
    Never,
    Not(Box<Rule>),
    And(Vec<Rule>),
    Or(Vec<Rule>),
    Tags(Vec<TagMatch>),
    Owner([u8; 32]),
    BlockHeight { min: u64, max: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TagMatch {
    name: Vec<u8>,
    value: TagValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TagValue {
    Any,
    Exact(Vec<u8>),
    Prefix(Vec<u8>),
}

impl Default for IndexFilter {
    fn default() -> Self {
        Self {
            rule: Rule::Always,
            source: serde_json::json!({"always": true}),
        }
    }
}

impl IndexFilter {
    pub fn parse(text: &str) -> Result<Self> {
        let source: Value = serde_json::from_str(text).context("filter is not JSON")?;
        let rule = parse_rule(&source, 0)?;
        Ok(Self { rule, source })
    }

    /// The configured JSON, as advertised in gateway info.
    pub fn source(&self) -> &Value {
        &self.source
    }

    pub fn is_never(&self) -> bool {
        self.rule == Rule::Never
    }

    pub(crate) fn matches(&self, item: &ObjectMetadata, height: u64) -> bool {
        self.rule.matches(item, height)
    }
}

const MAX_DEPTH: usize = 16;

fn parse_rule(value: &Value, depth: usize) -> Result<Rule> {
    ensure!(depth <= MAX_DEPTH, "filter nesting exceeds {MAX_DEPTH}");
    let object = value.as_object().context("filter must be a JSON object")?;
    ensure!(object.len() == 1, "filter object must have exactly one key");
    let (key, inner) = object.iter().next().unwrap();
    let list = |inner: &Value| -> Result<Vec<Rule>> {
        let items = inner
            .as_array()
            .with_context(|| format!("{key} must be an array"))?;
        ensure!(!items.is_empty(), "{key} must not be empty");
        items
            .iter()
            .map(|item| parse_rule(item, depth + 1))
            .collect()
    };
    Ok(match key.as_str() {
        "always" => {
            ensure!(inner == &Value::Bool(true), "always must be true");
            Rule::Always
        }
        "never" => {
            ensure!(inner == &Value::Bool(true), "never must be true");
            Rule::Never
        }
        "not" => Rule::Not(Box::new(parse_rule(inner, depth + 1)?)),
        "and" => Rule::And(list(inner)?),
        "or" => Rule::Or(list(inner)?),
        "tags" => {
            let tags = inner.as_array().context("tags must be an array")?;
            ensure!(!tags.is_empty(), "tags must not be empty");
            Rule::Tags(tags.iter().map(parse_tag).collect::<Result<_>>()?)
        }
        "attributes" => {
            let attributes = inner.as_object().context("attributes must be an object")?;
            ensure!(
                attributes.len() == 1 && attributes.contains_key("owner_address"),
                "only the owner_address attribute is supported"
            );
            let address = attributes["owner_address"]
                .as_str()
                .context("owner_address must be a string")?;
            let bytes = URL_SAFE_NO_PAD
                .decode(address)
                .context("owner_address must be base64url")?;
            Rule::Owner(
                bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("owner_address must be 32 bytes"))?,
            )
        }
        "blockHeight" => {
            let range = inner.as_object().context("blockHeight must be an object")?;
            ensure!(
                !range.is_empty() && range.keys().all(|key| key == "min" || key == "max"),
                "blockHeight takes min and/or max"
            );
            let bound = |name: &str, default: u64| -> Result<u64> {
                range.get(name).map_or(Ok(default), |value| {
                    value.as_u64().with_context(|| {
                        format!("blockHeight.{name} must be a non-negative integer")
                    })
                })
            };
            let (min, max) = (bound("min", 0)?, bound("max", u64::MAX)?);
            ensure!(min <= max, "blockHeight.min exceeds max");
            Rule::BlockHeight { min, max }
        }
        other => bail!("unsupported filter key {other}"),
    })
}

fn parse_tag(value: &Value) -> Result<TagMatch> {
    let tag = value.as_object().context("tag filter must be an object")?;
    let text = |name: &str| -> Result<Option<Vec<u8>>> {
        tag.get(name)
            .map(|value| {
                value
                    .as_str()
                    .map(|text| text.as_bytes().to_vec())
                    .with_context(|| format!("tag {name} must be a string"))
            })
            .transpose()
    };
    ensure!(
        tag.keys()
            .all(|key| matches!(key.as_str(), "name" | "value" | "valueStartsWith")),
        "tag filter takes name, value, or valueStartsWith"
    );
    let name = text("name")?.context("tag filter needs a name")?;
    let value = match (text("value")?, text("valueStartsWith")?) {
        (None, None) => TagValue::Any,
        (Some(value), None) => TagValue::Exact(value),
        (None, Some(prefix)) => TagValue::Prefix(prefix),
        (Some(_), Some(_)) => bail!("tag filter takes value or valueStartsWith, not both"),
    };
    Ok(TagMatch { name, value })
}

impl Rule {
    fn matches(&self, item: &ObjectMetadata, height: u64) -> bool {
        match self {
            Rule::Always => true,
            Rule::Never => false,
            Rule::Not(rule) => !rule.matches(item, height),
            Rule::And(rules) => rules.iter().all(|rule| rule.matches(item, height)),
            Rule::Or(rules) => rules.iter().any(|rule| rule.matches(item, height)),
            // Upstream semantics: every listed tag must be matched by some item tag.
            Rule::Tags(wanted) => wanted.iter().all(|wanted| {
                item.tags.iter().any(|(name, value)| {
                    *name == wanted.name
                        && match &wanted.value {
                            TagValue::Any => true,
                            TagValue::Exact(expected) => value == expected,
                            TagValue::Prefix(prefix) => value.starts_with(prefix),
                        }
                })
            }),
            Rule::Owner(address) => item.owner_address == address,
            Rule::BlockHeight { min, max } => (*min..=*max).contains(&height),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REDSTONE: &str = "I-5rWUehEv-MjdK9gFw09RxfSLQX9DIHxG614Wf8qo0";

    fn item(owner: &str, tags: &[(&str, &str)]) -> ObjectMetadata {
        ObjectMetadata {
            id: vec![7; 32],
            kind: 1,
            signature: Vec::new(),
            anchor: Vec::new(),
            owner_address: URL_SAFE_NO_PAD.decode(owner).unwrap(),
            owner_public_key: Vec::new(),
            target: Vec::new(),
            data_size: 0,
            content_type: None,
            content_encoding: None,
            signature_type: 1,
            format: None,
            quantity: None,
            reward: None,
            denomination: None,
            data_root: None,
            tags: tags
                .iter()
                .map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec()))
                .collect(),
        }
    }

    fn redstone_filter() -> IndexFilter {
        IndexFilter::parse(&format!(
            r#"{{"not":{{"and":[
                {{"attributes":{{"owner_address":"{REDSTONE}"}}}},
                {{"tags":[{{"name":"type","value":"redstone-oracles"}}]}},
                {{"blockHeight":{{"max":1870999}}}}
            ]}}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn skips_only_tagged_redstone_items_below_the_cutoff() {
        let filter = redstone_filter();
        let oracle = item(
            REDSTONE,
            &[("type", "redstone-oracles"), ("dataServiceId", "x")],
        );
        assert!(!filter.matches(&oracle, 1_755_000));
        assert!(!filter.matches(&oracle, 1_870_999));
        assert!(filter.matches(&oracle, 1_871_000));
        assert!(filter.matches(&item(REDSTONE, &[("type", "other")]), 1_755_000));
        let other_owner = "fcoN_xJeisVsPXA-trzVAuIiqO3ydLQxM-L4XbrQKzY";
        assert!(filter.matches(
            &item(other_owner, &[("type", "redstone-oracles")]),
            1_755_000
        ));
    }

    #[test]
    fn follows_upstream_tag_semantics() {
        let filter = IndexFilter::parse(
            r#"{"tags":[{"name":"App-Name","value":"A"},{"name":"Content-Type","valueStartsWith":"image/"},{"name":"X"}]}"#,
        )
        .unwrap();
        let owner = "fcoN_xJeisVsPXA-trzVAuIiqO3ydLQxM-L4XbrQKzY";
        assert!(filter.matches(
            &item(
                owner,
                &[("App-Name", "A"), ("Content-Type", "image/png"), ("X", "")]
            ),
            0
        ));
        assert!(!filter.matches(
            &item(owner, &[("App-Name", "A"), ("Content-Type", "image/png")]),
            0
        ));
        assert!(!filter.matches(
            &item(
                owner,
                &[("app-name", "A"), ("Content-Type", "image/png"), ("X", "")]
            ),
            0
        ));
    }

    #[test]
    fn rejects_unsupported_or_malformed_filters() {
        for bad in [
            r#"{"isNestedBundle":true}"#,
            r#"{"attributes":{"data_size":1}}"#,
            r#"{"attributes":{"owner_address":"short"}}"#,
            r#"{"blockHeight":{"min":5,"max":4}}"#,
            r#"{"blockHeight":{"below":4}}"#,
            r#"{"tags":[{"name":"a","value":"b","valueStartsWith":"c"}]}"#,
            r#"{"and":[]}"#,
            r#"{"always":true,"never":true}"#,
            r#"{"never":false}"#,
        ] {
            assert!(IndexFilter::parse(bad).is_err(), "{bad} was accepted");
        }
        assert!(IndexFilter::parse(r#"{"never":true}"#).unwrap().is_never());
    }
}
