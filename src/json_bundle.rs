use std::{
    cell::Cell,
    collections::BTreeMap,
    fmt,
    io::{self, Read},
    ops::Range,
    pin::Pin,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, ensure};
use axum::body::Bytes;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::Stream;
use serde::{
    Deserialize,
    de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256, Sha384};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

use crate::{
    ItemTag, MAX_DATA_ITEM_TAGS, MAX_JSON_BYTES, VerifiedItem,
    content::{Content, ContentReader},
};

const DECODE_BLOCK: usize = 64 * 1024;
type ByteStream = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;

#[derive(Debug)]
struct InvalidItem;
impl fmt::Display for InvalidItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid JSON data item")
    }
}
impl std::error::Error for InvalidItem {}

pub(crate) struct JsonBundle {
    entries: tokio::sync::mpsc::Receiver<Result<JsonEntry>>,
    cancelled: Arc<AtomicBool>,
    complete: Arc<AtomicBool>,
}

impl JsonBundle {
    pub(crate) async fn new(content: Content) -> Result<Self> {
        let bridge = tokio_util::io::SyncIoBridge::new(content.reader().await?);
        let (sender, entries) = tokio::sync::mpsc::channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&cancelled);
        let complete = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&complete);
        tokio::task::spawn_blocking(move || {
            let state = Rc::new(ParseState {
                position: Cell::new(0),
                budget: Cell::new(MAX_JSON_BYTES),
                data_prefix: Cell::new(false),
            });
            let reader = CountedReader {
                inner: io::BufReader::with_capacity(DECODE_BLOCK, bridge),
                state: Rc::clone(&state),
                cancelled: stop,
            };
            let mut decoder = serde_json::Deserializer::from_reader(reader);
            let parsed = RootSeed {
                state,
                source: content,
                sender: &sender,
            }
            .deserialize(&mut decoder)
            .and_then(|()| decoder.end());
            if let Err(error) = parsed {
                let _ = sender.blocking_send(Err(error.into()));
            } else {
                done.store(true, Ordering::Release);
            }
        });
        Ok(Self {
            entries,
            cancelled,
            complete,
        })
    }

    pub(crate) async fn next(&mut self) -> Result<Option<JsonEntry>> {
        match self.entries.recv().await {
            Some(entry) => entry.map(Some),
            None => {
                ensure!(
                    self.complete.load(Ordering::Acquire),
                    "JSON parser stopped before validating bundle framing"
                );
                Ok(None)
            }
        }
    }
}

impl Drop for JsonBundle {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

struct ParseState {
    position: Cell<usize>,
    budget: Cell<usize>,
    data_prefix: Cell<bool>,
}

struct CountedReader<R> {
    inner: R,
    state: Rc<ParseState>,
    cancelled: Arc<AtomicBool>,
}

impl<R: Read> Read for CountedReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(io::Error::other("JSON bundle read cancelled"));
        }
        let limit = bytes.len().min(self.state.budget.get());
        if limit == 0 && !bytes.is_empty() {
            return Err(io::Error::other("JSON item metadata exceeds size limit"));
        }
        let read = self.inner.read(&mut bytes[..limit])?;
        self.state.position.set(self.state.position.get() + read);
        self.state.budget.set(self.state.budget.get() - read);
        if self.state.data_prefix.get() {
            if let Some(byte) = bytes[..read].iter().find(|b| !b.is_ascii_whitespace()) {
                self.state.data_prefix.set(false);
                if *byte == b'"' {
                    // IgnoredAny skips this string without buffering its contents.
                    self.state.budget.set(usize::MAX);
                }
            }
        }
        Ok(read)
    }
}

struct RootSeed<'a> {
    state: Rc<ParseState>,
    source: Content,
    sender: &'a tokio::sync::mpsc::Sender<Result<JsonEntry>>,
}

impl<'de> DeserializeSeed<'de> for RootSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<(), D::Error> {
        decoder.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for RootSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON bundle object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        let mut found = false;
        while let Some(key) = map.next_key::<String>()? {
            if key == "items" {
                if found {
                    return Err(serde::de::Error::duplicate_field("items"));
                }
                found = true;
                map.next_value_seed(ItemsSeed {
                    state: Rc::clone(&self.state),
                    source: self.source.clone(),
                    sender: self.sender,
                })?;
                self.state.budget.set(MAX_JSON_BYTES);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        if !found {
            return Err(serde::de::Error::missing_field("items"));
        }
        Ok(())
    }
}

struct ItemsSeed<'a> {
    state: Rc<ParseState>,
    source: Content,
    sender: &'a tokio::sync::mpsc::Sender<Result<JsonEntry>>,
}

impl<'de> DeserializeSeed<'de> for ItemsSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<(), D::Error> {
        decoder.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for ItemsSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON bundle items array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        loop {
            self.state.budget.set(MAX_JSON_BYTES);
            let Some(entry) = seq.next_element_seed(EntrySeed {
                state: Rc::clone(&self.state),
                source: self.source.clone(),
            })?
            else {
                break;
            };
            self.sender
                .blocking_send(Ok(entry))
                .map_err(serde::de::Error::custom)?;
        }
        Ok(())
    }
}

struct EntrySeed {
    state: Rc<ParseState>,
    source: Content,
}
struct EntryVisitor {
    state: Rc<ParseState>,
}
#[derive(Default)]
struct Fields {
    offset: usize,
    values: BTreeMap<String, Box<RawValue>>,
    data: Option<Range<usize>>,
    invalid: bool,
}

impl<'de> DeserializeSeed<'de> for EntrySeed {
    type Value = JsonEntry;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<JsonEntry, D::Error> {
        let fields = decoder.deserialize_any(EntryVisitor {
            state: Rc::clone(&self.state),
        })?;
        let end = self.state.position.get();
        let id = fields
            .values
            .get("id")
            .and_then(|v| serde_json::from_str::<String>(v.get()).ok())
            .and_then(|id| crate::decode_fixed(&id, "JSON item ID").ok());
        let offset = fields.offset;
        Ok(JsonEntry {
            offset,
            size: end.saturating_sub(offset),
            id,
            source: self.source,
            fields,
        })
    }
}

impl<'de> Visitor<'de> for EntryVisitor {
    type Value = Fields;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON data item")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Fields, A::Error> {
        // deserialize_map has consumed the opening brace at this point.
        let mut fields = Fields {
            offset: self.state.position.get() - 1,
            ..Fields::default()
        };
        while let Some(key) = map.next_key::<String>()? {
            if key == "data" {
                fields.invalid |= fields.data.is_some();
                fields.data = Some(map.next_value_seed(DataSeed {
                    state: Rc::clone(&self.state),
                })?);
            } else if matches!(
                key.as_str(),
                "id" | "owner" | "target" | "nonce" | "tags" | "signature"
            ) {
                let value = map.next_value::<Box<RawValue>>()?;
                fields.invalid |= fields.values.insert(key, value).is_some();
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(fields)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Fields, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Fields {
            invalid: true,
            ..Fields::default()
        })
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<Fields, E> {
        Ok(Fields {
            invalid: true,
            ..Fields::default()
        })
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<Fields, E> {
        Ok(Fields {
            invalid: true,
            ..Fields::default()
        })
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<Fields, E> {
        Ok(Fields {
            invalid: true,
            ..Fields::default()
        })
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<Fields, E> {
        Ok(Fields {
            invalid: true,
            ..Fields::default()
        })
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<Fields, E> {
        Ok(Fields {
            invalid: true,
            ..Fields::default()
        })
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Fields, E> {
        Ok(Fields {
            invalid: true,
            ..Fields::default()
        })
    }
}

struct DataSeed {
    state: Rc<ParseState>,
}
impl<'de> DeserializeSeed<'de> for DataSeed {
    type Value = Range<usize>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        let start = self.state.position.get();
        let budget = self.state.budget.get();
        self.state.data_prefix.set(true);
        let result = IgnoredAny::deserialize(decoder);
        self.state.budget.set(budget);
        self.state.data_prefix.set(false);
        result?;
        Ok(start..self.state.position.get())
    }
}

pub(crate) struct JsonEntry {
    pub(crate) offset: usize,
    pub(crate) size: usize,
    pub(crate) id: Option<[u8; 32]>,
    source: Content,
    fields: Fields,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonTag {
    name: String,
    value: String,
}

impl JsonEntry {
    pub(crate) async fn verify(self) -> Result<Option<VerifiedItem>> {
        if self.fields.invalid || self.id.is_none() || self.fields.data.is_none() {
            return Ok(None);
        }
        let parsed = (|| -> Result<_> {
            let string = |name: &str| -> Result<String> {
                let raw = self
                    .fields
                    .values
                    .get(name)
                    .with_context(|| format!("missing JSON item {name}"))?;
                Ok(serde_json::from_str(raw.get())?)
            };
            let owner = crate::decode_b64(&string("owner")?, "JSON owner")?;
            let signature = crate::decode_b64(&string("signature")?, "JSON signature")?;
            let target = crate::decode_b64(&string("target")?, "JSON target")?;
            let anchor = match self.fields.values.get("nonce") {
                Some(raw) => {
                    crate::decode_b64(&serde_json::from_str::<String>(raw.get())?, "JSON nonce")?
                }
                None => Vec::new(),
            };
            ensure!(
                !owner.is_empty()
                    && owner.len() <= 1025
                    && !signature.is_empty()
                    && signature.len() <= 2052,
                "invalid JSON RSA key or signature size"
            );
            let id = self.id.expect("checked item ID");
            ensure!(
                crate::sha256(&[&signature]) == id,
                "JSON item signature hash differs from ID"
            );
            let raw = self
                .fields
                .values
                .get("tags")
                .context("missing JSON tags")?;
            let encoded: Vec<JsonTag> = serde_json::from_str(raw.get())?;
            ensure!(
                encoded.len() <= MAX_DATA_ITEM_TAGS,
                "too many JSON item tags"
            );
            let mut tags = Vec::with_capacity(encoded.len());
            for tag in encoded {
                let name = crate::decode_b64(&tag.name, "JSON tag name")?;
                let value = crate::decode_b64(&tag.value, "JSON tag value")?;
                ensure!(
                    !name.is_empty()
                        && name.len() <= 1024
                        && !value.is_empty()
                        && value.len() <= 3072,
                    "invalid JSON tag size"
                );
                tags.push(ItemTag {
                    name: Bytes::from(name),
                    value: Bytes::from(value),
                });
            }
            Ok((owner, signature, target, anchor, tags))
        })();
        let Ok((owner, signature, target, anchor, tags)) = parsed else {
            return Ok(None);
        };
        let span = self.fields.data.expect("checked data field");
        let mut start = span.start;
        while start < span.end {
            let bytes = self
                .source
                .read_at(start, (span.end - start).min(DECODE_BLOCK))
                .await?;
            let skipped = bytes.iter().take_while(|b| b.is_ascii_whitespace()).count();
            start += skipped;
            if skipped < bytes.len() {
                break;
            }
        }
        if start >= span.end
            || self.source.read_at(start, 1).await?[0] != b'"'
            || self.source.read_at(span.end - 1, 1).await?[0] != b'"'
        {
            return Ok(None);
        }
        let data_offset = start + 1 - self.offset;
        let encoded = self.source.slice(start + 1..span.end - 1)?;
        let (source, body_hash, sha384) = match Base64Data::scan(encoded).await {
            Ok(data) => data,
            Err(error) if error.is::<InvalidItem>() => return Ok(None),
            Err(error) => return Err(error),
        };
        let data_hash = crate::sha384(&[
            &crate::sha384(&[format!("blob{}", source.len).as_bytes()]),
            &sha384,
        ]);
        let tag_hashes: Vec<_> = tags
            .iter()
            .map(|t| {
                crate::deep_hash_list(&[
                    crate::deep_hash_blob(&t.name),
                    crate::deep_hash_blob(&t.value),
                ])
            })
            .collect();
        let payload = crate::deep_hash_list(&[
            crate::deep_hash_blob(b"dataitem"),
            crate::deep_hash_blob(b"1"),
            crate::deep_hash_blob(&owner),
            crate::deep_hash_blob(&target),
            crate::deep_hash_blob(&anchor),
            crate::deep_hash_list(&tag_hashes),
            data_hash,
        ]);
        let checked = crate::cpu_work(move || {
            Ok(
                crate::verify_rsa_pss(&owner, &signature, &payload, "JSON item")
                    .is_ok()
                    .then_some((owner, signature)),
            )
        })
        .await?;
        let Some((owner, signature)) = checked else {
            return Ok(None);
        };
        Ok(Some(VerifiedItem {
            data: Content::decoded_base64(Arc::new(source)),
            data_offset,
            item_size: self.size,
            body_hash,
            signature_type: 1,
            signature: Bytes::from(signature),
            owner: Bytes::from(owner),
            target: Bytes::from(target),
            anchor: Bytes::from(anchor),
            tags,
        }))
    }
}

#[derive(Debug)]
pub(crate) struct Base64Data {
    encoded: Content,
    checkpoints: Arc<Vec<(usize, usize)>>,
    pub(crate) len: usize,
}

impl Base64Data {
    async fn scan(encoded: Content) -> Result<(Self, [u8; 32], [u8; 48])> {
        let mut decoder = Decoder {
            reader: BufReader::with_capacity(DECODE_BLOCK, encoded.reader().await?),
            raw_position: 0,
        };
        let mut checkpoints = vec![(0, 0)];
        let stride = encoded.len().div_ceil(4096).max(DECODE_BLOCK);
        let mut next_checkpoint = stride;
        let mut len = 0usize;
        let mut hashers = (Sha256::new(), Sha384::new());
        while let Some(bytes) = decoder.next().await? {
            len = len
                .checked_add(bytes.len())
                .context("decoded JSON size overflow")?;
            hashers = crate::cpu_work(move || {
                hashers.0.update(&bytes);
                hashers.1.update(&bytes);
                Ok(hashers)
            })
            .await?;
            if decoder.raw_position >= next_checkpoint {
                checkpoints.push((decoder.raw_position, len));
                next_checkpoint = decoder.raw_position.saturating_add(stride);
            }
        }
        Ok((
            Self {
                encoded,
                checkpoints: Arc::new(checkpoints),
                len,
            },
            hashers.0.finalize().into(),
            hashers.1.finalize().into(),
        ))
    }

    pub(crate) fn resident_len(&self) -> usize {
        self.encoded
            .resident_len()
            .saturating_add(self.checkpoints.capacity() * std::mem::size_of::<(usize, usize)>())
    }

    pub(crate) async fn with_gateway(&self, gateway: &crate::Gateway) -> Self {
        Self {
            encoded: Box::pin(self.encoded.with_gateway(gateway)).await,
            checkpoints: Arc::clone(&self.checkpoints),
            len: self.len,
        }
    }

    pub(crate) async fn stream(self: Arc<Self>, offset: usize, len: usize) -> Result<ByteStream> {
        let index = self
            .checkpoints
            .partition_point(|(_, decoded)| *decoded <= offset)
            .saturating_sub(1);
        let (raw, decoded) = self.checkpoints[index];
        let content = self.encoded.slice(raw..self.encoded.len())?;
        let reader = Box::pin(content.reader()).await?;
        let state = (
            Decoder {
                reader: BufReader::with_capacity(DECODE_BLOCK, reader),
                raw_position: 0,
            },
            offset - decoded,
            len,
            self,
        );
        Ok(Box::pin(futures_util::stream::try_unfold(
            state,
            |(mut decoder, mut skip, remaining, source)| async move {
                if remaining == 0 {
                    return Ok(None);
                }
                loop {
                    let bytes =
                        decoder
                            .next()
                            .await
                            .map_err(io::Error::other)?
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "truncated decoded JSON payload",
                                )
                            })?;
                    if skip >= bytes.len() {
                        skip -= bytes.len();
                        continue;
                    }
                    let count = (bytes.len() - skip).min(remaining);
                    let bytes = bytes.slice(skip..skip + count);
                    return Ok(Some((bytes, (decoder, 0, remaining - count, source))));
                }
            },
        )))
    }
}

struct Decoder {
    reader: BufReader<ContentReader>,
    raw_position: usize,
}

impl Decoder {
    async fn next(&mut self) -> Result<Option<Bytes>> {
        let mut encoded = Vec::with_capacity(DECODE_BLOCK);
        while encoded.len() < DECODE_BLOCK {
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                break;
            }
            let count = available
                .iter()
                .position(|b| *b == b'\\')
                .unwrap_or(available.len())
                .min(DECODE_BLOCK - encoded.len());
            if count > 0 {
                encoded.extend_from_slice(&available[..count]);
                self.reader.consume(count);
                self.raw_position += count;
                continue;
            }
            self.reader.consume(1);
            self.raw_position += 1;
            let escaped = self.reader.read_u8().await?;
            self.raw_position += 1;
            let byte = match escaped {
                b'u' => {
                    let mut digits = [0; 4];
                    self.reader.read_exact(&mut digits).await?;
                    self.raw_position += 4;
                    let mut value = 0u16;
                    for digit in digits {
                        value = value * 16
                            + match digit {
                                b'0'..=b'9' => u16::from(digit - b'0'),
                                b'a'..=b'f' => u16::from(digit - b'a' + 10),
                                b'A'..=b'F' => u16::from(digit - b'A' + 10),
                                _ => return Err(InvalidItem.into()),
                            };
                    }
                    u8::try_from(value).map_err(|_| InvalidItem)?
                }
                b'"' | b'\\' | b'/' => escaped,
                b'b' => 8,
                b'f' => 12,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                _ => return Err(InvalidItem.into()),
            };
            encoded.push(byte);
        }
        if encoded.is_empty() {
            return Ok(None);
        }
        let bytes = URL_SAFE_NO_PAD.decode(&encoded).map_err(|_| InvalidItem)?;
        Ok(Some(Bytes::from(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{ContentWriter, SpoolBudget};

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/json-bundle-434410.json");
    const ITEM_ID: &str = "Fo4czsdeHnVizyMKi8mqMHfu7vu29IG9GdlXaM9dYfg";

    #[test]
    fn concurrent_json_roots_leave_blocking_capacity_for_verification() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(crate::background::BLOCKING_THREADS)
            .build()?;
        runtime.block_on(crate::BACKGROUND_CPU.scope((), async {
            let fixture: serde_json::Value = serde_json::from_slice(FIXTURE)?;
            let item = &fixture["items"][0];
            let expected = crate::decode_b64(item["data"].as_str().unwrap(), "fixture data")?;
            let expected_hash = crate::sha256(&[&expected]);
            let bytes = serde_json::to_vec(&serde_json::json!({"items": [item, item, item]}))?;
            let work = async {
                let mut ancestors = Vec::new();
                for _ in 0..2 * crate::MAX_BUNDLE_DEPTH {
                    let mut ancestor = JsonBundle::new(bytes.clone().into()).await?;
                    ancestor.next().await?.context("missing ancestor item")?;
                    ancestors.push(ancestor);
                }
                let mut first = JsonBundle::new(bytes.clone().into()).await?;
                let mut second = JsonBundle::new(bytes.into()).await?;
                let first_entry = first.next().await?.context("missing first root item")?;
                let second_entry = second.next().await?.context("missing second root item")?;
                let verify = |mut bundle: JsonBundle, entry: JsonEntry| async move {
                    let mut next = Some(entry);
                    let mut count = 0;
                    while let Some(entry) = next {
                        let item = entry.verify().await?.context("valid item rejected")?;
                        assert_eq!(item.body_hash, expected_hash);
                        count += 1;
                        next = bundle.next().await?;
                    }
                    assert_eq!(count, 3);
                    Ok::<_, anyhow::Error>(())
                };
                tokio::try_join!(verify(first, first_entry), verify(second, second_entry))?;
                drop(ancestors);
                Ok::<_, anyhow::Error>(())
            };
            tokio::time::timeout(std::time::Duration::from_secs(3), work)
                .await
                .context("concurrent JSON parsers blocked verification")?
        }))
    }

    #[tokio::test]
    async fn historical_json_signature_and_escaped_payload() -> Result<()> {
        let fixture: serde_json::Value = serde_json::from_slice(FIXTURE)?;
        let encoded = fixture["items"][0]["data"].as_str().unwrap();
        let expected = crate::decode_b64(encoded, "fixture data")?;
        let reordered: serde_json::Map<_, _> = fixture["items"][0]
            .as_object()
            .unwrap()
            .iter()
            .rev()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let encoded_json = serde_json::to_string(&serde_json::json!({"items": [reordered]}))?;
        let escaped_prefix: String = encoded[..24]
            .bytes()
            .map(|b| format!("\\u{b:04x}"))
            .collect();
        let escaped = encoded_json.replacen(encoded, &(escaped_prefix + &encoded[24..]), 1);
        for bytes in [FIXTURE.to_vec(), escaped.into_bytes()] {
            let mut bundle = JsonBundle::new(bytes.clone().into()).await?;
            let entry = bundle
                .next()
                .await?
                .context("missing historical JSON item")?;
            assert_eq!(entry.id, Some(crate::decode_fixed(ITEM_ID, "fixture ID")?));
            assert_eq!(bytes[entry.offset], b'{');
            assert_eq!(bytes[entry.offset + entry.size - 1], b'}');
            let item = entry
                .verify()
                .await?
                .context("historical JSON signature rejected")?;
            assert_eq!(
                item.data.read_all(expected.len()).await?.as_ref(),
                expected.as_slice()
            );
            assert_eq!(item.body_hash, crate::sha256(&[&expected]));
            assert_eq!(
                item.text_tag(b"Content-Type").as_deref(),
                Some("application/x-bittorrent")
            );
            assert!(bundle.next().await?.is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn invalid_json_item_is_discarded_without_losing_valid_sibling() -> Result<()> {
        let fixture: serde_json::Value = serde_json::from_slice(FIXTURE)?;
        let valid = fixture["items"][0].clone();
        let mut corrupt = valid.clone();
        corrupt["data"] = serde_json::Value::String("Y29ycnVwdA".into());
        let document = serde_json::to_vec(&serde_json::json!({"items": [corrupt, valid]}))?;
        let mut bundle = JsonBundle::new(document.into()).await?;
        assert!(bundle.next().await?.unwrap().verify().await?.is_none());
        assert!(bundle.next().await?.unwrap().verify().await?.is_some());
        assert!(bundle.next().await?.is_none());

        let mut truncated = JsonBundle::new(FIXTURE[..FIXTURE.len() - 1].to_vec().into()).await?;
        assert!(truncated.next().await?.is_some());
        assert!(truncated.next().await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn decoded_file_content_preserves_slices_and_hashes() -> Result<()> {
        let expected: Vec<_> = (0..DECODE_BLOCK * 5 + 7).map(|i| (i % 251) as u8).collect();
        let encoded = URL_SAFE_NO_PAD.encode(&expected);
        let escaped = encoded.replace('A', "\\u0041");
        let budget = Arc::new(SpoolBudget::new(escaped.len()));
        let mut writer = ContentWriter::new(escaped.len(), 0, budget).await?;
        writer.write(escaped.as_bytes()).await?;
        let (file, _) = writer.finish().await?;
        let (source, hash, _) = Base64Data::scan(file).await?;
        assert_eq!(hash, crate::sha256(&[&expected]));
        let content = Content::decoded_base64(Arc::new(source));
        for range in [
            0..1,
            2..DECODE_BLOCK + 3,
            DECODE_BLOCK * 4 + 1..expected.len(),
            expected.len()..expected.len(),
        ] {
            let view = content.slice(range.clone())?;
            assert_eq!(
                view.read_all(view.len()).await?.as_ref(),
                &expected[range.clone()]
            );
            assert_eq!(view.hashes().await?.0, crate::sha256(&[&expected[range]]));
        }
        Ok(())
    }

    #[tokio::test]
    async fn large_payload_skipping_keeps_metadata_limit() -> Result<()> {
        let bytes = format!(
            "{{\"items\":[{{\"data\":\"{}\"}}]}}",
            "A".repeat(MAX_JSON_BYTES * 2)
        )
        .into_bytes();
        let mut bundle = JsonBundle::new(bytes.into()).await?;
        assert!(bundle.next().await?.unwrap().verify().await?.is_none());
        assert!(bundle.next().await?.is_none());
        let bytes = format!(
            "{{\"items\":[{{\"data\":[\"{}\"]}}]}}",
            "A".repeat(MAX_JSON_BYTES * 2)
        )
        .into_bytes();
        let mut bundle = JsonBundle::new(bytes.into()).await?;
        assert!(bundle.next().await.is_err());
        Ok(())
    }
}
