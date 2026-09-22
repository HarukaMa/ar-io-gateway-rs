use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_RANGE, RANGE};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::atomic::AtomicUsize;

use crate::{Bytes, Gateway};

pub(crate) const PAGE_SIZE: usize = 25;
const MAX_ITEMS: usize = 262_144;
const MAX_TABLE_BYTES: usize = MAX_ITEMS * 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InspectionRequest {
    pub id: String,
    #[serde(default)]
    pub start: usize,
    pub item: Option<usize>,
    #[serde(default)]
    pub unindexed: bool,
}

pub(crate) fn tags_json(tags: impl Iterator<Item = (Vec<u8>, Vec<u8>)>) -> Value {
    Value::Array(
        tags.map(|(name, value)| {
            json!({
                "name": String::from_utf8_lossy(&name),
                "value": String::from_utf8_lossy(&value),
                "name_base64": URL_SAFE_NO_PAD.encode(&name),
                "value_base64": URL_SAFE_NO_PAD.encode(&value),
            })
        })
        .collect(),
    )
}

pub(crate) async fn inspect(gateway: &Gateway, request: &InspectionRequest) -> Result<Value> {
    let id = crate::decode_fixed::<32>(&request.id, "bundle ID")?;
    ensure!(
        request.start < MAX_ITEMS && request.item.is_none_or(|i| i < MAX_ITEMS),
        "Inspection position exceeds the 262144-item limit"
    );
    if !request.unindexed {
        if let Some(store) = &gateway.block_store {
            let reader = store
                .reconnect()
                .await
                .context("Index connection unavailable")?;
            if let Some(page) = reader
                .inspect_bundle(&id, request.start)
                .await
                .context("Index inspection unavailable")?
            {
                return Ok(page);
            }
        }
        if let Some(item) = discover_item(gateway, &request.id).await? {
            return Ok(
                json!({"id": request.id, "source": "unverified", "kind": "item",
                "has_more": false, "items": [item]}),
            );
        }
    }
    let client = reqwest::Client::builder()
        .timeout(gateway.config.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let source = RangeReader {
        client,
        url: crate::endpoint(&gateway.config.archive_url, &format!("raw/{}", request.id)),
        remaining: AtomicUsize::new(MAX_TABLE_BYTES + 32 + crate::MAX_DATA_ITEM_HEADER_BYTES),
    };
    let (count_bytes, total) = source.read(0, 32, None).await?;
    let count = integer(&count_bytes)?;
    ensure!(
        count <= MAX_ITEMS as u128,
        "Not a supported binary bundle, or its table exceeds the 262144-item inspection limit. JSON bundles cannot be inspected with header-only reads."
    );
    let count = count as usize;
    let end = request
        .item
        .map_or(request.start.saturating_add(PAGE_SIZE).min(count), |i| {
            i + 1
        });
    ensure!(
        request.start <= count && end <= count,
        "Item position is outside the bundle"
    );
    let table_end = 32 + count as u128 * 64;
    ensure!(
        table_end <= total,
        "Bundle table exceeds the upstream content size"
    );
    let table = if end == 0 {
        Bytes::new()
    } else {
        source.read(32, end * 64, Some(total)).await?.0
    };
    let mut offset = table_end;
    let mut items = Vec::new();
    for (index, entry) in table.chunks_exact(64).enumerate() {
        let size = integer(&entry[..32])?;
        let next = offset.checked_add(size).context("Bundle offset overflow")?;
        ensure!(size > 0 && next <= total, "Invalid bundle item bounds");
        if request
            .item
            .map_or(index >= request.start, |wanted| index == wanted)
        {
            let mut item = json!({"index": index, "id": URL_SAFE_NO_PAD.encode(&entry[32..]),
                "item_offset": offset.to_string(), "item_size": size.to_string(), "source": "unverified"});
            if request.item.is_some() {
                let details = read_header(&source, offset, size, total).await?;
                item.as_object_mut()
                    .unwrap()
                    .extend(details.as_object().unwrap().clone());
            }
            items.push(item);
        }
        offset = next;
    }
    if end == count {
        ensure!(
            offset == total,
            "Bundle table sizes do not match the upstream content size"
        );
    }
    Ok(
        json!({"id": request.id, "source": "unverified", "format": "binary", "total": count,
        "start": request.start, "has_more": end < count, "items": items}),
    )
}

async fn discover_item(gateway: &Gateway, id: &str) -> Result<Option<Value>> {
    let mut without_parent = None;
    for source in gateway
        .config
        .graphql_sources
        .iter()
        .take(crate::MAX_GRAPHQL_SOURCES)
    {
        let response = gateway.request_json::<Value>(gateway.client.post(source).json(&json!({
            "query": "query($ids: [ID!]!) { transactions(ids: $ids, first: 1) { edges { node { id owner { address key } recipient tags { name value } data { size } bundledIn { id } } } } }",
            "variables": {"ids": [id]},
        }))).await;
        let Ok(response) = response else {
            continue;
        };
        let Some(node) = response.pointer("/data/transactions/edges/0/node") else {
            continue;
        };
        ensure!(
            node["id"].as_str() == Some(id),
            "External index returned a different item ID"
        );
        let tags = node["tags"]
            .as_array()
            .context("External item tags are unavailable")?;
        ensure!(
            tags.len() <= crate::MAX_DATA_ITEM_TAGS,
            "External item tag count exceeds limit"
        );
        let pairs = tags
            .iter()
            .map(|tag| {
                Ok((
                    tag["name"]
                        .as_str()
                        .context("Invalid external tag name")?
                        .as_bytes()
                        .to_vec(),
                    tag["value"]
                        .as_str()
                        .context("Invalid external tag value")?
                        .as_bytes()
                        .to_vec(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        if crate::BundleFormat::from_pairs(pairs.iter().map(|(n, v)| (n.as_slice(), v.as_slice())))
            .is_ok()
        {
            return Ok(None);
        }
        let size = node["data"]["size"]
            .as_str()
            .context("External item size is unavailable")?;
        let size = crate::parse_u128(size, "external item size")?;
        let parent = node["bundledIn"]["id"].as_str().filter(|id| !id.is_empty());
        if let Some(parent) = parent {
            crate::decode_fixed::<32>(parent, "external parent bundle ID")?;
            ensure!(parent != id, "External item is its own parent");
        }
        let item = json!({
            "id": id, "source": "unverified", "metadata_source": "external_index",
            "owner": node["owner"]["key"], "owner_address": node["owner"]["address"],
            "target": node["recipient"], "data_size": size.to_string(), "parent_id": parent,
            "tags": tags_json(pairs.into_iter()),
        });
        if parent.is_some() {
            return Ok(Some(item));
        }
        without_parent.get_or_insert(item);
    }
    if without_parent.is_some() {
        return Ok(without_parent);
    }
    if let Ok(tags) = gateway
        .get_json::<Vec<crate::Tag>>(&gateway.config.archive_url, &format!("tx/{id}/tags"))
        .await
    {
        if crate::require_bundle_tags(&tags).is_ok() {
            return Ok(None);
        }
    }
    anyhow::bail!(
        "Metadata unavailable from the configured indexes. Cannot identify this ID as an item or bundle without reading its payload."
    )
}

fn integer(bytes: &[u8]) -> Result<u128> {
    ensure!(
        bytes.len() == 32 && bytes[16..].iter().all(|b| *b == 0),
        "Unsupported binary bundle integer"
    );
    Ok(u128::from_le_bytes(bytes[..16].try_into()?))
}

struct RangeReader {
    client: reqwest::Client,
    url: String,
    remaining: AtomicUsize,
}

impl RangeReader {
    async fn read(
        &self,
        offset: u128,
        length: usize,
        total: Option<u128>,
    ) -> Result<(Bytes, u128)> {
        ensure!(length > 0, "Empty range");
        let end = offset
            .checked_add(length as u128 - 1)
            .context("Range overflow")?;
        ensure!(
            total.is_none_or(|total| end < total),
            "Header exceeds item bounds"
        );
        let response = self
            .client
            .get(&self.url)
            .header(RANGE, format!("bytes={offset}-{end}"))
            .header(ACCEPT_ENCODING, "identity")
            .send()
            .await
            .context("Upstream range request failed")?;
        ensure!(
            response.status() == reqwest::StatusCode::PARTIAL_CONTENT,
            "Upstream did not return a byte range (206). Full downloads are disabled."
        );
        ensure!(
            response
                .headers()
                .get(CONTENT_ENCODING)
                .is_none_or(|v| v == "identity"),
            "Encoded range responses are unsupported"
        );
        let range = response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .context("Missing Content-Range")?;
        let (bounds, size) = range
            .strip_prefix("bytes ")
            .and_then(|r| r.split_once('/'))
            .context("Invalid Content-Range")?;
        let size: u128 = size.parse().context("Invalid range content size")?;
        ensure!(
            bounds == format!("{offset}-{end}")
                && size > end
                && total.is_none_or(|total| total == size),
            "Upstream returned inconsistent byte ranges"
        );
        let body = crate::read_response_body_with_limit(response, length, &self.remaining, None)
            .await
            .context("Invalid range response body")?;
        ensure!(body.len() == length, "Truncated range response");
        Ok((body.into(), size))
    }
}

async fn read_header(source: &RangeReader, offset: u128, size: u128, total: u128) -> Result<Value> {
    // Exact field-sized reads avoid pulling payload bytes even for tiny headers.
    let mut cursor = 0usize;
    async fn field(
        source: &RangeReader,
        offset: u128,
        size: u128,
        total: u128,
        cursor: &mut usize,
        length: usize,
    ) -> Result<Bytes> {
        ensure!(
            (*cursor as u128) + length as u128 <= size,
            "Truncated item header"
        );
        if length == 0 {
            return Ok(Bytes::new());
        }
        let bytes = source
            .read(offset + *cursor as u128, length, Some(total))
            .await?
            .0;
        *cursor += length;
        Ok(bytes)
    }
    let prefix = field(source, offset, size, total, &mut cursor, 2).await?;
    let signature_type = u16::from_le_bytes(prefix[..].try_into()?);
    let (signature_size, owner_size) = crate::data_item_signature_sizes(signature_type).context(
        "Unsupported item header. Header-only inspection requires a typed ANS-104 item.",
    )?;
    let fixed = field(
        source,
        offset,
        size,
        total,
        &mut cursor,
        signature_size + owner_size + 1,
    )
    .await?;
    let owner = &fixed[signature_size..signature_size + owner_size];
    let target_present = fixed[fixed.len() - 1];
    ensure!(target_present <= 1, "Invalid target presence flag");
    let target_field = field(
        source,
        offset,
        size,
        total,
        &mut cursor,
        usize::from(target_present) * 32 + 1,
    )
    .await?;
    let anchor_present = target_field[target_field.len() - 1];
    ensure!(anchor_present <= 1, "Invalid anchor presence flag");
    let lengths = field(
        source,
        offset,
        size,
        total,
        &mut cursor,
        usize::from(anchor_present) * 32 + 16,
    )
    .await?;
    let lengths_offset = usize::from(anchor_present) * 32;
    let count = u64::from_le_bytes(lengths[lengths_offset..lengths_offset + 8].try_into()?);
    let length = u64::from_le_bytes(lengths[lengths_offset + 8..].try_into()?);
    ensure!(
        count <= crate::MAX_DATA_ITEM_TAGS as u64
            && length <= crate::MAX_DATA_ITEM_TAG_BYTES as u64,
        "Item tags exceed inspection limits"
    );
    let tags = field(source, offset, size, total, &mut cursor, length as usize).await?;
    let tags = crate::parse_avro_tags(&tags, count as usize)?;
    let nested =
        crate::BundleFormat::from_pairs(tags.iter().map(|t| (t.name.as_ref(), t.value.as_ref())))
            .ok();
    Ok(
        json!({"signature_type": signature_type, "owner": URL_SAFE_NO_PAD.encode(owner),
        "signature": URL_SAFE_NO_PAD.encode(&fixed[..signature_size]),
        "target": URL_SAFE_NO_PAD.encode(&target_field[..target_field.len()-1]),
        "anchor": URL_SAFE_NO_PAD.encode(&lengths[..lengths_offset]),
        "data_offset": cursor.to_string(), "data_size": (size - cursor as u128).to_string(),
        "bundle": nested.is_some(), "tags": tags_json(tags.into_iter().map(|t| (t.name.to_vec(), t.value.to_vec())))}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    #[tokio::test]
    async fn pages_and_headers_never_request_payloads() {
        let payload = vec![42; 1024];
        let (mut item, _) =
            crate::tests::signed_data_item(&payload, &[(b"Content-Type", b"text/plain")]);
        item[2] ^= 1;
        let item_len = item.len();
        let header_len = item.len() - payload.len();
        let bundle = Arc::new(crate::tests::encode_bundle(&vec![item.as_slice(); 27]));
        let table_end = 32 + 27 * 64;
        let reads = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(get({
            let bundle = bundle.clone();
            let reads = reads.clone();
            move |headers: HeaderMap| {
                let bundle = bundle.clone();
                let reads = reads.clone();
                async move {
                    let (start, end) = headers["range"]
                        .to_str()
                        .unwrap()
                        .strip_prefix("bytes=")
                        .unwrap()
                        .split_once('-')
                        .unwrap();
                    let (start, end): (usize, usize) =
                        (start.parse().unwrap(), end.parse().unwrap());
                    reads.lock().unwrap().push((start, end));
                    assert!(
                        end < table_end
                            || ((start - table_end) / item_len == (end - table_end) / item_len
                                && (end - table_end) % item_len < header_len),
                        "payload requested"
                    );
                    (
                        StatusCode::PARTIAL_CONTENT,
                        [(
                            "content-range",
                            format!("bytes {start}-{end}/{}", bundle.len()),
                        )],
                        bundle[start..=end].to_vec(),
                    )
                        .into_response()
                }
            }
        }));
        let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap()
        }));
        let gateway = Gateway::new(
            crate::Config::new(
                &url,
                &url,
                vec![url.clone()],
                Duration::from_secs(5),
                1,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let mut request = InspectionRequest {
            id: URL_SAFE_NO_PAD.encode([7; 32]),
            start: 0,
            item: None,
            unindexed: true,
        };
        let first = inspect(&gateway, &request).await.unwrap();
        assert_eq!(first["items"].as_array().unwrap().len(), 25);
        assert_eq!(first["has_more"], true);
        assert!(
            reads
                .lock()
                .unwrap()
                .iter()
                .all(|(_, end)| *end < table_end)
        );
        request.start = 25;
        let last = inspect(&gateway, &request).await.unwrap();
        assert_eq!(last["items"][0]["index"], 25);
        assert_eq!(last["items"].as_array().unwrap().len(), 2);
        assert_eq!(last["has_more"], false);
        request.item = Some(26);
        let detail = inspect(&gateway, &request).await.unwrap();
        assert_eq!(detail["items"][0]["data_size"], "1024");
        assert_eq!(detail["items"][0]["source"], "unverified");
        assert_eq!(detail["items"][0]["tags"][0]["value"], "text/plain");
        assert_eq!(detail["items"][0]["data_offset"], header_len.to_string());
    }

    #[tokio::test]
    async fn item_lookup_uses_metadata_without_requesting_payloads() {
        let id = URL_SAFE_NO_PAD.encode([7; 32]);
        let parent = URL_SAFE_NO_PAD.encode([8; 32]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let response = json!({"data":{"transactions":{"edges":[{"node":{
            "id":id, "owner":{"address":"owner","key":""}, "recipient":"",
            "tags":[{"name":"Content-Type","value":"text/plain"}],
            "data":{"size":"1024"}, "bundledIn":{"id":parent},
        }}]}}});
        let mut missing_parent = response.clone();
        missing_parent["data"]["transactions"]["edges"][0]["node"]["bundledIn"]["id"] = json!("");
        let app = Router::new()
            .route(
                "/graphql",
                axum::routing::post(move || {
                    let response = response.clone();
                    async move { axum::Json(response) }
                }),
            )
            .route(
                "/missing-parent",
                axum::routing::post(move || {
                    let response = missing_parent.clone();
                    async move { axum::Json(response) }
                }),
            )
            .fallback(forbidden_payload);
        async fn forbidden_payload() -> StatusCode {
            panic!("item lookup attempted a payload request")
        }
        let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap()
        }));
        let mut gateway = Gateway::new(
            crate::Config::new(
                &url,
                &url,
                vec![url.clone()],
                Duration::from_secs(5),
                1,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        gateway
            .config
            .graphql_sources
            .insert(0, format!("{url}/missing-parent"));
        let request = InspectionRequest {
            id: id.clone(),
            start: 0,
            item: None,
            unindexed: false,
        };
        let result = inspect(&gateway, &request).await.unwrap();
        assert_eq!(result["kind"], "item");
        assert_eq!(result["items"][0]["parent_id"], parent);
        assert_eq!(result["items"][0]["source"], "unverified");
        assert_eq!(result["items"][0]["data_size"], "1024");
        gateway.config.graphql_sources.pop();
        let missing = inspect(&gateway, &request).await.unwrap();
        assert!(missing["items"][0]["parent_id"].is_null());
        assert_eq!(missing["items"][0]["data_size"], "1024");
        let wrong = InspectionRequest {
            id: URL_SAFE_NO_PAD.encode([9; 32]),
            ..request
        };
        assert!(inspect(&gateway, &wrong).await.is_err());
    }

    #[tokio::test]
    async fn refuses_full_downloads_and_wrong_ranges() {
        for (status, range, body) in [
            (StatusCode::OK, "bytes 0-31/100", vec![0; 32]),
            (StatusCode::PARTIAL_CONTENT, "bytes 1-32/100", vec![0; 32]),
            (StatusCode::PARTIAL_CONTENT, "bytes 0-31/100", vec![0; 33]),
            (StatusCode::PARTIAL_CONTENT, "bytes 0-31/100", vec![0; 31]),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let app = Router::new().fallback(get(move || {
                let body = body.clone();
                async move { (status, [("content-range", range)], body) }
            }));
            let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap()
            }));
            let source = RangeReader {
                client: reqwest::Client::new(),
                url,
                remaining: AtomicUsize::new(32),
            };
            assert!(source.read(0, 32, None).await.is_err());
        }
    }
}
