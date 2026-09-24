use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_graphql::{
    Context, EmptyMutation, EmptySubscription, Enum, ID, InputObject, MaybeUndefined, Object,
    SimpleObject,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query as QueryParams, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::TryStreamExt;
use serde::Deserialize;
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard, Semaphore};
use tokio_postgres::{NoTls, Row, types::ToSql};

use super::BlockStore;

const MAX_PAGE: usize = 1000;
const MAX_RESULT_BYTES: usize = 16 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
type Schema = async_graphql::Schema<QueryRoot, EmptyMutation, EmptySubscription>;
type GqlResult<T> = async_graphql::Result<T>;

struct Service {
    schema: Schema,
    source: Option<Arc<BlockStore>>,
    permits: Semaphore,
}

pub(crate) fn router<S: Clone + Send + Sync + 'static>(
    source: Option<Arc<BlockStore>>,
) -> Router<S> {
    let service = Arc::new(Service {
        schema: schema(),
        source,
        permits: Semaphore::new(4),
    });
    Router::new()
        .route("/graphql", get(get_query).post(post_query))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(service)
}

fn schema() -> Schema {
    Schema::build(QueryRoot, EmptyMutation, EmptySubscription)
        .limit_depth(16)
        .limit_recursive_depth(32)
        .limit_complexity(20_000)
        .finish()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetQuery {
    query: String,
    operation_name: Option<String>,
    variables: Option<String>,
}

async fn get_query(
    State(service): State<Arc<Service>>,
    QueryParams(input): QueryParams<GetQuery>,
) -> Response {
    if input.query.len() + input.variables.as_ref().map_or(0, String::len) > 64 * 1024 {
        return failure(
            StatusCode::PAYLOAD_TOO_LARGE,
            "GraphQL request exceeds size limit",
        );
    }
    let mut request = async_graphql::Request::new(input.query);
    if let Some(name) = input.operation_name {
        request = request.operation_name(name);
    }
    if let Some(variables) = input.variables {
        let Ok(value @ serde_json::Value::Object(_)) = serde_json::from_str(&variables) else {
            return failure(
                StatusCode::BAD_REQUEST,
                "GraphQL variables must be a JSON object",
            );
        };
        request = request.variables(async_graphql::Variables::from_json(value));
    }
    execute(service, request).await
}

async fn post_query(
    State(service): State<Arc<Service>>,
    input: Result<Json<async_graphql::Request>, axum::extract::rejection::JsonRejection>,
) -> Response {
    match input {
        Ok(Json(request)) => execute(service, request).await,
        Err(error) => failure(
            if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            },
            "Invalid GraphQL JSON request",
        ),
    }
}

fn failure(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({"errors": [{"message": message}]})),
    )
        .into_response()
}

async fn execute(service: Arc<Service>, request: async_graphql::Request) -> Response {
    let Ok(_permit) = service.permits.try_acquire() else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "GraphQL request capacity exhausted",
        );
    };
    let db = Arc::new(RequestDb {
        source: service.source.clone(),
        connection: Mutex::new(None),
        remaining_bytes: AtomicUsize::new(MAX_RESULT_BYTES),
    });
    match tokio::time::timeout(REQUEST_TIMEOUT, service.schema.execute(request.data(db))).await {
        Ok(response) => {
            let status = if !response.errors.is_empty()
                && response.errors.iter().all(|error| error.path.is_empty())
            {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::OK
            };
            (status, Json(response)).into_response()
        }
        Err(_) => failure(StatusCode::GATEWAY_TIMEOUT, "GraphQL request timed out"),
    }
}

struct RequestDb {
    source: Option<Arc<BlockStore>>,
    connection: Mutex<Option<BlockStore>>,
    remaining_bytes: AtomicUsize,
}

impl RequestDb {
    fn consume(&self, bytes: usize) -> GqlResult<()> {
        self.remaining_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                left.checked_sub(bytes)
            })
            .map(|_| ())
            .map_err(|_| async_graphql::Error::new("GraphQL result exceeds size limit"))
    }

    async fn store(&self) -> GqlResult<MappedMutexGuard<'_, BlockStore>> {
        let mut guard = self.connection.lock().await;
        if guard.is_none() {
            let source = self
                .source
                .as_ref()
                .ok_or_else(|| async_graphql::Error::new("GraphQL requires an indexed database"))?;
            let store = source.reconnect().await.map_err(database_error)?;
            store
                .client
                .batch_execute(
                    "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
                 SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s';
                 SET LOCAL work_mem='16MB'; SET LOCAL max_parallel_workers_per_gather=0;",
                )
                .await
                .map_err(database_error)?;
            *guard = Some(store);
        }
        Ok(MutexGuard::map(guard, |store| store.as_mut().unwrap()))
    }
}

impl Drop for RequestDb {
    fn drop(&mut self) {
        if let Some(store) = self.connection.get_mut() {
            let cancel = store.client.cancel_token();
            tokio::spawn(async move {
                let _ =
                    tokio::time::timeout(Duration::from_secs(5), cancel.cancel_query(NoTls)).await;
            });
        }
    }
}

fn database_error(error: impl std::fmt::Display) -> async_graphql::Error {
    eprintln!("GraphQL database query failed: {error}");
    async_graphql::Error::new("GraphQL database query failed")
}

#[derive(Enum, Copy, Clone, Eq, PartialEq, Default)]
#[graphql(name = "SortOrder")]
enum SortOrder {
    HeightAsc,
    #[default]
    HeightDesc,
}

impl SortOrder {
    fn sql(self) -> &'static str {
        if self == Self::HeightAsc {
            "ASC"
        } else {
            "DESC"
        }
    }
    fn comparison(self) -> &'static str {
        if self == Self::HeightAsc { ">" } else { "<" }
    }
}

#[derive(Enum, Copy, Clone, Eq, PartialEq, Default)]
enum TagOperator {
    #[default]
    Eq,
}

#[derive(InputObject)]
struct TagFilter {
    name: String,
    values: Vec<String>,
    #[graphql(default_with = "Some(TagOperator::Eq)")]
    op: Option<TagOperator>,
}

#[derive(InputObject, Default)]
struct BlockFilter {
    min: Option<i32>,
    max: Option<i32>,
}

#[derive(SimpleObject)]
struct PageInfo {
    has_next_page: bool,
}
#[derive(SimpleObject)]
struct TransactionConnection {
    page_info: PageInfo,
    edges: Vec<TransactionEdge>,
}
#[derive(SimpleObject)]
struct TransactionEdge {
    cursor: String,
    node: Transaction,
}
#[derive(SimpleObject)]
struct BlockConnection {
    page_info: PageInfo,
    edges: Vec<BlockEdge>,
}
#[derive(SimpleObject)]
struct BlockEdge {
    cursor: String,
    node: Block,
}
#[derive(SimpleObject, Clone)]
struct Block {
    id: ID,
    timestamp: i32,
    height: i32,
    previous: ID,
}
#[derive(SimpleObject)]
struct Tag {
    name: String,
    value: String,
}
#[derive(SimpleObject)]
struct Amount {
    winston: String,
    ar: String,
}
#[derive(SimpleObject)]
struct MetaData {
    size: String,
    r#type: Option<String>,
}
#[derive(SimpleObject)]
struct Parent {
    id: ID,
}
#[derive(SimpleObject)]
struct Bundle {
    id: ID,
}
struct Owner {
    address: String,
    key: Option<String>,
}
#[Object]
impl Owner {
    async fn address(&self) -> &str {
        &self.address
    }
    async fn key(&self) -> GqlResult<&str> {
        self.key
            .as_deref()
            .ok_or_else(|| async_graphql::Error::new("Owner public key is not indexed"))
    }
}
#[derive(SimpleObject)]
struct Transaction {
    id: ID,
    anchor: Option<String>,
    signature: String,
    signature_type: Option<i32>,
    recipient: String,
    owner: Owner,
    fee: Amount,
    quantity: Amount,
    data: MetaData,
    tags: Vec<Tag>,
    block: Option<Block>,
    #[graphql(deprecation = "Use `bundledIn`")]
    parent: Option<Parent>,
    bundled_in: Option<Bundle>,
}

struct QueryRoot;

#[Object(name = "Query")]
impl QueryRoot {
    async fn transaction(&self, ctx: &Context<'_>, id: ID) -> GqlResult<Option<Transaction>> {
        let page = transactions(
            ctx,
            TransactionFilter {
                ids: vec![id],
                first: 1,
                ..Default::default()
            },
            ctx.look_ahead().field("tags").exists(),
        )
        .await?;
        Ok(page.edges.into_iter().next().map(|edge| edge.node))
    }

    #[allow(clippy::too_many_arguments)]
    #[graphql(complexity = "first.unwrap_or(10).clamp(0, 1000) as usize * child_complexity + 1")]
    async fn transactions(
        &self,
        ctx: &Context<'_>,
        ids: Option<Vec<ID>>,
        owners: Option<Vec<String>>,
        recipients: Option<Vec<String>>,
        tags: Option<Vec<TagFilter>>,
        bundled_in: MaybeUndefined<Vec<ID>>,
        block: Option<BlockFilter>,
        #[graphql(default = 10)] first: Option<i32>,
        after: Option<String>,
        #[graphql(default_with = "Some(SortOrder::HeightDesc)")] sort: Option<SortOrder>,
        #[graphql(deprecation = "Use `bundledIn`")] parent: MaybeUndefined<Vec<ID>>,
    ) -> GqlResult<TransactionConnection> {
        let bundled_in = if matches!(bundled_in, MaybeUndefined::Undefined) {
            parent
        } else {
            bundled_in
        };
        transactions(
            ctx,
            TransactionFilter {
                ids: ids.unwrap_or_default(),
                owners: owners.unwrap_or_default(),
                recipients: recipients.unwrap_or_default(),
                tags: tags.unwrap_or_default(),
                bundled_in,
                block: block.unwrap_or_default(),
                first: page_size(first)?,
                after,
                sort: sort.unwrap_or_default(),
            },
            ctx.look_ahead()
                .field("edges")
                .field("node")
                .field("tags")
                .exists(),
        )
        .await
    }

    async fn block(&self, ctx: &Context<'_>, id: String) -> GqlResult<Option<Block>> {
        let page = blocks(
            ctx,
            vec![ID(id)],
            BlockFilter::default(),
            1,
            None,
            SortOrder::HeightDesc,
        )
        .await?;
        Ok(page.edges.into_iter().next().map(|edge| edge.node))
    }

    #[graphql(complexity = "first.unwrap_or(10).clamp(0, 1000) as usize * child_complexity + 1")]
    async fn blocks(
        &self,
        ctx: &Context<'_>,
        ids: Option<Vec<ID>>,
        height: Option<BlockFilter>,
        #[graphql(default = 10)] first: Option<i32>,
        after: Option<String>,
        #[graphql(default_with = "Some(SortOrder::HeightDesc)")] sort: Option<SortOrder>,
    ) -> GqlResult<BlockConnection> {
        blocks(
            ctx,
            ids.unwrap_or_default(),
            height.unwrap_or_default(),
            page_size(first)?,
            after,
            sort.unwrap_or_default(),
        )
        .await
    }
}

fn page_size(first: Option<i32>) -> GqlResult<usize> {
    let first = first.unwrap_or(10);
    if first < 0 {
        return Err("first must be non-negative".into());
    }
    Ok((first as usize).min(MAX_PAGE))
}

#[derive(Default)]
struct TransactionFilter {
    ids: Vec<ID>,
    owners: Vec<String>,
    recipients: Vec<String>,
    tags: Vec<TagFilter>,
    bundled_in: MaybeUndefined<Vec<ID>>,
    block: BlockFilter,
    first: usize,
    after: Option<String>,
    sort: SortOrder,
}

struct Sql {
    text: String,
    parameters: Vec<Box<dyn ToSql + Sync + Send>>,
}
impl Sql {
    fn new(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            parameters: Vec::new(),
        }
    }
    fn bind(&mut self, value: impl ToSql + Sync + Send + 'static) -> String {
        self.parameters.push(Box::new(value));
        format!("${}", self.parameters.len())
    }
    fn filter(&mut self, clause: impl AsRef<str>) {
        self.text.push_str(" AND ");
        self.text.push_str(clause.as_ref());
    }
    fn params(&self) -> Vec<&(dyn ToSql + Sync)> {
        self.parameters
            .iter()
            .map(|v| &**v as &(dyn ToSql + Sync))
            .collect()
    }
    fn heights(&mut self, column: &str, bounds: BlockFilter) {
        if let Some(min) = bounds.min.filter(|v| *v >= 0) {
            let p = self.bind(i64::from(min));
            self.filter(format!("{column}>={p}"));
        }
        if let Some(max) = bounds.max.filter(|v| *v >= 0) {
            let p = self.bind(i64::from(max));
            self.filter(format!("{column}<={p}"));
        }
    }
}

fn decode_list(values: impl IntoIterator<Item = impl AsRef<str>>) -> GqlResult<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    for value in values {
        if result.len() == 1000 {
            return Err("Filter exceeds 1000 values".into());
        }
        result.push(
            URL_SAFE_NO_PAD
                .decode(value.as_ref().trim_end_matches('='))
                .map_err(|_| async_graphql::Error::new("Invalid base64url filter value"))?,
        );
    }
    Ok(result)
}

fn decode_cursor(cursor: &str) -> GqlResult<serde_json::Value> {
    if cursor.len() > 1024 {
        return Err("Invalid cursor".into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor.trim_end_matches('='))
        .map_err(|_| async_graphql::Error::new("Invalid cursor"))?;
    serde_json::from_slice(&bytes).map_err(|_| async_graphql::Error::new("Invalid cursor"))
}
fn encode_cursor(value: serde_json::Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

fn transaction_cursor(sql: &mut Sql, cursor: &str, sort: SortOrder) -> GqlResult<()> {
    let value = decode_cursor(cursor)?;
    let fields = value
        .as_array()
        .filter(|v| v.len() == 5)
        .ok_or_else(|| async_graphql::Error::new("Invalid transaction cursor"))?;
    let id = fields[3]
        .as_str()
        .ok_or_else(|| async_graphql::Error::new("Invalid transaction cursor"))?;
    let id = crate::decode_fixed::<32>(id, "cursor ID")
        .map_err(|_| async_graphql::Error::new("Invalid transaction cursor"))?
        .to_vec();
    let kind = fields[2]
        .as_bool()
        .ok_or_else(|| async_graphql::Error::new("Invalid transaction cursor"))?;
    if !fields[4].is_null() && fields[4].as_i64().filter(|v| *v >= 0).is_none() {
        return Err("Invalid transaction cursor".into());
    }
    if fields[0].is_null() && fields[1].is_null() && fields[4].as_i64().is_some() {
        // This index contains verified canonical placements. A pending cursor sorts above them.
        if sort == SortOrder::HeightAsc {
            sql.filter("false");
        }
        return Ok(());
    }
    let height = fields[0]
        .as_i64()
        .filter(|v| *v >= 0)
        .ok_or_else(|| async_graphql::Error::new("Invalid transaction cursor"))?;
    let position = fields[1]
        .as_i64()
        .and_then(|v| i32::try_from(v).ok())
        .filter(|v| *v >= 0)
        .ok_or_else(|| async_graphql::Error::new("Invalid transaction cursor"))?;
    let h = sql.bind(height);
    let p = sql.bind(position);
    let k = sql.bind(i16::from(kind));
    let id = sql.bind(id);
    sql.filter(format!(
        "(p.block_height,p.position,p.kind,p.id) {} ({h},{p},{k},{id})",
        sort.comparison()
    ));
    Ok(())
}

async fn transactions(
    ctx: &Context<'_>,
    filter: TransactionFilter,
    include_tags: bool,
) -> GqlResult<TransactionConnection> {
    let mut sql = Sql::new(
        "SELECT o.key,o.id,o.anchor,o.signature,o.signature_type,o.target,o.owner_address,w.public_key,
                coalesce(o.reward,0)::text AS fee,coalesce(o.quantity,0)::text AS quantity,
                o.data_size::text AS data_size,o.content_type,o.indexed_at,
                p.block_height,p.position,p.kind,b.hash,b.timestamp,b.previous_hash,parent.id AS parent_id
         FROM public.canonical_placements p
         JOIN public.objects o ON o.key=p.object_key
         JOIN public.canonical_blocks c ON c.height=p.block_height
         JOIN public.blocks b ON b.height=c.height AND b.hash=c.block_hash
         JOIN public.owners w ON w.address=o.owner_address
         LEFT JOIN public.item_locations l ON l.key=p.location_key
         LEFT JOIN public.objects parent ON parent.key=l.parent_key
         WHERE o.metadata_complete AND b.timestamp IS NOT NULL");
    // Keep selective request constraints ahead of global tag matching.
    let tag_first = filter.ids.is_empty()
        && filter.owners.is_empty()
        && filter.recipients.is_empty()
        && filter.block.min.is_none()
        && filter.block.max.is_none()
        && matches!(&filter.bundled_in, MaybeUndefined::Undefined)
        && filter.tags.len() > 1;
    let (tag_query_start, tag_query_end) = if filter.ids.is_empty() {
        ("EXISTS (", ")")
    } else {
        ("(", " LIMIT 1) IS TRUE")
    };
    if !filter.ids.is_empty() {
        let ids = decode_list(&filter.ids)?;
        let prefixes: Vec<i64> = ids
            .iter()
            .filter_map(|id| id.get(..8))
            .map(|v| i64::from_be_bytes(v.try_into().unwrap()))
            .collect();
        let prefixes = sql.bind(prefixes);
        let ids = sql.bind(ids);
        sql.filter(format!(
            "public.object_id_prefix(o.id)=ANY({prefixes}::bigint[]) AND o.id=ANY({ids}::bytea[])"
        ));
    }
    if !filter.owners.is_empty() {
        let owners = sql.bind(decode_list(&filter.owners)?);
        sql.filter(format!("o.owner_address IN (SELECT address FROM public.owners WHERE address=ANY({owners}::bytea[]) OR public_key=ANY({owners}::bytea[]))"));
    }
    if !filter.recipients.is_empty() {
        let recipients = sql.bind(decode_list(&filter.recipients)?);
        sql.filter(format!("o.target=ANY({recipients}::bytea[])"));
    }
    match filter.bundled_in {
        MaybeUndefined::Undefined => {}
        MaybeUndefined::Null => sql.filter("p.kind=0"),
        MaybeUndefined::Value(ids) => {
            let ids = sql.bind(decode_list(&ids)?);
            sql.filter(format!("p.kind=1 AND parent.id=ANY({ids}::bytea[])"));
        }
    }
    if filter.tags.len() > 128 {
        return Err("Filter exceeds 128 tags".into());
    }
    let mut candidates = String::new();
    for (index, tag) in filter.tags.into_iter().enumerate() {
        let _ = tag.op;
        if tag.values.len() > 1000 {
            return Err("Tag filter exceeds 1000 values".into());
        }
        let name = sql.bind(tag.name.into_bytes());
        let values = sql.bind(
            tag.values
                .into_iter()
                .map(String::into_bytes)
                .collect::<Vec<_>>(),
        );
        let alias = if tag_first && index > 0 {
            "matching"
        } else {
            "t"
        };
        let predicate = format!(
            "{alias}.name_key IN (SELECT key FROM public.tag_names
                WHERE sha256(value)=sha256({name}::bytea) AND value={name})
             AND {alias}.value_key IN (SELECT v.key FROM unnest({values}::bytea[]) wanted(value)
                JOIN public.tag_values v ON sha256(v.value)=sha256(wanted.value) AND v.value=wanted.value)"
        );
        if tag_first {
            if index == 0 {
                candidates = format!(
                    "SELECT DISTINCT t.object_key FROM public.object_tags t WHERE {predicate}"
                );
            } else {
                candidates.push_str(&format!(
                    " AND EXISTS (SELECT true FROM public.object_tags matching
                        WHERE matching.object_key=t.object_key AND {predicate})"
                ));
            }
        } else {
            sql.filter(format!(
                "{tag_query_start} SELECT true FROM public.object_tags t
                 WHERE t.object_key=o.key AND {predicate}{tag_query_end}"
            ));
        }
    }
    if tag_first {
        sql.text.insert_str(
            0,
            &format!("WITH matched_tags AS MATERIALIZED ({candidates}) "),
        );
        sql.filter("o.key IN (SELECT object_key FROM matched_tags)");
    }
    sql.heights("p.block_height", filter.block);
    if let Some(cursor) = filter.after.filter(|v| !v.is_empty()) {
        transaction_cursor(&mut sql, &cursor, filter.sort)?;
    }
    let direction = filter.sort.sql();
    let limit = sql.bind((filter.first + 1) as i64);
    sql.text.push_str(&format!(" ORDER BY p.block_height {direction},p.position {direction},p.kind {direction},p.id {direction} LIMIT {limit}"));
    let request_db = ctx.data::<Arc<RequestDb>>()?;
    let store = request_db.store().await?;
    let stream = store
        .client
        .query_raw(&sql.text, sql.params())
        .await
        .map_err(database_error)?;
    tokio::pin!(stream);
    let mut has_next_page = false;
    let mut edges = Vec::with_capacity(filter.first);
    let mut keys = Vec::with_capacity(filter.first);
    while let Some(row) = stream.try_next().await.map_err(database_error)? {
        if edges.len() == filter.first {
            has_next_page = true;
            continue;
        }
        let id = URL_SAFE_NO_PAD.encode(row.get::<_, Vec<u8>>("id"));
        let height: i64 = row.get("block_height");
        let position: i32 = row.get("position");
        let kind: i16 = row.get("kind");
        let indexed_at: i64 = row.get("indexed_at");
        let parent: Option<Vec<u8>> = row.get("parent_id");
        let parent = parent.map(|v| URL_SAFE_NO_PAD.encode(v));
        let signature = URL_SAFE_NO_PAD.encode(row.get::<_, Vec<u8>>("signature"));
        let owner_key = row
            .get::<_, Option<Vec<u8>>>("public_key")
            .map(|v| URL_SAFE_NO_PAD.encode(v));
        let content_type: Option<String> = row.get("content_type");
        request_db.consume(
            signature.len()
                + owner_key.as_ref().map_or(0, String::len)
                + content_type.as_ref().map_or(0, String::len)
                + 1024,
        )?;
        keys.push(row.get::<_, i64>("key"));
        edges.push(TransactionEdge {
            cursor: encode_cursor(serde_json::json!([
                height,
                position,
                kind == 1,
                id,
                indexed_at
            ])),
            node: Transaction {
                id: ID(id),
                anchor: Some(URL_SAFE_NO_PAD.encode(row.get::<_, Vec<u8>>("anchor"))),
                signature,
                signature_type: Some(i32::from(row.get::<_, i16>("signature_type"))),
                recipient: URL_SAFE_NO_PAD.encode(row.get::<_, Vec<u8>>("target")),
                owner: Owner {
                    address: URL_SAFE_NO_PAD.encode(row.get::<_, Vec<u8>>("owner_address")),
                    key: owner_key,
                },
                fee: amount(row.get("fee")),
                quantity: amount(row.get("quantity")),
                data: MetaData {
                    size: row.get("data_size"),
                    r#type: content_type,
                },
                tags: Vec::new(),
                block: Some(block_from_row(&row, "block_height")?),
                parent: parent.as_ref().map(|v| Parent { id: ID(v.clone()) }),
                bundled_in: parent.map(|v| Bundle { id: ID(v) }),
            },
        });
    }
    if include_tags && !keys.is_empty() {
        let positions: HashMap<i64, usize> =
            keys.iter().enumerate().map(|(i, k)| (*k, i)).collect();
        let stream = store.client.query_raw(
            "SELECT t.object_key,n.value,v.value FROM public.object_tags t
             JOIN public.tag_names n ON n.key=t.name_key JOIN public.tag_values v ON v.key=t.value_key
             WHERE t.object_key=ANY($1) ORDER BY t.object_key,t.ordinal", [&keys as &(dyn ToSql + Sync)]
        ).await.map_err(database_error)?;
        tokio::pin!(stream);
        while let Some(row) = stream.try_next().await.map_err(database_error)? {
            let name: Vec<u8> = row.get(1);
            let value: Vec<u8> = row.get(2);
            let name = String::from_utf8_lossy(&name).into_owned();
            let value = String::from_utf8_lossy(&value).into_owned();
            request_db.consume(name.len() + value.len() + 64)?;
            edges[positions[&row.get::<_, i64>(0)]]
                .node
                .tags
                .push(Tag { name, value });
        }
    }
    Ok(TransactionConnection {
        page_info: PageInfo { has_next_page },
        edges,
    })
}

fn amount(winston: String) -> Amount {
    let padded = format!("{winston:0>13}");
    let (whole, fractional) = padded.split_at(padded.len() - 12);
    let fractional = fractional.trim_end_matches('0');
    let ar = if fractional.is_empty() {
        whole.to_owned()
    } else {
        format!("{whole}.{fractional}")
    };
    Amount { winston, ar }
}

fn block_from_row(row: &Row, height_column: &str) -> GqlResult<Block> {
    let height = i32::try_from(row.get::<_, i64>(height_column))
        .map_err(|_| async_graphql::Error::new("Block height exceeds GraphQL Int"))?;
    let timestamp = i32::try_from(row.get::<_, i64>("timestamp"))
        .map_err(|_| async_graphql::Error::new("Block timestamp exceeds GraphQL Int"))?;
    Ok(Block {
        id: ID(URL_SAFE_NO_PAD.encode(row.get::<_, Vec<u8>>("hash"))),
        height,
        timestamp,
        previous: ID(row
            .get::<_, Option<Vec<u8>>>("previous_hash")
            .map(|v| URL_SAFE_NO_PAD.encode(v))
            .unwrap_or_default()),
    })
}

async fn blocks(
    ctx: &Context<'_>,
    ids: Vec<ID>,
    heights: BlockFilter,
    first: usize,
    after: Option<String>,
    sort: SortOrder,
) -> GqlResult<BlockConnection> {
    let mut sql = Sql::new(
        "SELECT b.hash,b.timestamp,b.height,b.previous_hash FROM public.canonical_blocks c JOIN public.blocks b ON b.height=c.height AND b.hash=c.block_hash WHERE b.timestamp IS NOT NULL",
    );
    if !ids.is_empty() {
        let ids = sql.bind(decode_list(&ids)?);
        sql.filter(format!("c.block_hash=ANY({ids}::bytea[])"));
    }
    sql.heights("c.height", heights);
    if let Some(after) = after.filter(|v| !v.is_empty()) {
        let cursor = decode_cursor(&after)?;
        let fields = cursor
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or_else(|| async_graphql::Error::new("Invalid block cursor"))?;
        let height = fields[0]
            .as_i64()
            .filter(|v| *v >= 0)
            .ok_or_else(|| async_graphql::Error::new("Invalid block cursor"))?;
        let height = sql.bind(height);
        sql.filter(format!("c.height {} {height}", sort.comparison()));
    }
    let limit = sql.bind((first + 1) as i64);
    sql.text
        .push_str(&format!(" ORDER BY c.height {} LIMIT {limit}", sort.sql()));
    let db = ctx.data::<Arc<RequestDb>>()?;
    let store = db.store().await?;
    let rows = store
        .client
        .query(&sql.text, &sql.params())
        .await
        .map_err(database_error)?;
    let has_next_page = rows.len() > first;
    db.consume(rows.len() * 256)?;
    let edges = rows
        .into_iter()
        .take(first)
        .map(|row| {
            let node = block_from_row(&row, "height")?;
            Ok(BlockEdge {
                cursor: encode_cursor(serde_json::json!([node.height])),
                node,
            })
        })
        .collect::<GqlResult<Vec<_>>>()?;
    Ok(BlockConnection {
        page_info: PageInfo { has_next_page },
        edges,
    })
}

#[cfg(test)]
mod tests;
