use super::*;
use anyhow::{Result, ensure};
use serde_json::{Value, json};

async fn query(
    schema: &Schema,
    db: &Arc<RequestDb>,
    text: &str,
    variables: Value,
) -> Result<Value> {
    let response = schema
        .execute(
            async_graphql::Request::new(text)
                .variables(async_graphql::Variables::from_json(variables))
                .data(db.clone()),
        )
        .await;
    ensure!(
        response.errors.is_empty(),
        "GraphQL errors: {:?}",
        response.errors
    );
    Ok(response.data.into_json()?)
}

fn ids(page: &Value) -> Vec<String> {
    page["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edge| edge["node"]["id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn amounts_preserve_precision_beyond_float_and_integer_ranges() {
    assert_eq!(amount("1".into()).ar, "0.000000000001");
    assert_eq!(amount("1000000000000".into()).ar, "1");
    assert_eq!(
        amount("340282366920938463463374607431768211455".into()).ar,
        "340282366920938463463374607.431768211455"
    );
}

#[tokio::test]
async fn graphql_validation_rejects_unsupported_operations_and_abuse() {
    let schema = schema();
    for (text, expected) in [
        (
            "{ transactions { edges { node { unknownField } } } }",
            "unknownfield",
        ),
        ("mutation { deleteEverything }", "mutation"),
        (
            "subscription { transactions { edges { cursor } } }",
            "subscription",
        ),
        (
            "{ transactions(first: -1) { edges { cursor } } }",
            "non-negative",
        ),
        (
            "{ transactions(after: \"bad!\") { edges { cursor } } }",
            "invalid cursor",
        ),
        (
            "{ blocks(after: \"W10\") { edges { cursor } } }",
            "invalid block cursor",
        ),
        (
            "{ transactions(tags: [{name: \"a\", values: [\"b\"], op: NEQ}]) { edges { cursor } } }",
            "neq",
        ),
    ] {
        let response = schema.execute(text).await;
        assert!(
            response
                .errors
                .iter()
                .any(|error| error.message.to_ascii_lowercase().contains(expected)),
            "unexpected errors for {text}: {:?}",
            response.errors
        );
    }
    let response = schema
        .execute("{ __type(name: \"Transaction\") { name } }")
        .await;
    assert!(response.errors.is_empty());
    assert_eq!(
        response.data.into_json().unwrap()["__type"]["name"],
        "Transaction"
    );
}

#[tokio::test]
#[ignore = "requires ar_io_rust_test; isolated fixture transaction is rolled back"]
async fn graphql_filters_cursors_and_metadata_match_gateway_contract() -> Result<()> {
    let store = BlockStore::connect(&std::env::var("DATABASE_URL")?).await?;
    ensure!(
        store
            .client
            .query_one("SELECT current_database()", &[])
            .await?
            .get::<_, String>(0)
            == "ar_io_rust_test",
        "requires dedicated test database"
    );
    store.client.batch_execute("BEGIN").await?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos()
        .to_le_bytes();
    let owner = crate::sha256(&[&nonce, b"owner"]).to_vec();
    let public_key = [owner.clone(), owner.clone()].concat();
    let recipient = crate::sha256(&[&nonce, b"recipient"]).to_vec();
    store
        .client
        .execute(
            "INSERT INTO public.owners(address,public_key) VALUES($1,$2)",
            &[&owner, &public_key],
        )
        .await?;
    let height: i64 = store
        .client
        .query_one(
            "SELECT coalesce(max(height),0)+1000 FROM public.canonical_blocks",
            &[],
        )
        .await?
        .get(0);
    let mut block_ids = Vec::new();
    for i in 0..2u8 {
        let digest = crate::sha256(&[&nonce, &[i], b"block"]);
        let hash = [digest.as_slice(), &digest[..16]].concat();
        store.client.execute("INSERT INTO public.blocks(height,hash,previous_hash,tx_root,weave_size,timestamp) VALUES($1,$2,$2,''::bytea,0,1000000)", &[&(height+i64::from(i)),&hash]).await?;
        store.client.execute("INSERT INTO public.canonical_blocks(height,block_hash,metadata_complete) VALUES($1,$2,true)", &[&(height+i64::from(i)),&hash]).await?;
        block_ids.push(URL_SAFE_NO_PAD.encode(hash));
    }
    let mut keys = Vec::new();
    let mut object_ids = Vec::new();
    for i in 0..6u8 {
        let id = crate::sha256(&[&nonce, &[i], b"object"]).to_vec();
        let kind = if i == 2 || i == 3 { 1_i16 } else { 0_i16 };
        let key: i64 = store.client.query_one(
            "INSERT INTO public.objects(id,kind,metadata_complete,signature,anchor,owner_address,target,data_size,content_type,signature_type,quantity,reward,indexed_at)
             VALUES($1,$2,true,$1,''::bytea,$3,$4,123,'text/plain',1,1234567890123,1,1000000) RETURNING key", &[&id,&kind,&owner,&recipient]
        ).await?.get(0);
        keys.push(key);
        object_ids.push(URL_SAFE_NO_PAD.encode(&id));
        if i == 5 {
            continue;
        }
        let location: Option<i64> = if kind == 1 {
            let offset = 1000 * i64::from(i);
            Some(store.client.query_one(
                "INSERT INTO public.item_locations(object_key,parent_key,root_key,path,item_offset,item_size,data_offset) VALUES($1,$2,$2,ARRAY[$3::bigint]::numeric[],$3::bigint,500,100) RETURNING key",
                &[&key,&keys[0],&offset]
            ).await?.get(0))
        } else {
            None
        };
        let position = if i == 1 { 1_i32 } else { 0_i32 };
        let placed_height = height + i64::from(i == 4);
        store.client.execute("INSERT INTO public.canonical_placements(object_key,block_height,position,kind,id,location_key) VALUES($1,$2,$3,$4,$5,$6)", &[&key,&placed_height,&position,&kind,&id,&location]).await?;
    }
    let app_name = format!("GraphQL-{}", u128::from_le_bytes(nonce));
    let shape_name = format!("Shape-{}", u128::from_le_bytes(nonce));
    for (i, key) in keys.iter().enumerate() {
        let color = if i == 2 || i == 4 { "blue" } else { "red" };
        let shape = if i == 3 { "circle" } else { "square" };
        for (ordinal, (name, value)) in [
            (app_name.as_str(), color),
            (shape_name.as_str(), shape),
            (app_name.as_str(), color),
        ]
        .into_iter()
        .enumerate()
        {
            let mut dictionary = Vec::new();
            for (table, bytes) in [
                ("tag_names", name.as_bytes()),
                ("tag_values", value.as_bytes()),
            ] {
                let rows = store.client.query(&format!("SELECT key FROM public.{table} WHERE sha256(value)=sha256($1::bytea) AND value=$1"), &[&bytes]).await?;
                let key: i64 = if let Some(row) = rows.first() {
                    row.get(0)
                } else {
                    store
                        .client
                        .query_one(
                            &format!("INSERT INTO public.{table}(value) VALUES($1) RETURNING key"),
                            &[&bytes],
                        )
                        .await?
                        .get(0)
                };
                dictionary.push(key);
            }
            store.client.execute("INSERT INTO public.object_tags(object_key,ordinal,name_key,value_key) VALUES($1,$2,$3,$4)", &[key,&(ordinal as i32),&dictionary[0],&dictionary[1]]).await?;
        }
    }
    let db = Arc::new(RequestDb {
        source: None,
        connection: Mutex::new(Some(store)),
        remaining_bytes: AtomicUsize::new(MAX_RESULT_BYTES),
    });
    let schema = schema();
    let full = query(
        &schema,
        &db,
        r#"
        query Detail($id:ID!,$show:Boolean!) {
          selected:transaction(id:$id) { ...Details tags @include(if:$show) { name value } }
        }
        fragment Details on Transaction {
          id anchor signature signatureType recipient owner { address key }
          fee { winston ar } quantity { winston ar } data { size type }
          block { id height timestamp previous } parent { id } bundledIn { id }
        }"#,
        json!({"id":object_ids[0],"show":true}),
    )
    .await?;
    let tx = &full["selected"];
    ensure!(
        tx["id"] == object_ids[0] && tx["signature"] == object_ids[0],
        "transaction identity changed"
    );
    ensure!(
        tx["owner"]["address"] == URL_SAFE_NO_PAD.encode(&owner)
            && tx["owner"]["key"] == URL_SAFE_NO_PAD.encode(&public_key),
        "owner fields differ"
    );
    ensure!(
        tx["quantity"]["ar"] == "1.234567890123" && tx["fee"]["ar"] == "0.000000000001",
        "amount precision lost"
    );
    ensure!(
        tx["data"] == json!({"size":"123","type":"text/plain"})
            && tx["block"]["id"] == block_ids[0],
        "metadata differs"
    );
    ensure!(
        tx["tags"]
            == json!([{"name":app_name,"value":"red"},{"name":shape_name,"value":"square"},{"name":app_name,"value":"red"}]),
        "ordered duplicate tags lost"
    );
    ensure!(
        tx["parent"].is_null() && tx["bundledIn"].is_null(),
        "L1 gained a parent"
    );
    let items = query(
        &schema,
        &db,
        "query($id:ID!){transaction(id:$id){parent{id} bundledIn{id}}}",
        json!({"id":object_ids[2]}),
    )
    .await?;
    ensure!(
        items["transaction"]["parent"]["id"] == object_ids[0]
            && items["transaction"]["bundledIn"]["id"] == object_ids[0],
        "bundle parent lost"
    );
    let orphan = query(
        &schema,
        &db,
        "query($id:ID!){transaction(id:$id){id}}",
        json!({"id":object_ids[5]}),
    )
    .await?;
    ensure!(
        orphan["transaction"].is_null(),
        "unplaced metadata leaked into canonical results"
    );

    let page_query = "query($ids:[ID!],$after:String,$sort:SortOrder){transactions(ids:$ids,first:2,after:$after,sort:$sort){pageInfo{hasNextPage} edges{cursor node{id}}}}";
    let mut item_order = vec![2, 3];
    item_order.sort_by_key(|i| URL_SAFE_NO_PAD.decode(&object_ids[*i]).unwrap());
    let ascending: Vec<String> = [vec![0], item_order, vec![1, 4]]
        .concat()
        .iter()
        .map(|i| object_ids[*i].clone())
        .collect();
    for sort in ["HEIGHT_ASC", "HEIGHT_DESC"] {
        let mut collected = Vec::new();
        let mut cursor = Value::Null;
        loop {
            let page = query(
                &schema,
                &db,
                page_query,
                json!({"ids":object_ids,"sort":sort,"after":cursor}),
            )
            .await?;
            let page = &page["transactions"];
            collected.extend(ids(page));
            if page["pageInfo"]["hasNextPage"] == false {
                break;
            }
            cursor = page["edges"].as_array().unwrap().last().unwrap()["cursor"].clone();
            ensure!(collected.len() <= 5, "pagination did not advance");
        }
        let expected = if sort == "HEIGHT_ASC" {
            ascending.clone()
        } else {
            ascending.iter().rev().cloned().collect()
        };
        ensure!(
            collected == expected,
            "cursor ordering differs: {collected:?} != {expected:?}"
        );
    }
    let combined = query(&schema,&db,
        "query($ids:[ID!],$owners:[String!],$recipients:[String!],$tags:[TagFilter!],$block:BlockFilter){transactions(ids:$ids,owners:$owners,recipients:$recipients,tags:$tags,block:$block,sort:HEIGHT_ASC){edges{node{id}}}}",
        json!({"ids":object_ids,"owners":[URL_SAFE_NO_PAD.encode(&public_key)],"recipients":[URL_SAFE_NO_PAD.encode(&recipient)],"tags":[{"name":app_name,"values":["red","blue"]},{"name":shape_name,"values":["square"]}],"block":{"min":height,"max":height}})).await?;
    let expected: Vec<_> = ascending
        .iter()
        .filter(|id| **id != object_ids[3] && **id != object_ids[4])
        .cloned()
        .collect();
    ensure!(
        ids(&combined["transactions"]) == expected,
        "combined filters or tag deduplication differ"
    );
    for (extra, expected) in [
        (
            "bundledIn:null".to_owned(),
            vec![
                object_ids[0].clone(),
                object_ids[1].clone(),
                object_ids[4].clone(),
            ],
        ),
        (
            format!("parent:[\"{}\"]", object_ids[0]),
            ascending
                .iter()
                .filter(|id| **id == object_ids[2] || **id == object_ids[3])
                .cloned()
                .collect(),
        ),
        (
            format!("bundledIn:null,parent:[\"{}\"]", object_ids[0]),
            vec![
                object_ids[0].clone(),
                object_ids[1].clone(),
                object_ids[4].clone(),
            ],
        ),
        ("bundledIn:[]".to_owned(), vec![]),
        (format!("tags:[{{name:\"{app_name}\",values:[]}}]"), vec![]),
        (
            format!(
                "tags:[{{name:\"{}\",values:[\"red\"]}}]",
                app_name.to_lowercase()
            ),
            vec![],
        ),
    ] {
        let text = format!(
            "query($ids:[ID!]){{transactions(ids:$ids,sort:HEIGHT_ASC,{extra}){{edges{{node{{id}}}}}}}}"
        );
        let result = query(&schema, &db, &text, json!({"ids":object_ids})).await?;
        ensure!(
            ids(&result["transactions"]) == expected,
            "filter semantics differ for {extra}"
        );
    }
    let block_page=query(&schema,&db,"query($ids:[ID!]){blocks(ids:$ids,first:1,sort:HEIGHT_ASC){pageInfo{hasNextPage} edges{cursor node{id height previous timestamp}}}}",json!({"ids":block_ids})).await?;
    ensure!(
        block_page["blocks"]["pageInfo"]["hasNextPage"] == true
            && block_page["blocks"]["edges"][0]["node"]["id"] == block_ids[0],
        "block pagination differs"
    );
    let block_next=query(&schema,&db,"query($ids:[ID!],$after:String,$id:String!){block(id:$id){id} blocks(ids:$ids,after:$after,sort:HEIGHT_ASC){pageInfo{hasNextPage} edges{node{id}}}}",json!({"ids":block_ids,"id":block_ids[0],"after":block_page["blocks"]["edges"][0]["cursor"]})).await?;
    ensure!(
        block_next["block"]["id"] == block_ids[0]
            && ids(&block_next["blocks"]) == vec![block_ids[1].clone()]
            && block_next["blocks"]["pageInfo"]["hasNextPage"] == false,
        "block lookup or final page differs"
    );
    let store = db
        .store()
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    store
        .client
        .execute(
            "DELETE FROM public.canonical_blocks WHERE height=$1",
            &[&height],
        )
        .await?;
    drop(store);
    let removed = query(
        &schema,
        &db,
        "query($ids:[ID!]){transactions(ids:$ids){edges{node{id}}}}",
        json!({"ids":object_ids}),
    )
    .await?;
    ensure!(
        ids(&removed["transactions"]) == vec![object_ids[4].clone()],
        "fork removal left stale transactions or items"
    );
    db.store()
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?
        .client
        .batch_execute("ROLLBACK")
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a canonical transaction in ar_io_rust_test; run serially"]
async fn graphql_id_only_queries_do_not_wait_for_unrequested_tags() -> Result<()> {
    let store = BlockStore::connect(&std::env::var("DATABASE_URL")?).await?;
    ensure!(
        store
            .client
            .query_one("SELECT current_database()", &[])
            .await?
            .get::<_, String>(0)
            == "ar_io_rust_test",
        "requires dedicated test database"
    );
    let row = store
        .client
        .query_one(
            "SELECT o.id FROM public.objects o
         JOIN public.canonical_placements p ON p.object_key=o.key
         JOIN public.canonical_blocks c ON c.height=p.block_height
         JOIN public.blocks b ON b.height=c.height AND b.hash=c.block_hash
         WHERE o.metadata_complete AND b.timestamp IS NOT NULL
           AND EXISTS(SELECT 1 FROM public.object_tags t WHERE t.object_key=o.key) LIMIT 1",
            &[],
        )
        .await?;
    let id = URL_SAFE_NO_PAD.encode(row.get::<_, Vec<u8>>(0));
    let blocker = store.reconnect().await?;
    let db = Arc::new(RequestDb {
        source: Some(Arc::new(store)),
        connection: Mutex::new(None),
        remaining_bytes: AtomicUsize::new(MAX_RESULT_BYTES),
    });
    let schema = schema();
    blocker
        .client
        .batch_execute("BEGIN; LOCK TABLE public.object_tags IN ACCESS EXCLUSIVE MODE")
        .await?;
    let response = schema
        .execute(
            async_graphql::Request::new(
                "query($id:ID!){single:transaction(id:$id){id}
             many:transactions(ids:[$id]){edges{node{id hidden:tags @skip(if:true){name}}}}}",
            )
            .variables(async_graphql::Variables::from_json(json!({"id":id})))
            .data(db.clone()),
        )
        .await;
    blocker.client.batch_execute("ROLLBACK").await?;
    ensure!(
        response.errors.is_empty(),
        "unrequested tags blocked ID retrieval: {:?}",
        response.errors
    );
    let value = response.data.into_json()?;
    ensure!(
        value["single"]["id"] == id && value["many"]["edges"][0]["node"]["id"] == id,
        "ID-only result differs"
    );
    let tagged = query(
        &schema,
        &db,
        "query($id:ID!){transaction(id:$id){id} transaction(id:$id){...Fields}
         transactions(ids:[$id]){edges{node{...Fields}}}}
         fragment Fields on Transaction { selected:tags{name value} }",
        json!({"id":id}),
    )
    .await?;
    let store = db
        .store()
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let rows = store
        .client
        .query(
            "SELECT n.value,v.value FROM public.object_tags t
         JOIN public.objects o ON o.key=t.object_key
         JOIN public.tag_names n ON n.key=t.name_key JOIN public.tag_values v ON v.key=t.value_key
         WHERE o.id=$1 ORDER BY t.ordinal",
            &[&URL_SAFE_NO_PAD.decode(&id)?],
        )
        .await?;
    let expected: Vec<_> = rows
        .iter()
        .map(|row| {
            json!({
                "name":String::from_utf8_lossy(&row.get::<_,Vec<u8>>(0)),
                "value":String::from_utf8_lossy(&row.get::<_,Vec<u8>>(1)),
            })
        })
        .collect();
    ensure!(
        tagged["transaction"]["selected"] == json!(expected)
            && tagged["transactions"]["edges"][0]["node"]["selected"] == json!(expected),
        "aliased or fragmented tag selection differs"
    );
    Ok(())
}
