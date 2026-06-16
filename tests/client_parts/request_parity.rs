// Request byte-parity against the shared poe-request / records-request
// fixtures, plus a handful of direct request-shape assertions. Each fixture is
// path-referenced from the canonical sdk-ts tree (never copied), and the body
// is compared as canonicalised JSON (key-sorted, compact) — the contract the
// fixture pins.

/// Canonicalise a JSON body to key-sorted compact form for structural equality.
fn canonicalise_json_body(raw: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(raw).unwrap();
    sort_value(&value).to_string()
}

/// Recursively key-sort a JSON value so two logically-equal bodies compare
/// equal regardless of key order or whitespace.
fn sort_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: std::collections::BTreeMap<String, serde_json::Value> =
                std::collections::BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), sort_value(v));
            }
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(sort_value).collect())
        }
        other => other.clone(),
    }
}

/// The opaque bearer token a fixture's `Authorization: Bearer <token>` carries.
///
/// The client forwards the key verbatim, so feeding it the token from the
/// fixture's own authorization value reproduces that header exactly — pinning
/// pass-through, not any particular key format.
fn bearer_from_fixture(fixture: &serde_json::Value) -> String {
    fixture["authorization"]
        .as_str()
        .and_then(|h| h.strip_prefix("Bearer "))
        .expect("fixture authorization must be `Bearer <token>`")
        .to_string()
}

#[test]
fn poe_publish_request_matches_fixture() {
    let fixture_path = common::sdk_ts_fixtures()
        .join("poe-request")
        .join("poe-publish-request.json");
    let fixture = common::read_fixture_json(&fixture_path);

    // The key is opaque to the client; derive it from the fixture's own
    // Authorization value so the test pins the verbatim forwarding, not a format.
    let key = bearer_from_fixture(&fixture);
    let transport = Box::new(MockTransport::single(StubResponse::json(
        202,
        publish_success_body(),
    )));
    let (client, ptr) = client_with("http://test.example/api/v1",Some(&key), transport);

    // 16 bytes of canonical-CBOR-shaped placeholder: the fixture pins the wire
    // shape, not record contents.
    let record = vec![0xaa_u8; 16];
    client
        .poe()
        .publish(&PublishInput {
            record,
            quote_id: QUOTE_ID.to_string(),
            signatures: None,
            idempotency_key: None,
        })
        .unwrap();

    let captured = mock(ptr).first();
    assert_eq!(captured.url, fixture["url"].as_str().unwrap());
    assert_eq!(captured.method, HttpMethod::Post);
    assert_eq!(
        header(&captured, "authorization").as_deref(),
        fixture["authorization"].as_str()
    );
    assert_eq!(
        header(&captured, "content-type").as_deref(),
        fixture["content_type"].as_str()
    );
    assert_eq!(
        header(&captured, "accept").as_deref(),
        fixture["accept"].as_str()
    );
    assert_eq!(
        canonicalise_json_body(captured.body.as_json()),
        canonicalise_json_body(fixture["body"].as_str().unwrap())
    );
}

#[test]
fn records_get_request_matches_fixture() {
    let fixture_path = common::sdk_ts_fixtures()
        .join("records-request")
        .join("records-get-request.json");
    let fixture = common::read_fixture_json(&fixture_path);

    let key = bearer_from_fixture(&fixture);
    let record_body = serde_json::json!({
        "tx_hash": "a".repeat(64),
        "status": "confirmed",
        "block_height": 12_345_678,
        "block_time": "2026-01-01T00:00:00.000Z",
        "num_confirmations": 100,
        "scheme": 0,
        "item_count": 1,
        "signer_ed25519": null,
        "metadata_cbor_base64": "oWNmb29jYmFy",
    });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, record_body)));
    let (client, ptr) = client_with("http://test.example/api/v1",Some(&key), transport);

    client.records().get(&"a".repeat(64)).unwrap();

    let captured = mock(ptr).first();
    assert_eq!(captured.url, fixture["url"].as_str().unwrap());
    assert_eq!(captured.method, HttpMethod::Get);
    assert_eq!(
        header(&captured, "authorization").as_deref(),
        fixture["authorization"].as_str()
    );
    assert_eq!(
        header(&captured, "accept").as_deref(),
        fixture["accept"].as_str()
    );
    // The records namespace emits `content-type: application/json` on GET, matching
    // both reference SDKs (TS records.ts / Py records.py build the same header set).
    assert_eq!(
        header(&captured, "content-type").as_deref(),
        Some("application/json")
    );
    // The records.get path never carries a request body.
    assert_eq!(captured.body, RequestBodySnapshot::None);
}

#[test]
fn records_list_request_emits_json_headers_and_no_body() {
    // The records.list GET carries the same json-headers set records.get emits
    // (content-type + accept + bearer) and never a request body.
    let page = records_list_body(serde_json::json!([]), false, None);
    let transport = Box::new(MockTransport::single(StubResponse::json(200, page)));
    let (client, ptr) = client_with("http://test.example/api/v1",Some(&bearer_key()), transport);

    client.records().list(None).unwrap();

    let captured = mock(ptr).first();
    assert_eq!(captured.method, HttpMethod::Get);
    assert_eq!(
        header(&captured, "content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(header(&captured, "accept").as_deref(), Some("application/json"));
    assert!(header(&captured, "authorization").is_some());
    assert_eq!(captured.body, RequestBodySnapshot::None);
}

// ---------------------------------------------------------------------------
// Direct request-shape assertions (no fixture)
// ---------------------------------------------------------------------------

#[test]
fn quote_posts_byte_counts_and_parses_opaque_price_lock() {
    // The quote is an opaque price token: only quote_id + amount + currency +
    // expires_at. The gateway's pricing internals (breakdown / margin / FX age)
    // are deliberately NOT part of the public response.
    let body = serde_json::json!({
        "quote_id": QUOTE_ID,
        "amount": "180000",
        "currency": "USD",
        "expires_at": "2026-05-26T12:15:00.000Z",
    });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    // The caller names the gateway; the bearer is forwarded verbatim.
    let (client, ptr) = client_with("https://gateway.example.com/api/v1",Some(&bearer_key()), transport);

    let out = client
        .poe()
        .quote(&QuoteInput {
            record_bytes: 256,
            recipient_count: 1,
            file_bytes_total: 1_048_576,
        })
        .unwrap();
    assert_eq!(out.quote_id, QUOTE_ID);
    assert_eq!(out.amount, "180000");
    assert_eq!(out.currency, "USD");
    assert_eq!(out.expires_at, "2026-05-26T12:15:00.000Z");

    let captured = mock(ptr).first();
    assert_eq!(captured.url, "https://gateway.example.com/api/v1/poe/quote");
    let sent: serde_json::Value = serde_json::from_str(captured.body.as_json()).unwrap();
    assert_eq!(
        sent,
        serde_json::json!({
            "record_bytes": 256,
            "recipient_count": 1,
            "file_bytes_total": 1_048_576,
        })
    );
}

#[test]
fn publish_hex_encodes_record_and_reports_dedup_hit_from_status() {
    // 202 → fresh (dedup_hit false).
    let transport = Box::new(MockTransport::single(StubResponse::json(
        202,
        publish_success_body(),
    )));
    let (client, ptr) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let out = client
        .poe()
        .publish(&PublishInput {
            record: vec![0xaa, 0xbb],
            quote_id: QUOTE_ID.to_string(),
            signatures: None,
            idempotency_key: None,
        })
        .unwrap();
    assert!(!out.dedup_hit);
    let sent: serde_json::Value =
        serde_json::from_str(mock(ptr).first().body.as_json()).unwrap();
    assert_eq!(sent["record"], "aabb");
    assert_eq!(sent["quote_id"], QUOTE_ID);

    // 200 → dedup hit.
    let transport = Box::new(MockTransport::single(StubResponse::json(
        200,
        publish_success_body(),
    )));
    let (client, _) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let out = client
        .poe()
        .publish(&PublishInput {
            record: vec![0xaa],
            quote_id: QUOTE_ID.to_string(),
            signatures: None,
            idempotency_key: None,
        })
        .unwrap();
    assert!(out.dedup_hit);
}

#[test]
fn publish_threads_idempotency_key_and_signatures() {
    let transport = Box::new(MockTransport::single(StubResponse::json(
        202,
        publish_success_body(),
    )));
    let (client, ptr) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    client
        .poe()
        .publish(&PublishInput {
            record: vec![0xaa],
            quote_id: QUOTE_ID.to_string(),
            signatures: Some(vec![RecordSignature {
                cose_sign1: "beef".to_string(),
                cose_key: Some("cafe".to_string()),
            }]),
            idempotency_key: Some("idem-p-1".to_string()),
        })
        .unwrap();
    let captured = mock(ptr).first();
    assert_eq!(header(&captured, "idempotency-key").as_deref(), Some("idem-p-1"));
    let sent: serde_json::Value = serde_json::from_str(captured.body.as_json()).unwrap();
    assert_eq!(
        sent["signatures"],
        serde_json::json!([{ "cose_sign1": "beef", "cose_key": "cafe" }])
    );
}

#[test]
fn uploads_builds_multipart_with_target_and_indexed_files() {
    let body = serde_json::json!({
        "uploads": [{ "idx": 0, "ok": true, "uri": format!("ar://{}", "A".repeat(43)), "sha256": "00".repeat(32), "bytes": 1 }],
    });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, ptr) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let out = client
        .poe()
        .uploads(&UploadsInput {
            target: "arweave".to_string(),
            data: vec![vec![0xaa], vec![0xbb]],
            idempotency_key: Some("idem-u-1".to_string()),
        })
        .unwrap();
    assert_eq!(out.uploads.len(), 1);

    let captured = mock(ptr).first();
    assert_eq!(captured.url, "http://test/api/v1/poe/uploads");
    assert_eq!(header(&captured, "idempotency-key").as_deref(), Some("idem-u-1"));
    // Multipart never carries an explicit content-type header (the transport
    // attaches the boundary content-type).
    assert!(header(&captured, "content-type").is_none());
    match &captured.body {
        RequestBodySnapshot::Multipart(fields) => {
            assert_eq!(fields[0].name, "target");
            assert_eq!(fields[0].value, b"arweave");
            assert_eq!(fields[1].name, "file_0");
            assert_eq!(fields[1].filename.as_deref(), Some("file_0.bin"));
            assert_eq!(fields[1].content_type.as_deref(), Some("application/octet-stream"));
            assert_eq!(fields[2].name, "file_1");
            assert_eq!(fields.len(), 3);
        }
        other => panic!("expected multipart body, got {other:?}"),
    }
}
