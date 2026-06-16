// Records (list / get), account, batch, config-resolution, and
// high-level publish-helper coverage. Assertions target request shape, parsed
// responses, page entries, and typed errors — never log strings.

use cardanowall::poe_standard::{validate_poe_record, ValidatorOptions};

/// A full RecordResource row, the projection records.list / records.get share.
fn record_resource_row(tx_hash: &str) -> serde_json::Value {
    serde_json::json!({
        "tx_hash": tx_hash,
        "status": "confirmed",
        "block_height": 100,
        "block_time": "2026-01-01T00:00:00.000Z",
        "num_confirmations": 15,
        "scheme": 0,
        "item_count": 1,
        "signer_ed25519": null,
        "metadata_cbor_base64": "oWNmb29jYmFy",
    })
}

// ---------------------------------------------------------------------------
// Config resolution
// ---------------------------------------------------------------------------

#[test]
fn config_resolution_contract() {
    // Explicit base_url + opaque bearer key: constructs, targets the given host,
    // forwards the key verbatim.
    let body = records_list_body(serde_json::json!([]), false, None);
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body.clone())));
    let (client, ptr) = client_with(
        "https://gateway.example.com/api/v1",
        Some("opaque-vendor-token-123"),
        transport,
    );
    client.records().list(None).unwrap();
    assert!(mock(ptr).first().url.starts_with("https://gateway.example.com/api/v1/records"));
    assert_eq!(
        header(&mock(ptr).first(), "authorization").as_deref(),
        Some("Bearer opaque-vendor-token-123")
    );

    // Explicit base_url, no key: anonymous, no Authorization header.
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, ptr) = client_with("https://gateway.example.com/api/v1", None, transport);
    client.records().list(None).unwrap();
    assert!(mock(ptr).first().url.starts_with("https://gateway.example.com/api/v1/records"));
    assert_eq!(header(&mock(ptr).first(), "authorization"), None);
}

#[test]
fn missing_base_url_is_rejected() {
    for base_url in [None, Some(String::new())] {
        let result = Label309Client::new(Label309ClientConfig {
            api_key: Some("opaque-token".to_string()),
            base_url,
        });
        let err: InvalidClientConfigError = match result {
            Ok(_) => panic!("expected InvalidClientConfigError for a missing/empty base_url"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("base_url is required"),
            "error must explain that base_url is required, got: {err}"
        );
    }
    assert_eq!(InvalidClientConfigError::CODE, "INVALID_CLIENT_CONFIG");
}

#[test]
fn base_url_strips_one_trailing_slash() {
    let body = records_list_body(serde_json::json!([]), false, None);
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, ptr) = client_with("http://localhost:3000/api/v1/", None, transport);
    // No input → no query string at all (the bare list endpoint).
    client.records().list(None).unwrap();
    assert_eq!(mock(ptr).first().url, "http://localhost:3000/api/v1/records");
}

/// Drive one matrix suffix through its real namespace call against `client`,
/// queuing the right stub response shape for that endpoint. Returns the URL the
/// client actually emitted. `tx` is the 64-char hex hash the `/records/<tx>`
/// suffixes bake into both their literal and their expected URL.
fn drive_join_suffix(suffix: &str, base_url: &str, tx: &str) -> String {
    // The success body each endpoint expects so the real call reaches the
    // transport (and the URL is captured) without erroring before the request.
    let publish_body = publish_success_body();
    let stub = match suffix {
        "/records" => StubResponse::json(200, records_list_body(serde_json::json!([]), false, None)),
        s if s == format!("/records/{tx}") => StubResponse::json(
            200,
            serde_json::json!({
                "tx_hash": tx, "status": "confirmed", "block_height": 1,
                "block_time": "2026-01-01T00:00:00.000Z", "num_confirmations": 1,
                "scheme": 0, "item_count": 1, "signer_ed25519": null,
                "metadata_cbor_base64": "oWNmb29jYmFy",
            }),
        ),
        "/account/balance" => {
            StubResponse::json(200, serde_json::json!({ "balance_usd_micros": "0" }))
        }
        "/poe/quote" => StubResponse::json(
            200,
            serde_json::json!({
                "quote_id": QUOTE_ID, "amount": "1", "currency": "USD",
                "expires_at": "2026-01-01T00:00:00.000Z",
            }),
        ),
        "/poe/publish" => StubResponse::json(202, publish_body),
        "/poe/publish-batch" => StubResponse::json(
            200,
            serde_json::json!({ "results": [], "balance_after_usd_micros": "4500000" }),
        ),
        "/poe/uploads" => StubResponse::json(
            200,
            serde_json::json!({
                "uploads": [{ "idx": 0, "ok": true, "uri": format!("ar://{}", "A".repeat(43)),
                              "sha256": "00".repeat(32), "bytes": 1 }],
            }),
        ),
        other => panic!("matrix suffix has no driver: {other:?}"),
    };
    let transport = Box::new(MockTransport::single(stub));
    let (client, ptr) = client_with(base_url, None, transport);
    match suffix {
        "/records" => {
            client.records().list(None).unwrap();
        }
        s if s == format!("/records/{tx}") => {
            client.records().get(tx).unwrap();
        }
        "/account/balance" => {
            client.account().balance().unwrap();
        }
        "/poe/quote" => {
            client
                .poe()
                .quote(&QuoteInput { record_bytes: 1, recipient_count: 0, file_bytes_total: 0 })
                .unwrap();
        }
        "/poe/publish" => {
            client
                .poe()
                .publish(&PublishInput {
                    record: vec![0xaa],
                    quote_id: QUOTE_ID.to_string(),
                    signatures: None,
                    idempotency_key: None,
                })
                .unwrap();
        }
        "/poe/publish-batch" => {
            client
                .poe()
                .publish_batch(&PublishBatchInput {
                    records: vec![PublishBatchEntry {
                        record: vec![0xaa],
                        quote_id: QUOTE_ID.to_string(),
                        signatures: None,
                    }],
                    idempotency_key: None,
                })
                .unwrap();
        }
        "/poe/uploads" => {
            client
                .poe()
                .uploads(&UploadsInput {
                    target: "arweave".to_string(),
                    data: vec![vec![0xaa]],
                    idempotency_key: None,
                })
                .unwrap();
        }
        other => panic!("matrix suffix has no driver: {other:?}"),
    }
    mock(ptr).first().url
}

/// The shared cross-SDK base_url-join parity matrix, loaded from a fixture that
/// is mirrored BYTE-IDENTICALLY across the three Label 309 SDKs
/// (label-309-ts, label-309-py, label-309-rs); each carries its own
/// self-contained copy because they publish to separate repositories. Any edit
/// to the matrix MUST be applied to all three copies in lockstep.
///
/// The contract: the configured `base_url` carries the gateway's version
/// segment, the client trims surrounding ASCII whitespace, strips AT MOST ONE
/// trailing slash, and appends the bare resource suffix by plain string
/// concatenation. Given the same `base_url`, every SDK must emit byte-identical
/// request URLs. Every suffix is driven through the real namespace call so the
/// assertion exercises the production join path.
///
/// The `…/api/v1//` rows are load-bearing: a base ending in two slashes must
/// strip exactly one (leaving one), proving the normalisation collapses no
/// further and never re-parses — the discriminator that catches a
/// `trim_end_matches('/')` that would strip every trailing slash. The
/// whitespace-wrapped rows pin the trim-before-join. The `origin-only` rows
/// prove the client injects no `/api/v1` of its own.
#[test]
fn base_url_join_convention_parity_matrix() {
    let tx = "a".repeat(64);
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/client-url-join/base-url-join-vectors.json");
    let vectors = common::read_fixture_json(&path);
    let cases = vectors["cases"].as_array().expect("matrix has a `cases` array");

    // Every suffix in the matrix must have a driver, and every driver must be
    // exercised by the matrix — a divergence means a suffix was added/removed on
    // one side. `drive_join_suffix` panics on an unknown suffix, covering the
    // first direction; this asserts the matrix references no stale suffix-set.
    let suffixes: std::collections::BTreeSet<String> = cases
        .iter()
        .map(|c| c["suffix"].as_str().unwrap().to_string())
        .collect();
    let expected_suffixes: std::collections::BTreeSet<String> = [
        "/records",
        &format!("/records/{tx}"),
        "/account/balance",
        "/poe/quote",
        "/poe/publish",
        "/poe/publish-batch",
        "/poe/uploads",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(suffixes, expected_suffixes, "matrix suffix set drifted");

    for case in cases {
        let base_url = case["base_url"].as_str().unwrap();
        let suffix = case["suffix"].as_str().unwrap();
        let expected = case["expected_url"].as_str().unwrap();
        let name = case["name"].as_str().unwrap();
        let actual = drive_join_suffix(suffix, base_url, &tx);
        assert_eq!(actual, expected, "case {name}: base_url {base_url:?} must join to {expected:?}");
    }
}

// ---------------------------------------------------------------------------
// Records list
// ---------------------------------------------------------------------------

#[test]
fn records_list_returns_page_of_record_resources_with_sealed_filter() {
    let rows = serde_json::json!([
        record_resource_row(&"a".repeat(64)),
        record_resource_row(&"b".repeat(64)),
    ]);
    let body = records_list_body(rows, true, Some("opaque-next"));
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, ptr) = client_with("http://test.example/api/v1",Some(&bearer_key()), transport);

    let out = client
        .records()
        .list(Some(&RecordsListInput {
            cursor: Some("eyJjdXIiOjF9".to_string()),
            limit: Some(25),
            sealed: Some(true),
        }))
        .unwrap();
    // The page projects to the same RecordResource shape records.get returns.
    assert_eq!(out.object, "list");
    assert_eq!(out.data.len(), 2);
    assert_eq!(out.data[0].tx_hash, "a".repeat(64));
    assert_eq!(out.data[0].metadata_cbor_base64, "oWNmb29jYmFy");
    assert_eq!(out.data[1].tx_hash, "b".repeat(64));
    assert_eq!(out.next_cursor.as_deref(), Some("opaque-next"));
    assert!(out.has_more);
    // The gateway omits `tip_block_height`, so the SDK derives it from the page
    // as max(block_height + num_confirmations - 1) = 100 + 15 - 1.
    assert_eq!(out.tip_block_height, Some(114));

    let url = mock(ptr).first().url;
    assert!(url.contains("http://test.example/api/v1/records?"));
    assert!(url.contains("sealed=true"));
    assert!(url.contains("limit=25"));
    assert!(url.contains("cursor=eyJjdXIiOjF9"));
    assert!(!url.contains("/api/v1/poe/"));
}

#[test]
fn records_list_omits_sealed_filter_and_query_when_no_input() {
    let body = records_list_body(serde_json::json!([]), false, None);
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, ptr) = client_with("http://test.example/api/v1",Some(&bearer_key()), transport);
    let out = client.records().list(None).unwrap();
    assert_eq!(out.data.len(), 0);
    // An empty page has no anchored rows to derive a tip from.
    assert_eq!(out.tip_block_height, None);
    // No input → the bare endpoint with no query string (no `sealed`).
    let url = mock(ptr).first().url;
    assert_eq!(url, "http://test.example/api/v1/records");
    assert!(!url.contains("sealed"));
}

#[test]
fn records_list_honours_gateway_supplied_tip_block_height() {
    // A gateway that reports `tip_block_height` populates confirmation data
    // directly; the SDK must NOT overwrite it with the page-derived value.
    let rows = serde_json::json!([record_resource_row(&"a".repeat(64))]);
    let mut body = records_list_body(rows, false, None);
    body.as_object_mut()
        .unwrap()
        .insert("tip_block_height".to_string(), serde_json::json!(9000));
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, _ptr) = client_with("http://test.example/api/v1",Some(&bearer_key()), transport);
    let out = client.records().list(None).unwrap();
    // Gateway-reported tip wins over the derived 100 + 15 - 1 = 114.
    assert_eq!(out.tip_block_height, Some(9000));
}

#[test]
fn records_list_omits_sealed_when_filter_is_false() {
    // sealed: Some(false) lists every record the caller may read — the filter is
    // applied only when explicitly true, matching the reference.
    let body = records_list_body(serde_json::json!([]), false, None);
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, ptr) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    client
        .records()
        .list(Some(&RecordsListInput {
            cursor: None,
            limit: Some(10),
            sealed: Some(false),
        }))
        .unwrap();
    let url = mock(ptr).first().url;
    assert!(!url.contains("sealed"));
    assert!(url.contains("limit=10"));
}

#[test]
fn records_list_raises_unauthorized_on_401() {
    let body = problem_body(serde_json::json!({
        "type": "about:blank", "title": "Unauthorized", "status": 401,
        "detail": "Authentication required.", "code": "unauthorized",
    }));
    let transport = Box::new(MockTransport::single(StubResponse::json(401, body)));
    let (client, _) = client_with("http://test/api/v1",None, transport);
    let err = http_err(
        client
            .records()
            .list(Some(&RecordsListInput {
                cursor: None,
                limit: None,
                sealed: Some(true),
            }))
            .unwrap_err(),
    );
    assert!(matches!(err.kind(), HttpErrorKind::Unauthorized));
}

// ---------------------------------------------------------------------------
// Records get / verify
// ---------------------------------------------------------------------------

#[test]
fn records_get_parses_resource_and_owner_field() {
    let body = serde_json::json!({
        "tx_hash": "a".repeat(64),
        "status": "confirmed",
        "block_height": 12_345_678,
        "block_time": "2026-01-01T00:00:00.000Z",
        "num_confirmations": 100,
        "scheme": 0,
        "item_count": 1,
        "signer_ed25519": null,
        "metadata_cbor_base64": "oWNmb29jYmFy",
        "account_id": "acct_06bqrjg0csvqfanaqexvqexvqc",
    });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, ptr) = client_with("http://test.example/api/v1",Some(&bearer_key()), transport);
    let out = client.records().get(&"a".repeat(64)).unwrap();
    assert_eq!(out.status.as_deref(), Some("confirmed"));
    assert_eq!(out.scheme, 0);
    assert_eq!(out.account_id.as_deref(), Some("acct_06bqrjg0csvqfanaqexvqexvqc"));
    let url = mock(ptr).first().url;
    assert_eq!(url, format!("http://test.example/api/v1/records/{}", "a".repeat(64)));
    assert!(!url.contains("/api/v1/poe/"));
}

// ---------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------

#[test]
fn account_balance_gets_endpoint_and_returns_micros_as_string() {
    let body = serde_json::json!({ "balance_usd_micros": "1234567" });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, ptr) = client_with("http://test.example/api/v1",Some(&bearer_key()), transport);

    let out: AccountBalance = client.account().balance().unwrap();
    assert_eq!(out.balance_usd_micros, "1234567");

    let captured = mock(ptr).first();
    assert_eq!(captured.url, "http://test.example/api/v1/account/balance");
    assert_eq!(captured.method, HttpMethod::Get);
    assert_eq!(
        header(&captured, "authorization").as_deref(),
        Some(format!("Bearer {}", bearer_key()).as_str())
    );
}

#[test]
fn account_balance_preserves_value_past_2_to_the_53_verbatim() {
    // 2^53 + 1 — the first integer an f64 cannot represent exactly. The decimal
    // string must survive byte-for-byte (never round-tripped through a number).
    let huge = "9007199254740993";
    let body = serde_json::json!({ "balance_usd_micros": huge });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, _) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let out = client.account().balance().unwrap();
    assert_eq!(out.balance_usd_micros, huge);
}

#[test]
fn account_balance_reads_zero_for_account_with_no_ledger_activity() {
    let body = serde_json::json!({ "balance_usd_micros": "0" });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, _) = client_with("http://test/api/v1",None, transport);
    let out = client.account().balance().unwrap();
    assert_eq!(out.balance_usd_micros, "0");
}

#[test]
fn account_balance_raises_insufficient_scope_on_403() {
    let body = problem_body(serde_json::json!({
        "code": "insufficient-scope", "status": 403,
        "required": ["account:read"], "granted": ["poe:read"],
    }));
    let transport = Box::new(MockTransport::single(StubResponse::json(403, body)));
    let (client, _) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let err = http_err(client.account().balance().unwrap_err());
    match err.kind() {
        HttpErrorKind::InsufficientScope {
            required_scopes,
            granted_scopes,
        } => {
            assert_eq!(required_scopes, &["account:read"]);
            assert_eq!(granted_scopes, &["poe:read"]);
        }
        other => panic!("expected InsufficientScope, got {other:?}"),
    }
}

#[test]
fn account_balance_raises_unauthorized_on_401_when_anonymous() {
    let body = problem_body(serde_json::json!({ "code": "unauthorized", "status": 401 }));
    let transport = Box::new(MockTransport::single(StubResponse::json(401, body)));
    let (client, _) = client_with("http://test/api/v1",None, transport);
    let err = http_err(client.account().balance().unwrap_err());
    assert!(matches!(err.kind(), HttpErrorKind::Unauthorized));
}

// ---------------------------------------------------------------------------
// publish-batch
// ---------------------------------------------------------------------------

#[test]
fn publish_batch_posts_records_and_parses_mixed_results() {
    let body = serde_json::json!({
        "results": [
            {
                "record_idx": 0,
                "id": "poe_06bqrjg0csvqfanaqexvqexvqc",
                "tx_hash": null,
                "status": "submitting",
                "items_count": 1,
                "signed": false,
                "sealed": false,
                "items": [],
                "conformance_profile": "core",
            },
            {
                "record_idx": 1,
                "error": { "code": "malformed-cbor", "detail": "record is not canonical CBOR." },
            },
        ],
        "balance_after_usd_micros": "4320000",
    });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, ptr) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let out = client
        .poe()
        .publish_batch(&PublishBatchInput {
            records: vec![
                PublishBatchEntry { record: vec![0xaa], quote_id: QUOTE_ID.to_string(), signatures: None },
                PublishBatchEntry {
                    record: vec![0xbb, 0xcc],
                    quote_id: "01956b41-7c00-7000-8000-000000000002".to_string(),
                    signatures: None,
                },
            ],
            idempotency_key: None,
        })
        .unwrap();
    assert_eq!(out.results.len(), 2);
    assert_eq!(out.balance_after_usd_micros, "4320000");
    // Partial-failure result shape: one success, one per-record failure.
    match &out.results[0] {
        PublishBatchResultEntry::Success(s) => assert_eq!(s.record_idx, 0),
        other => panic!("expected success, got {other:?}"),
    }
    match &out.results[1] {
        PublishBatchResultEntry::Failure(f) => {
            assert_eq!(f.record_idx, 1);
            assert_eq!(f.error.code, "malformed-cbor");
        }
        other => panic!("expected failure, got {other:?}"),
    }

    let captured = mock(ptr).first();
    assert_eq!(captured.url, "http://test/api/v1/poe/publish-batch");
    let sent: serde_json::Value = serde_json::from_str(captured.body.as_json()).unwrap();
    assert_eq!(sent["records"][0]["record"], "aa");
    assert_eq!(sent["records"][0]["quote_id"], QUOTE_ID);
    assert_eq!(sent["records"][1]["record"], "bbcc");
}

#[test]
fn publish_batch_surfaces_batch_too_large() {
    let body = problem_body(serde_json::json!({ "code": "batch-too-large", "status": 400, "max": 50, "got": 73 }));
    let transport = Box::new(MockTransport::single(StubResponse::json(400, body)));
    let (client, _) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let err = http_err(
        client
            .poe()
            .publish_batch(&PublishBatchInput {
                records: vec![PublishBatchEntry {
                    record: vec![0xaa],
                    quote_id: QUOTE_ID.to_string(),
                    signatures: None,
                }],
                idempotency_key: None,
            })
            .unwrap_err(),
    );
    match err.kind() {
        HttpErrorKind::BatchTooLarge { max, got } => {
            assert_eq!(*max, Some(50));
            assert_eq!(*got, Some(73));
        }
        other => panic!("expected BatchTooLarge, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// High-level publish helpers
// ---------------------------------------------------------------------------

/// A deterministic in-memory Ed25519 signer, mirroring the integrator wiring.
struct InMemorySigner {
    signing: ed25519_dalek::SigningKey,
    pubkey: Vec<u8>,
}

impl InMemorySigner {
    fn from_seed(seed: [u8; 32]) -> Self {
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = signing.verifying_key().to_bytes().to_vec();
        Self { signing, pubkey }
    }
}

impl Signer for InMemorySigner {
    fn signer_pubkey(&self) -> Vec<u8> {
        self.pubkey.clone()
    }
    fn sign(&self, sig_structure_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
        use ed25519_dalek::Signer as _;
        Ok(self.signing.sign(sig_structure_bytes).to_bytes().to_vec())
    }
}

#[test]
fn publish_content_signs_and_posts_single_item_record() {
    let transport = Box::new(MockTransport::single(StubResponse::json(202, publish_success_body())));
    let (client, ptr) = client_with("http://test.example/api/v1",Some(&bearer_key()), transport);
    let signer = InMemorySigner::from_seed([0x42; 32]);
    let out = client
        .poe()
        .publish_content(&PublishContentInput {
            content: b"hello world".to_vec(),
            quote_id: QUOTE_ID.to_string(),
            hash_alg: None,
            signer: Some(&signer),
            idempotency_key: None,
        })
        .unwrap();
    assert_eq!(out.id, "poe_06bqrjg0csvqfanaqexvqexvqc");
    assert!(!out.dedup_hit);

    let captured = mock(ptr).first();
    assert!(captured.url.ends_with("/api/v1/poe/publish"));
    let sent: serde_json::Value = serde_json::from_str(captured.body.as_json()).unwrap();
    assert_eq!(sent["quote_id"], QUOTE_ID);
    // Round-trip the posted record through the structural validator.
    let record_bytes = hex::decode(sent["record"].as_str().unwrap()).unwrap();
    let result = validate_poe_record(&record_bytes, &ValidatorOptions::default());
    let record = match result {
        cardanowall::poe_standard::ValidateResult::Ok { record, .. } => *record,
        cardanowall::poe_standard::ValidateResult::Fail { issues } => {
            panic!("record failed validation: {issues:?}")
        }
    };
    assert_eq!(record.v, 1);
    let items = record.items.unwrap();
    assert_eq!(items.len(), 1);
    let (alg, digest) = &items[0].hashes[0];
    assert_eq!(alg, "sha2-256");
    assert_eq!(digest, &cardanowall::hash::sha256(b"hello world").to_vec());
    assert_eq!(record.sigs.unwrap().len(), 1);
}

#[test]
fn publish_content_unsigned_omits_sigs() {
    let transport = Box::new(MockTransport::single(StubResponse::json(202, publish_success_body())));
    let (client, ptr) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    client
        .poe()
        .publish_content(&PublishContentInput {
            content: b"hello".to_vec(),
            quote_id: QUOTE_ID.to_string(),
            hash_alg: None,
            signer: None,
            idempotency_key: None,
        })
        .unwrap();
    let sent: serde_json::Value = serde_json::from_str(mock(ptr).first().body.as_json()).unwrap();
    let record_bytes = hex::decode(sent["record"].as_str().unwrap()).unwrap();
    let record = match validate_poe_record(&record_bytes, &ValidatorOptions::default()) {
        cardanowall::poe_standard::ValidateResult::Ok { record, .. } => *record,
        other => panic!("validation failed: {other:?}"),
    };
    assert!(record.sigs.is_none());
}

#[test]
fn publish_content_supports_blake2b_256() {
    let transport = Box::new(MockTransport::single(StubResponse::json(202, publish_success_body())));
    let (client, ptr) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    client
        .poe()
        .publish_content(&PublishContentInput {
            content: vec![0xaa, 0xbb, 0xcc],
            quote_id: QUOTE_ID.to_string(),
            hash_alg: Some(SupportedHashAlg::Blake2b256),
            signer: None,
            idempotency_key: None,
        })
        .unwrap();
    let sent: serde_json::Value = serde_json::from_str(mock(ptr).first().body.as_json()).unwrap();
    let record_bytes = hex::decode(sent["record"].as_str().unwrap()).unwrap();
    let record = match validate_poe_record(&record_bytes, &ValidatorOptions::default()) {
        cardanowall::poe_standard::ValidateResult::Ok { record, .. } => *record,
        other => panic!("validation failed: {other:?}"),
    };
    let items = record.items.unwrap();
    let algs: Vec<&str> = items[0].hashes.iter().map(|(a, _)| a.as_str()).collect();
    assert_eq!(algs, vec!["blake2b-256"]);
}

#[test]
fn publish_prehashed_validates_and_posts_supplied_digest() {
    let transport = Box::new(MockTransport::single(StubResponse::json(202, publish_success_body())));
    let (client, ptr) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let digest = hex::encode(cardanowall::hash::sha256(b"prehashed"));
    client
        .poe()
        .publish_prehashed(&PublishPrehashedInput {
            hashes: vec![(SupportedHashAlg::Sha2_256, digest.clone())],
            quote_id: QUOTE_ID.to_string(),
            signer: None,
            idempotency_key: None,
        })
        .unwrap();
    let sent: serde_json::Value = serde_json::from_str(mock(ptr).first().body.as_json()).unwrap();
    let record_bytes = hex::decode(sent["record"].as_str().unwrap()).unwrap();
    let record = match validate_poe_record(&record_bytes, &ValidatorOptions::default()) {
        cardanowall::poe_standard::ValidateResult::Ok { record, .. } => *record,
        other => panic!("validation failed: {other:?}"),
    };
    assert_eq!(hex::encode(&record.items.unwrap()[0].hashes[0].1), digest);
}

#[test]
fn publish_prehashed_rejects_wrong_length_digest() {
    let transport = Box::new(MockTransport::single(StubResponse::json(202, publish_success_body())));
    let (client, _) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let err = client
        .poe()
        .publish_prehashed(&PublishPrehashedInput {
            hashes: vec![(SupportedHashAlg::Sha2_256, "aabb".to_string())],
            quote_id: QUOTE_ID.to_string(),
            signer: None,
            idempotency_key: None,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        cardanowall::client::PublishHelperError::Validation(
            cardanowall::client::PublishError::InvalidDigest
        )
    ));
}

#[test]
fn publish_sealed_encrypts_uploads_and_publishes_with_ar_uri() {
    let ar_uri = format!("ar://{}", "C".repeat(43));
    let uploads_body = serde_json::json!({
        "uploads": [{ "idx": 0, "ok": true, "uri": ar_uri, "sha256": "00".repeat(32), "bytes": 42 }],
    });
    let transport = Box::new(MockTransport::new(vec![
        StubResponse::json(200, uploads_body),
        StubResponse::json(202, publish_success_body()),
    ]));
    let (client, ptr) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let recipient = vec![0x07_u8; 32];
    client
        .poe()
        .publish_sealed(&PublishSealedInput {
            content: b"secret".to_vec(),
            recipients: vec![recipient],
            quote_id: QUOTE_ID.to_string(),
            hash_alg: None,
            kem: Some(SealedKemChoice::X25519),
            signer: None,
            idempotency_key: None,
            chunk_bytes: None,
        })
        .unwrap();
    // Two calls: uploads then publish.
    assert_eq!(mock(ptr).call_count(), 2);
    let publish_req = mock(ptr).nth(1);
    let sent: serde_json::Value = serde_json::from_str(publish_req.body.as_json()).unwrap();
    let record_bytes = hex::decode(sent["record"].as_str().unwrap()).unwrap();
    // Decode the posted record with the independent CBOR oracle and assert the
    // sealed envelope's wire shape directly.
    let record: ciborium::Value = ciborium::from_reader(record_bytes.as_slice()).unwrap();
    let lookup = |map: &ciborium::Value, key: &str| -> Option<ciborium::Value> {
        map.as_map().and_then(|pairs| {
            pairs
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v.clone())
        })
    };
    let item = lookup(&record, "items").unwrap().as_array().unwrap()[0].clone();
    let enc = lookup(&item, "enc").expect("the published item carries an enc envelope");
    assert_eq!(lookup(&enc, "kem").unwrap().as_text(), Some("x25519"));
    assert_eq!(
        lookup(&enc, "aead").unwrap().as_text(),
        Some("chacha20-poly1305-stream64k")
    );
    assert_eq!(lookup(&enc, "nonce").unwrap().as_bytes().unwrap().len(), 24);
    assert_eq!(lookup(&enc, "slots_mac").unwrap().as_bytes().unwrap().len(), 32);
    // One classical slot, carrying a 32-byte epk and a 48-byte wrap.
    let slots = lookup(&enc, "slots").unwrap().as_array().unwrap().to_vec();
    assert_eq!(slots.len(), 1);
    assert_eq!(lookup(&slots[0], "epk").unwrap().as_bytes().unwrap().len(), 32);
    assert_eq!(lookup(&slots[0], "wrap").unwrap().as_bytes().unwrap().len(), 48);
    // The ar:// upload URI lands on the item.
    assert!(lookup(&item, "uris").is_some());
}

#[test]
fn publish_sealed_rejects_empty_and_wrong_length_recipients() {
    let transport = Box::new(MockTransport::single(StubResponse::json(202, publish_success_body())));
    let (client, _) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let empty = client.poe().publish_sealed(&PublishSealedInput {
        content: b"x".to_vec(),
        recipients: vec![],
        quote_id: QUOTE_ID.to_string(),
        hash_alg: None,
        kem: None,
        signer: None,
        idempotency_key: None,
        chunk_bytes: None,
    });
    assert!(matches!(
        empty.unwrap_err(),
        cardanowall::client::PublishHelperError::Validation(
            cardanowall::client::PublishError::InvalidRecipient
        )
    ));

    let transport = Box::new(MockTransport::single(StubResponse::json(202, publish_success_body())));
    let (client, _) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let wrong = client.poe().publish_sealed(&PublishSealedInput {
        content: b"x".to_vec(),
        recipients: vec![vec![0u8; 31]],
        quote_id: QUOTE_ID.to_string(),
        hash_alg: None,
        kem: Some(SealedKemChoice::X25519),
        signer: None,
        idempotency_key: None,
        chunk_bytes: None,
    });
    assert!(matches!(
        wrong.unwrap_err(),
        cardanowall::client::PublishHelperError::Validation(
            cardanowall::client::PublishError::InvalidRecipient
        )
    ));
}

#[test]
fn publish_sealed_escalates_partial_upload_failure() {
    // The single-shot /uploads route returns a per-file rejection with a SPECIFIC
    // code + detail. The resumable path runs this small blob single-shot; the
    // failure must surface as a PartialUploadError whose failed[0] carries the
    // VERBATIM original code + detail (not a flattened synthetic "upload-failed"),
    // so the CLI and callers see the same diagnostic the single-shot route emits.
    let uploads_body = serde_json::json!({
        "uploads": [{ "idx": 0, "ok": false, "error": { "code": "storage-provider-rejected", "detail": "arweave timeout" } }],
    });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, uploads_body)));
    let (client, _) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let err = client
        .poe()
        .publish_sealed(&PublishSealedInput {
            content: b"x".to_vec(),
            recipients: vec![vec![0x07; 32]],
            quote_id: QUOTE_ID.to_string(),
            hash_alg: None,
            kem: Some(SealedKemChoice::X25519),
            signer: None,
            idempotency_key: None,
            chunk_bytes: None,
        })
        .unwrap_err();
    match err {
        cardanowall::client::PublishHelperError::PartialUpload(p) => {
            // The index-0 contract the CLI relies on is preserved.
            assert_eq!(p.failed_indices(), vec![0]);
            // The original per-file code + detail survive verbatim.
            match &p.failed[0] {
                cardanowall::client::UploadEntry::Failure { idx, error, .. } => {
                    assert_eq!(*idx, 0);
                    assert_eq!(error.code, "storage-provider-rejected");
                    assert_eq!(error.detail, "arweave timeout");
                }
                other => panic!("expected a Failure entry, got {other:?}"),
            }
        }
        other => panic!("expected PartialUpload, got {other:?}"),
    }
}

#[test]
fn publish_merkle_binds_root_and_leaf_count() {
    let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| cardanowall::hash::sha256(&[i])).collect();
    let expected_root = cardanowall::merkle::merkle_root(&leaves).unwrap();
    let ar_uri = format!("ar://{}", "X".repeat(43));
    let uploads_body = serde_json::json!({
        "uploads": [{ "idx": 0, "ok": true, "uri": ar_uri.clone(), "sha256": "00".repeat(32), "bytes": 42 }],
    });
    let transport = Box::new(MockTransport::new(vec![
        StubResponse::json(200, uploads_body),
        StubResponse::json(202, publish_success_body()),
    ]));
    let (client, ptr) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let signer = InMemorySigner::from_seed([0x42; 32]);
    let out = client
        .poe()
        .publish_merkle(&PublishMerkleInput {
            leaves: leaves.iter().map(|l| MerkleLeaf::Bytes(l.to_vec())).collect(),
            quote_id: QUOTE_ID.to_string(),
            hash_alg: None,
            signer: Some(&signer),
            idempotency_key: None,
            chunk_bytes: None,
        })
        .unwrap();
    assert_eq!(out.leaf_count, 4);
    assert_eq!(out.root, hex::encode(expected_root));
    assert_eq!(out.ar_uri, ar_uri);

    let publish_req = mock(ptr).nth(1);
    let sent: serde_json::Value = serde_json::from_str(publish_req.body.as_json()).unwrap();
    let record_bytes = hex::decode(sent["record"].as_str().unwrap()).unwrap();
    let record = match validate_poe_record(&record_bytes, &ValidatorOptions::default()) {
        cardanowall::poe_standard::ValidateResult::Ok { record, .. } => *record,
        other => panic!("validation failed: {other:?}"),
    };
    let merkle = record.merkle.unwrap();
    assert_eq!(merkle.len(), 1);
    assert_eq!(merkle[0].leaf_count, 4);
    assert_eq!(merkle[0].root, expected_root.to_vec());
}

#[test]
fn publish_merkle_rejects_empty_leaves() {
    let transport = Box::new(MockTransport::single(StubResponse::json(202, publish_success_body())));
    let (client, _) = client_with("http://test/api/v1",Some(&bearer_key()), transport);
    let err = client
        .poe()
        .publish_merkle(&PublishMerkleInput {
            leaves: vec![],
            quote_id: QUOTE_ID.to_string(),
            hash_alg: None,
            signer: None,
            idempotency_key: None,
            chunk_bytes: None,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        cardanowall::client::PublishHelperError::Validation(
            cardanowall::client::PublishError::InvalidLeaves
        )
    ));
}

// ---------------------------------------------------------------------------
// Real-socket: the client transport must NOT follow redirects either. The
// deny-host / SSRF guard checks only the original URL; an un-rechecked Location
// hop could pivot to a blocked host. A 3xx surfaces as a non-2xx status.
// ---------------------------------------------------------------------------

#[test]
fn client_transport_does_not_follow_redirects() {
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // The "internal" target the redirect points at. It must never be contacted.
    let internal_reached = Arc::new(AtomicBool::new(false));
    let internal_flag = Arc::clone(&internal_reached);
    let internal = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let internal_addr = internal.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = internal.accept() {
            internal_flag.store(true, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nINTERNAL-SECRET",
            );
            let _ = stream.flush();
        }
    });

    // The hostile gateway: a one-shot loopback server returning a 302 to the
    // internal target.
    let location = format!("http://127.0.0.1:{}/metadata", internal_addr.port());
    let gateway = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let gateway_addr = gateway.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = gateway.accept() {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });

    // The default client transport carries an empty deny-host list, so the
    // loopback request connects (the non-webhook egress does not IP-block here);
    // this isolates the redirect-policy behaviour under test.
    let transport = cardanowall::client::ReqwestClientTransport::new();
    let url = format!("http://127.0.0.1:{}/redirect", gateway_addr.port());
    let response = transport
        .send(&url, HttpMethod::Get, &[], &RequestBody::None)
        .expect("loopback gateway request succeeds");

    assert_eq!(response.status, 302, "the 3xx must surface as the status");
    assert_ne!(
        response.body, b"INTERNAL-SECRET",
        "the internal body must never be returned"
    );
    assert!(
        !internal_reached.load(Ordering::SeqCst),
        "the redirect target must never be contacted"
    );
}

// ---------------------------------------------------------------------------
// Records count
// ---------------------------------------------------------------------------

#[test]
fn records_count_sends_the_signer_and_filters_and_parses_the_count() {
    // The count is publisher-scoped: the signer is always on the query, and the
    // optional filters (scheme/sealed/block/time) ride alongside it with the
    // list route's parameter names. The body parses to { object: "count", count,
    // url }.
    let signer = "b".repeat(64);
    let body = serde_json::json!({
        "object": "count",
        "count": 4242,
        "url": "/api/v1/records/count",
    });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, ptr) = client_with("http://test/api/v1", Some(&bearer_key()), transport);

    let input = cardanowall::client::RecordsCountInput {
        signer: signer.clone(),
        scheme: Some(1),
        sealed: Some(true),
        from_block: Some(100),
        to_block: Some(200),
        from_time: Some("2026-01-01T00:00:00Z".to_string()),
        to_time: Some("2026-02-01T00:00:00Z".to_string()),
    };
    let out = client.records().count(&input).unwrap();

    assert_eq!(out.object, "count");
    assert_eq!(out.count, 4242);
    assert_eq!(out.url, "/api/v1/records/count");

    let req = mock(ptr).first();
    assert_eq!(req.method, HttpMethod::Get);
    let url = req.url;
    assert!(url.starts_with("http://test/api/v1/records/count?"), "url was {url}");
    assert!(url.contains(&format!("signer={signer}")));
    assert!(url.contains("scheme=1"));
    assert!(url.contains("sealed=true"));
    assert!(url.contains("from_block=100"));
    assert!(url.contains("to_block=200"));
    // Time values are percent-encoded the URLSearchParams way (':' -> %3A).
    assert!(url.contains("from_time=2026-01-01T00%3A00%3A00Z"));
    assert!(url.contains("to_time=2026-02-01T00%3A00%3A00Z"));
}

#[test]
fn records_count_minimal_input_sends_only_the_signer() {
    let signer = "c".repeat(64);
    let body = serde_json::json!({ "object": "count", "count": 0, "url": "/api/v1/records/count" });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, ptr) = client_with("http://test/api/v1", Some(&bearer_key()), transport);

    let out = client
        .records()
        .count(&cardanowall::client::RecordsCountInput::new(signer.clone()))
        .unwrap();
    assert_eq!(out.count, 0);

    let url = mock(ptr).first().url;
    assert!(url.ends_with(&format!("/records/count?signer={signer}")), "url was {url}");
    assert!(!url.contains("scheme"));
    assert!(!url.contains("sealed"));
}

#[test]
fn records_count_surfaces_validation_failed_without_a_valid_signer() {
    // The gateway 422s a count whose signer is missing/invalid; the client
    // surfaces that as a typed error (the SDK always sends a signer string, so
    // this exercises the gateway rejecting a malformed one).
    let body = problem_body(serde_json::json!({
        "status": 422, "code": "validation-failed",
        "detail": "signer must be 64 lowercase hex characters (a 32-byte Ed25519 key)",
    }));
    let transport = Box::new(MockTransport::single(StubResponse::json(422, body)));
    let (client, _) = client_with("http://test/api/v1", Some(&bearer_key()), transport);
    let err = http_err(
        client
            .records()
            .count(&cardanowall::client::RecordsCountInput::new("not-hex"))
            .unwrap_err(),
    );
    assert_eq!(err.http_status(), 422);
    assert_eq!(err.code(), "validation-failed");
}

// ---------------------------------------------------------------------------
// Quote breakdown (additive deserialize)
// ---------------------------------------------------------------------------

#[test]
fn quote_parses_the_optional_breakdown_when_present() {
    // A breakdown-exposing gateway returns the additive fields; they parse onto
    // the optional QuoteResponse fields without disturbing the always-present
    // opaque token.
    let body = serde_json::json!({
        "quote_id": QUOTE_ID,
        "amount": "1250000",
        "currency": "USD",
        "expires_at": "2026-06-15T00:15:00Z",
        "usd_micros": "1250000",
        "breakdown": {
            "network_usd_micros": "171617",
            "storage_usd_micros": "1000000",
            "service_usd_micros": "78383",
        },
        "margin_pct": 0.07,
        "margin_source": "operator-default",
        "fx_age_seconds": 42,
    });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, _) = client_with("http://test/api/v1", Some(&bearer_key()), transport);
    let q = client
        .poe()
        .quote(&cardanowall::client::QuoteInput {
            record_bytes: 1,
            recipient_count: 0,
            file_bytes_total: 0,
        })
        .unwrap();

    assert_eq!(q.quote_id, QUOTE_ID);
    assert_eq!(q.amount, "1250000");
    assert_eq!(q.usd_micros.as_deref(), Some("1250000"));
    let bd = q.breakdown.expect("breakdown present");
    assert_eq!(bd.network_usd_micros, "171617");
    assert_eq!(bd.storage_usd_micros, "1000000");
    assert_eq!(bd.service_usd_micros, "78383");
    assert_eq!(q.margin_pct, Some(0.07));
    assert_eq!(q.margin_source.as_deref(), Some("operator-default"));
    assert_eq!(q.fx_age_seconds, Some(42));
}

#[test]
fn quote_without_a_breakdown_still_parses_with_none_fields() {
    // A non-breakdown gateway returns only the opaque token; the additive fields
    // default to None, so an older/minimal gateway is parsed unchanged.
    let body = serde_json::json!({
        "quote_id": QUOTE_ID,
        "amount": "1250000",
        "currency": "USD",
        "expires_at": "2026-06-15T00:15:00Z",
    });
    let transport = Box::new(MockTransport::single(StubResponse::json(200, body)));
    let (client, _) = client_with("http://test/api/v1", Some(&bearer_key()), transport);
    let q = client
        .poe()
        .quote(&cardanowall::client::QuoteInput {
            record_bytes: 1,
            recipient_count: 0,
            file_bytes_total: 0,
        })
        .unwrap();
    assert_eq!(q.quote_id, QUOTE_ID);
    assert!(q.usd_micros.is_none());
    assert!(q.breakdown.is_none());
    assert!(q.margin_pct.is_none());
    assert!(q.margin_source.is_none());
    assert!(q.fx_age_seconds.is_none());
}
