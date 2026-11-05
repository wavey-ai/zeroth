use super::*;

#[test]
fn empty_optional_filters_from_the_customer_form_do_not_break_pagination() {
    let url = url::Url::parse("https://id.example/audit?organization_id=org-a&event_type=&actor_id=&outcome=&from=&until=").unwrap();
    let parsed = audit_event_filter_from_url(&url).unwrap();
    assert_eq!(parsed.organization_id.as_deref(), Some("org-a"));
    assert_eq!(parsed.event_type, None);
    assert_eq!(parsed.actor_id, None);
    assert_eq!(parsed.from, None);
    assert_eq!(parsed.until, None);
}

#[test]
fn customer_html_escapes_legacy_audit_values_and_restricts_export_links() {
    let row: AuditEventRow = serde_json::from_value(serde_json::json!({
        "id":"evt_legacy","event_type":"<script>attack()</script>","created_at":100,
        "details_json":"{}","actor_id":"<img src=x onerror=attack()>"
    }))
    .unwrap();
    let page = AuditEventsResponse {
        events: vec![audit_event_response_from_row(row)],
        next_cursor: None,
        has_more: false,
    };
    let url = url::Url::parse("https://id.example/audit?organization_id=org-a").unwrap();
    let reader = audit_history_document(&page, &url, false);
    assert!(!reader.contains("<script>attack()"));
    assert!(!reader.contains("<img src=x"));
    assert!(reader.contains("&lt;script&gt;attack()&lt;/script&gt;"));
    assert!(!reader.contains("Download this page as CSV"));
    assert!(audit_history_document(&page, &url, true).contains("Download this page as CSV"));
}
use rusqlite::{params, params_from_iter, types::ValueRef, Connection};
use std::collections::HashSet;

fn database() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    for migration in zeroth_storage::migrations::ALL {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn
}

fn seed(
    conn: &Connection,
    id: &str,
    organization: Option<&str>,
    recorded_at: Option<i64>,
    created_at: i32,
) {
    conn.execute(
        "INSERT INTO zeroth_audit_events (
             id, event_type, user_id, client_id, provider_id, created_at, details_json,
             schema_version, organization_id, actor_type, actor_id, target_type, target_id,
             outcome, reason_code, request_id, recorded_at, event_json
         ) VALUES (?, 'client.upsert', 'shared-user', 'shared-client', 'entra', ?, '{}',
                   ?, ?, 'user', 'administrator', 'client', 'application', 'success',
                   'configuration_updated', 'request-1', ?, ?)",
        params![
            id,
            created_at,
            i32::from(recorded_at.is_some()),
            organization,
            recorded_at,
            recorded_at
                .map(|_| serde_json::json!({ "event_id": id, "schema_version": 1 }).to_string())
        ],
    )
    .unwrap();
}

fn rows(conn: &Connection, filter: &AuditEventFilter) -> Vec<AuditEventRow> {
    let query = audit_event_query(filter).unwrap();
    let mut statement = conn.prepare(&query.sql).unwrap();
    let columns = statement
        .column_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    statement
        .query_map(params_from_iter(query.parameters.iter()), |row| {
            let mut value = serde_json::Map::new();
            for (index, column) in columns.iter().enumerate() {
                value.insert(
                    column.clone(),
                    match row.get_ref(index)? {
                        ValueRef::Null => serde_json::Value::Null,
                        ValueRef::Integer(value) => value.into(),
                        ValueRef::Real(value) => serde_json::json!(value),
                        ValueRef::Text(value) => String::from_utf8(value.to_vec()).unwrap().into(),
                        ValueRef::Blob(_) => panic!("unexpected blob"),
                    },
                );
            }
            Ok(serde_json::Value::Object(value))
        })
        .unwrap()
        .map(|value| serde_json::from_value(value.unwrap()).unwrap())
        .collect()
}

fn filter(query: &str) -> AuditEventFilter {
    audit_event_filter_from_url(
        &url::Url::parse(&format!("https://id.example/events?{query}")).unwrap(),
    )
    .unwrap()
}

#[test]
fn equal_timestamp_pages_and_legacy_fallback_have_no_gaps_or_duplicates() {
    let conn = database();
    for index in 0..137 {
        seed(
            &conn,
            &format!("evt_{index:04}"),
            Some("org-a"),
            Some(5_000_000_000),
            100,
        );
        seed(
            &conn,
            &format!("other_{index:04}"),
            Some("org-b"),
            Some(5_000_000_000),
            100,
        );
    }
    seed(&conn, "legacy", Some("org-a"), None, 90);
    let mut filter = filter("organization_id=org-a&limit=17");
    let mut observed = Vec::new();
    loop {
        let page = audit_event_page(rows(&conn, &filter), &filter).unwrap();
        assert!(page.events.len() <= 17);
        for event in page.events {
            assert_eq!(event.organization_id.as_deref(), Some("org-a"));
            observed.push(event.id);
        }
        if !page.has_more {
            assert!(page.next_cursor.is_none());
            break;
        }
        let cursor = page.next_cursor.unwrap();
        let mut url =
            url::Url::parse("https://id.example/events?organization_id=org-a&limit=17").unwrap();
        url.query_pairs_mut().append_pair("cursor", &cursor);
        filter = audit_event_filter_from_url(&url).unwrap();
    }
    let expected = (0..137)
        .rev()
        .map(|index| format!("evt_{index:04}"))
        .chain(["legacy".to_owned()])
        .collect::<Vec<_>>();
    assert_eq!(observed, expected);
    assert_eq!(
        observed.iter().collect::<HashSet<_>>().len(),
        observed.len()
    );
}

#[test]
fn organization_actor_target_time_and_outcome_filters_are_bound_and_immutable() {
    let conn = database();
    conn.execute("INSERT INTO zeroth_clients (id, name, redirect_uris_json, account_tenant_id, created_at, updated_at) VALUES ('shared-client', 'Shared', '[]', 'org-a', 1, 1)", []).unwrap();
    seed(&conn, "matching", Some("org-a"), Some(5_000_000_000), 1);
    seed(&conn, "another-org", Some("org-b"), Some(5_000_000_000), 1);
    seed(&conn, "platform-legacy", None, None, 1);
    seed(&conn, "before", Some("org-a"), Some(4_999_999_999), 1);
    seed(
        &conn,
        "until-exclusive",
        Some("org-a"),
        Some(5_000_000_001),
        1,
    );
    conn.execute("UPDATE zeroth_clients SET account_tenant_id = 'org-b'", [])
        .unwrap();
    let selected = filter(
        "organization_id=org-a&actor_type=user&actor_id=administrator&target_type=client&target_id=application&outcome=success&event_type=client.upsert&provider_id=entra&client_id=shared-client&user_id=shared-user&from=5000000000&until=5000000001",
    );
    let page = audit_event_page(rows(&conn, &selected), &selected).unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].id, "matching");
    assert_eq!(page.events[0].recorded_at, 5_000_000_000);
    assert_eq!(
        page.events[0].event.as_ref().unwrap()["event_id"],
        "matching"
    );
    assert_eq!(page.events[0].actor_id.as_deref(), Some("administrator"));
    assert_eq!(page.events[0].target_id.as_deref(), Some("application"));
    let mut injected = selected;
    injected.organization_id = Some("org-a' OR 1=1 --".to_owned());
    let query = audit_event_query(&injected).unwrap();
    assert!(!query.sql.contains("OR 1=1"));
    assert!(rows(&conn, &injected).is_empty());
}

#[test]
fn unscoped_legacy_events_remain_in_operator_history_without_inferred_organization() {
    let conn = database();
    conn.execute("INSERT INTO zeroth_audit_events (id, event_type, user_id, client_id, created_at, details_json) VALUES ('legacy', 'user.disable', 'user', 'client', 123, '{}')", []).unwrap();
    let all = AuditEventFilter::default();
    let page = audit_event_page(rows(&conn, &all), &all).unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].schema_version, 0);
    assert_eq!(page.events[0].outcome, "unknown");
    assert_eq!(page.events[0].recorded_at, 123);
    assert!(page.events[0].organization_id.is_none());
    assert!(page.events[0].actor_id.is_none());
    assert!(page.events[0].event.is_none());
    assert!(rows(&conn, &filter("organization_id=customer")).is_empty());
}

#[test]
fn pagination_cursor_binds_all_filters_but_allows_format_and_page_size_changes() {
    let conn = database();
    for id in ["a", "b", "c"] {
        seed(&conn, id, Some("org-a"), Some(100), 1);
    }
    let initial = filter("organization_id=org-a&actor_id=administrator&limit=1");
    let page = audit_event_page(rows(&conn, &initial), &initial).unwrap();
    let cursor = page.next_cursor.unwrap();
    for base in [
        "organization_id=org-b&actor_id=administrator&limit=1",
        "organization_id=org-a&actor_id=another-actor&limit=1",
        "organization_id=org-a&actor_id=administrator&from=1&limit=1",
        "organization_id=org-a&actor_id=administrator&outcome=success&limit=1",
    ] {
        let mut url = url::Url::parse(&format!("https://id.example/events?{base}")).unwrap();
        url.query_pairs_mut().append_pair("cursor", &cursor);
        assert!(audit_event_filter_from_url(&url).is_err());
    }
    let mut url = url::Url::parse(
        "https://id.example/events?actor_id=administrator&organization_id=org-a&limit=2&format=csv",
    )
    .unwrap();
    url.query_pairs_mut().append_pair("cursor", &cursor);
    let next = audit_event_filter_from_url(&url).unwrap();
    assert!(next.csv);
    let page = audit_event_page(rows(&conn, &next), &next).unwrap();
    assert_eq!(
        page.events
            .iter()
            .map(|event| event.id.as_str())
            .collect::<Vec<_>>(),
        ["b", "a"]
    );
    assert!(!page.has_more);
}

#[test]
fn malformed_unbounded_or_ambiguous_query_parameters_are_rejected() {
    for query in [
        "limit=0",
        "limit=101",
        "limit=-1",
        "limit=65536",
        "from=-1",
        "from=no",
        "until=9223372036854775808",
        "from=10&until=9",
        "organization_id=org-a&organization_id=org-b",
        "outcome=successful",
        "format=xlsx",
        "cursor=bogus",
    ] {
        assert!(
            audit_event_filter_from_url(
                &url::Url::parse(&format!("https://id.example/events?{query}")).unwrap()
            )
            .is_err(),
            "{query}"
        );
    }
    let mut url = url::Url::parse("https://id.example/events").unwrap();
    url.query_pairs_mut()
        .append_pair("cursor", &"a".repeat(2049));
    assert!(audit_event_filter_from_url(&url).is_err());
    for value in [
        serde_json::json!({ "version": 2, "recorded_at": 100, "id": "event", "filters": audit_filter_fingerprint(&AuditEventFilter::default()) }),
        serde_json::json!({ "version": 1, "recorded_at": -1, "id": "event", "filters": audit_filter_fingerprint(&AuditEventFilter::default()) }),
        serde_json::json!({ "version": 1, "recorded_at": 100, "id": "' OR 1=1", "filters": audit_filter_fingerprint(&AuditEventFilter::default()) }),
    ] {
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
        let mut url = url::Url::parse("https://id.example/events").unwrap();
        url.query_pairs_mut().append_pair("cursor", &encoded);
        assert!(audit_event_filter_from_url(&url).is_err());
    }
}

#[test]
fn csv_quotes_delimiters_and_neutralizes_spreadsheet_formula_prefixes() {
    for value in [
        "=1+1",
        "+SUM(A1)",
        "-1+2",
        "@SUM(A1)",
        " \t=1+1",
        "\ttext",
        "\rtext",
        "\ntext",
        "\u{feff} =1+1",
    ] {
        assert!(audit_csv_cell(value).starts_with("\"'"), "{value:?}");
    }
    assert_eq!(audit_csv_cell("ordinary"), "\"ordinary\"");
    assert_eq!(
        audit_csv_cell("quoted\", comma, newline\nvalue"),
        "\"quoted\"\", comma, newline\nvalue\""
    );
    let conn = database();
    for id in ["a", "b", "c"] {
        seed(&conn, id, Some("org-a"), Some(100), 1);
    }
    let filter = filter("organization_id=org-a&limit=1&format=csv");
    let page = audit_event_page(rows(&conn, &filter), &filter).unwrap();
    assert!(page.has_more);
    let csv = audit_events_csv(&page.events);
    assert!(csv.starts_with("id,recorded_at,event_type,schema_version,organization_id"));
    assert_eq!(csv.matches("\r\n").count(), 2);
    assert!(csv.contains("\"c\",\"100\""));
    assert!(!csv.contains("\"b\",\"100\""));
}

#[test]
fn organization_history_uses_the_scope_time_and_id_index() {
    let conn = database();
    let query = audit_event_query(&filter("organization_id=org-a&from=100&limit=10")).unwrap();
    let plan = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {}", query.sql))
        .unwrap()
        .query_map(params_from_iter(query.parameters.iter()), |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" ");
    assert!(
        plan.contains("idx_zeroth_audit_events_org_recorded_id"),
        "{plan}"
    );
}
