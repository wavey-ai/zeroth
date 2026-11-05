use super::*;

const OBJECT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
fn current() -> DirectoryUser {
    DirectoryUser {
        id: "dir_opaque".into(),
        tenant_id: "acme".into(),
        provider_id: "entra".into(),
        authority_id: "11111111-2222-3333-4444-555555555555".into(),
        external_id: OBJECT.into(),
        user_name: "old@example.com".into(),
        display_name: Some("Old Name".into()),
        profile_json: "{}".into(),
        active: true,
        deleted: false,
        user_id: Some("usr_internal_private".into()),
        created_at: 1,
        updated_at: 2,
        version: 1,
    }
}
fn patch(operations: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"schemas":[PATCH_SCHEMA],"Operations":operations})
}

#[test]
fn create_requires_immutable_object_id_and_preserves_only_supported_profile_data() {
    let body = serde_json::json!({"schemas":[USER_SCHEMA],"externalId":OBJECT.to_ascii_uppercase(),"userName":"person@example.com",
        "displayName":"Person","name":{"givenName":"Some","familyName":"Person"},"emails":[{"type":"work","value":"person@example.com","primary":true}],
        "roles":["administrator"],"groups":["anything"]});
    let change = user_change(&body).unwrap();
    assert_eq!(change.external_id, OBJECT);
    assert!(change.active);
    assert!(!change
        .profile_json
        .as_ref()
        .unwrap()
        .contains("administrator"));
    let mut bad = body.clone();
    bad["externalId"] = "person@example.com".into();
    assert!(user_change(&bad).is_err());
    bad = body;
    bad["password"] = "secret".into();
    assert!(user_change(&bad).is_err());
}

#[test]
fn standard_and_legacy_entra_deactivation_patches_are_supported() {
    for value in [
        serde_json::json!(false),
        serde_json::json!("False"),
        serde_json::json!("false"),
    ] {
        let result = patched_user(
            &current(),
            &patch(serde_json::json!([{"op":"Replace","path":"active","value":value}])),
        )
        .unwrap();
        assert!(!result.active);
    }
    for invalid in [
        serde_json::json!(0),
        serde_json::json!(" false "),
        serde_json::json!(null),
    ] {
        assert!(patched_user(
            &current(),
            &patch(serde_json::json!([{"op":"replace","path":"active","value":invalid}]))
        )
        .is_err());
    }
}

#[test]
fn combined_metadata_updates_and_deactivation_are_applied_together() {
    let body = patch(serde_json::json!([
        {"op":"replace","value":{"userName":"new@example.com","active":false,"displayName":"New Name"}},
        {"op":"Add","path":"name.givenName","value":"New"},
        {"op":"Replace","path":"name.familyName","value":"Person"},
        {"op":"replace","path":"emails[type eq \"work\"].value","value":"new@example.com"}
    ]));
    let change = patched_user(&current(), &body).unwrap();
    assert!(!change.active);
    assert_eq!(change.user_name, "new@example.com");
    assert_eq!(change.external_id, OBJECT);
    let profile: serde_json::Value =
        serde_json::from_str(change.profile_json.as_ref().unwrap()).unwrap();
    assert_eq!(profile["name"]["givenName"], "New");
    assert_eq!(profile["emails"][0]["value"], "new@example.com");
}

#[test]
fn external_id_changes_readonly_paths_and_oversized_patch_batches_fail_closed() {
    let error=patched_user(&current(),&patch(serde_json::json!([{"op":"replace","path":"externalId","value":"ffffffff-1111-2222-3333-444444444444"}]))).unwrap_err();
    assert_eq!(error.code, "mutability");
    for operation in [
        serde_json::json!({"op":"remove","path":"active"}),
        serde_json::json!({"op":"replace","path":"roles","value":["admin"]}),
        serde_json::json!({"op":"replace","path":"id","value":"other"}),
    ] {
        assert!(patched_user(&current(), &patch(serde_json::json!([operation]))).is_err());
    }
    assert!(patched_user(&current(), &patch(serde_json::json!([]))).is_err());
    let operations = vec![serde_json::json!({"op":"replace","path":"active","value":false}); 33];
    assert!(patched_user(&current(), &patch(serde_json::json!(operations))).is_err());
}

#[test]
fn strict_filter_parser_accepts_equality_and_rejects_unsupported_or_injected_syntax() {
    assert_eq!(
        parse_filter("userName   eq \"test@example.com\"").unwrap(),
        Filter::UserName("test@example.com".into())
    );
    assert_eq!(
        parse_filter(&format!(
            "externalId eq \"{}\"",
            OBJECT.to_ascii_uppercase()
        ))
        .unwrap(),
        Filter::ExternalId(OBJECT.into())
    );
    for invalid in [
        "active eq false",
        "userName co \"x\"",
        "userName eq \"x\" or active eq true",
        "userName eq x",
        "externalId eq \"mail@example.com\"",
    ] {
        assert!(parse_filter(invalid).is_err());
    }
    let url = url::Url::parse("https://issuer/scim/v2/acme/Users?startIndex=1&count=1000").unwrap();
    assert_eq!(list_query(&url).unwrap().count, 100);
    assert!(list_query(&url::Url::parse("https://issuer/Users?count=1&count=2").unwrap()).is_err());
    assert!(list_query(&url::Url::parse("https://issuer/Users?startIndex=0").unwrap()).is_err());
    assert_eq!(
        list_query(&url::Url::parse("https://issuer/Users?count=0").unwrap())
            .unwrap()
            .count,
        0
    );
}

#[test]
fn source_auth_requires_exact_long_bearer_and_resource_never_exposes_local_user_id() {
    let token = "a".repeat(40);
    let other = "b".repeat(40);
    assert!(bearer_matches(&token, Some(&format!("Bearer {token}"))));
    assert!(!bearer_matches(&other, Some(&format!("Bearer {token}"))));
    assert!(!bearer_matches("short", Some("Bearer short")));
    assert!(!bearer_matches(
        &token,
        Some(&format!("Bearer {token} extra"))
    ));
    let value = resource(&current(), "https://issuer/scim/v2/acme");
    assert_eq!(value["id"], "dir_opaque");
    assert_eq!(value["externalId"], OBJECT);
    assert!(!value.to_string().contains("usr_internal_private"));
    assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    assert_eq!(rfc3339(951782400), "2000-02-29T00:00:00Z");
    assert_eq!(rfc3339(i32::MAX), "2038-01-19T03:14:07Z");
}

#[test]
fn optional_null_profile_values_clear_without_blocking_deactivation() {
    let body = patch(
        serde_json::json!([{"op":"replace","value":{"active":false,"name":{"givenName":null},"emails":null}}]),
    );
    let change = patched_user(&current(), &body).unwrap();
    assert!(!change.active);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(change.profile_json.as_ref().unwrap()).unwrap(),
        serde_json::json!({"name":{}})
    );
}
