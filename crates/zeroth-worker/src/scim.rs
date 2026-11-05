//! Entra's non-gallery SCIM 2 Users endpoint. A dedicated tenant secret authorizes
//! lifecycle changes. It is never an admin credential and never grants login.
use super::*;
#[cfg(target_arch = "wasm32")]
use provisioning::DirectoryAuthority;
use provisioning::{DirectoryUser, DirectoryUserChange, LifecycleError};

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const BODY_LIMIT: usize = 32 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Filter {
    UserName(String),
    ExternalId(String),
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct ListQuery {
    filter: Option<Filter>,
    start: usize,
    count: usize,
}

fn parse_filter(raw: &str) -> Result<Filter, LifecycleError> {
    if raw.len() > 1024 {
        return Err(LifecycleError::invalid("SCIM filter is too large"));
    }
    let (attribute, rest) = raw
        .trim()
        .split_once(char::is_whitespace)
        .ok_or_else(|| LifecycleError::invalid("invalid SCIM equality filter"))?;
    let (operation, value) = rest
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or_else(|| LifecycleError::invalid("invalid SCIM equality filter"))?;
    let value = value.trim();
    if !operation.eq_ignore_ascii_case("eq") {
        return Err(LifecycleError {
            status: 400,
            code: "invalidFilter",
            detail: "only userName or externalId equality filters are supported",
        });
    }
    let value: String = serde_json::from_str(value).map_err(|_| LifecycleError {
        status: 400,
        code: "invalidFilter",
        detail: "SCIM filter value must be a quoted string",
    })?;
    if value.len() > 320 || value.chars().any(char::is_control) {
        return Err(LifecycleError::invalid("invalid SCIM filter value"));
    }
    if attribute.eq_ignore_ascii_case("userName") {
        Ok(Filter::UserName(value))
    } else if attribute.eq_ignore_ascii_case("externalId") {
        Ok(Filter::ExternalId(provisioning::normalize_external_id(
            "entra", &value,
        )?))
    } else {
        Err(LifecycleError {
            status: 400,
            code: "invalidFilter",
            detail: "unsupported SCIM filter attribute",
        })
    }
}

fn list_query(url: &url::Url) -> Result<ListQuery, LifecycleError> {
    let mut result = ListQuery {
        filter: None,
        start: 1,
        count: 100,
    };
    let mut seen = std::collections::BTreeSet::new();
    for (name, value) in url.query_pairs() {
        if !seen.insert(name.to_string()) {
            return Err(LifecycleError::invalid("duplicate SCIM query parameter"));
        }
        match name.as_ref() {
            "filter" => result.filter = Some(parse_filter(&value)?),
            "startIndex" => {
                result.start = value
                    .parse::<usize>()
                    .ok()
                    .filter(|index| *index >= 1 && *index <= 1_000_000)
                    .ok_or_else(|| LifecycleError::invalid("startIndex must be positive"))?
            }
            "count" => {
                result.count = value
                    .parse::<usize>()
                    .map_err(|_| LifecycleError::invalid("count must be nonnegative"))?
                    .min(100)
            }
            _ => return Err(LifecycleError::invalid("unsupported SCIM query parameter")),
        }
    }
    Ok(result)
}

fn bool_value(value: &serde_json::Value) -> Result<bool, LifecycleError> {
    if let Some(value) = value.as_bool() {
        return Ok(value);
    }
    // Older Entra provisioning jobs send a string for the active PATCH value.
    if let Some(value) = value.as_str() {
        if value.eq_ignore_ascii_case("true") {
            return Ok(true);
        }
        if value.eq_ignore_ascii_case("false") {
            return Ok(false);
        }
    }
    Err(LifecycleError::invalid("active must be a boolean"))
}

fn schemas(value: &serde_json::Value, required: &str) -> Result<(), LifecycleError> {
    if !value
        .get("schemas")
        .and_then(|value| value.as_array())
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(required)))
    {
        return Err(LifecycleError {
            status: 400,
            code: "invalidSyntax",
            detail: "required SCIM schema is missing",
        });
    }
    Ok(())
}

fn user_change(value: &serde_json::Value) -> Result<DirectoryUserChange, LifecycleError> {
    schemas(value, USER_SCHEMA)?;
    let object = value
        .as_object()
        .ok_or_else(|| LifecycleError::invalid("SCIM user must be an object"))?;
    if object.contains_key("password") {
        return Err(LifecycleError::invalid(
            "SCIM password provisioning is not supported",
        ));
    }
    let external = object
        .get("externalId")
        .and_then(|value| value.as_str())
        .ok_or_else(|| LifecycleError::invalid("externalId must map to Entra objectId"))?;
    let name = object
        .get("userName")
        .and_then(|value| value.as_str())
        .ok_or_else(|| LifecycleError::invalid("userName is required"))?;
    let display = match object.get("displayName") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| LifecycleError::invalid("invalid displayName"))?
                .to_owned(),
        ),
    };
    let mut profile = serde_json::Map::new();
    for key in ["name", "emails"] {
        if let Some(value) = object.get(key).filter(|value| !value.is_null()) {
            profile.insert(key.into(), value.clone());
        }
    }
    let mut profile = serde_json::Value::Object(profile);
    clean_profile(&mut profile);
    let profile = profile.to_string();
    provisioning::validate_profile_json(&profile)?;
    Ok(DirectoryUserChange {
        external_id: provisioning::normalize_external_id("entra", external)?,
        user_name: name.into(),
        display_name: display,
        profile_json: Some(profile),
        active: object
            .get("active")
            .map(bool_value)
            .transpose()?
            .unwrap_or(true),
        deleted: false,
    })
}

fn patched_user(
    current: &DirectoryUser,
    body: &serde_json::Value,
) -> Result<DirectoryUserChange, LifecycleError> {
    schemas(body, PATCH_SCHEMA)?;
    let operations = body
        .get("Operations")
        .or_else(|| body.get("operations"))
        .and_then(|value| value.as_array())
        .filter(|operations| !operations.is_empty() && operations.len() <= 32)
        .ok_or_else(|| LifecycleError::invalid("SCIM patch requires one to 32 operations"))?;
    let mut change = DirectoryUserChange {
        external_id: current.external_id.clone(),
        user_name: current.user_name.clone(),
        display_name: current.display_name.clone(),
        profile_json: Some(current.profile_json.clone()),
        active: current.active,
        deleted: false,
    };
    let mut profile: serde_json::Value =
        serde_json::from_str(&current.profile_json).map_err(|_| LifecycleError::storage())?;
    for operation in operations {
        let op = operation
            .get("op")
            .and_then(|value| value.as_str())
            .ok_or_else(|| LifecycleError::invalid("SCIM patch operation is missing"))?;
        if !["add", "replace", "remove"]
            .iter()
            .any(|supported| op.eq_ignore_ascii_case(supported))
        {
            return Err(LifecycleError::invalid("unsupported SCIM patch operation"));
        }
        let remove = op.eq_ignore_ascii_case("remove");
        match operation.get("path") {
            None => {
                if remove {
                    return Err(LifecycleError::invalid("remove requires a path"));
                }
                let fields = operation
                    .get("value")
                    .and_then(|value| value.as_object())
                    .ok_or_else(|| {
                        LifecycleError::invalid("pathless SCIM patch must have an object value")
                    })?;
                for (key, value) in fields {
                    apply_attribute(&mut change, &mut profile, key, Some(value), false)?;
                }
            }
            Some(path) => {
                let path = path
                    .as_str()
                    .ok_or_else(|| LifecycleError::invalid("invalid SCIM patch path"))?;
                apply_attribute(
                    &mut change,
                    &mut profile,
                    path,
                    operation.get("value"),
                    remove,
                )?;
            }
        }
    }
    clean_profile(&mut profile);
    let profile = profile.to_string();
    provisioning::validate_profile_json(&profile)?;
    change.profile_json = Some(profile);
    Ok(change)
}

fn apply_attribute(
    change: &mut DirectoryUserChange,
    profile: &mut serde_json::Value,
    path: &str,
    value: Option<&serde_json::Value>,
    remove: bool,
) -> Result<(), LifecycleError> {
    let path = path.to_ascii_lowercase();
    let path = path
        .strip_prefix("urn:ietf:params:scim:schemas:core:2.0:user:")
        .unwrap_or(&path);
    let value = value.unwrap_or(&serde_json::Value::Null);
    match path {
        "active" if !remove => change.active = bool_value(value)?,
        "externalid" if !remove => {
            let external = value
                .as_str()
                .ok_or_else(|| LifecycleError::invalid("invalid externalId"))?;
            if provisioning::normalize_external_id("entra", external)? != change.external_id {
                return Err(LifecycleError {
                    status: 400,
                    code: "mutability",
                    detail: "externalId is immutable and cannot retarget an account",
                });
            }
        }
        "username" if !remove => {
            change.user_name = value
                .as_str()
                .ok_or_else(|| LifecycleError::invalid("invalid userName"))?
                .into()
        }
        "displayname" => {
            change.display_name = if remove || value.is_null() {
                None
            } else {
                Some(
                    value
                        .as_str()
                        .ok_or_else(|| LifecycleError::invalid("invalid displayName"))?
                        .into(),
                )
            }
        }
        "name" | "emails" => {
            let object = profile
                .as_object_mut()
                .ok_or_else(LifecycleError::storage)?;
            if remove || value.is_null() {
                object.remove(path);
            } else {
                object.insert(path.into(), value.clone());
            }
        }
        "name.givenname" | "name.familyname" | "name.middlename" | "name.formatted" => {
            let key = match path {
                "name.givenname" => "givenName",
                "name.familyname" => "familyName",
                "name.middlename" => "middleName",
                _ => "formatted",
            };
            if profile.get("name").is_none() {
                profile["name"] = serde_json::json!({});
            }
            let name = profile
                .get_mut("name")
                .and_then(|value| value.as_object_mut())
                .ok_or_else(|| LifecycleError::invalid("invalid SCIM name"))?;
            if remove || value.is_null() {
                name.remove(key);
            } else {
                name.insert(key.into(), value.clone());
            }
        }
        "emails[type eq \"work\"].value" => {
            if profile.get("emails").is_none() {
                profile["emails"] = serde_json::json!([]);
            }
            let emails = profile
                .get_mut("emails")
                .and_then(|value| value.as_array_mut())
                .ok_or_else(|| LifecycleError::invalid("invalid SCIM emails"))?;
            let index = emails.iter().position(|email| {
                email
                    .get("type")
                    .and_then(|value| value.as_str())
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("work"))
            });
            if remove || value.is_null() {
                if let Some(index) = index {
                    emails.remove(index);
                }
            } else if let Some(index) = index {
                emails[index]["value"] = value.clone();
            } else {
                emails.push(serde_json::json!({"type":"work","value":value}));
            }
        }
        _ => {
            return Err(LifecycleError {
                status: 400,
                code: "invalidPath",
                detail: "unsupported or read-only SCIM patch path",
            });
        }
    }
    Ok(())
}

fn clean_profile(profile: &mut serde_json::Value) {
    if let Some(name) = profile
        .get_mut("name")
        .and_then(|value| value.as_object_mut())
    {
        name.retain(|_, value| !value.is_null());
    }
    if let Some(emails) = profile
        .get_mut("emails")
        .and_then(|value| value.as_array_mut())
    {
        emails.retain(|email| !email.get("value").is_some_and(|value| value.is_null()));
        for email in emails {
            if let Some(object) = email.as_object_mut() {
                object.retain(|_, value| !value.is_null());
            }
        }
    }
}

fn rfc3339(timestamp: i32) -> String {
    let seconds = i64::from(timestamp.max(0));
    let days = seconds / 86400;
    let within = seconds % 86400;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        within / 3600,
        (within % 3600) / 60,
        within % 60
    )
}

fn resource(user: &DirectoryUser, base: &str) -> serde_json::Value {
    let mut resource = serde_json::json!({"schemas":[USER_SCHEMA],"id":user.id,"externalId":user.external_id,
        "userName":user.user_name,"displayName":user.display_name,"active":user.active&&!user.deleted,
        "meta":{"resourceType":"User","created":rfc3339(user.created_at),"lastModified":rfc3339(user.updated_at),"location":format!("{base}/Users/{}",user.id)}});
    if let Ok(profile) = serde_json::from_str::<serde_json::Value>(&user.profile_json) {
        for key in ["name", "emails"] {
            if let Some(value) = profile.get(key) {
                resource[key] = value.clone();
            }
        }
    }
    resource
}

fn bearer_matches(expected: &str, authorization: Option<&str>) -> bool {
    if !(32..=4096).contains(&expected.len())
        || !expected.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return false;
    }
    let Some((scheme, value)) =
        authorization.and_then(|authorization| authorization.split_once(' '))
    else {
        return false;
    };
    scheme.eq_ignore_ascii_case("Bearer")
        && constant_time_eq(&hash_secret(expected), &hash_secret(value))
}

#[cfg(target_arch = "wasm32")]
fn scim_json(value: &serde_json::Value, status: u16) -> worker::Result<Response> {
    let response = json_status(value, status)?;
    response
        .headers()
        .set("Content-Type", "application/scim+json")?;
    response.headers().set("Cache-Control", "no-store")?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn error_response(error: LifecycleError) -> worker::Result<Response> {
    let mut value = serde_json::json!({"schemas":[ERROR_SCHEMA],"status":error.status.to_string(),"detail":error.detail});
    if matches!(
        error.code,
        "invalidFilter"
            | "tooMany"
            | "uniqueness"
            | "mutability"
            | "invalidSyntax"
            | "invalidPath"
            | "noTarget"
            | "invalidValue"
            | "invalidVers"
            | "sensitive"
    ) {
        value["scimType"] = error.code.into();
    }
    let response = scim_json(&value, error.status)?;
    if error.status == 401 {
        response.headers().set("WWW-Authenticate", "Bearer")?;
    }
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
async fn read_body(request: &mut Request) -> Result<serde_json::Value, LifecycleError> {
    use futures_util::StreamExt;
    let content = request_header(request, "Content-Type")
        .map_err(|_| LifecycleError::invalid("invalid Content-Type"))?
        .unwrap_or_default();
    if !matches!(
        content
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "application/scim+json" | "application/json"
    ) {
        return Err(LifecycleError {
            status: 415,
            code: "invalidSyntax",
            detail: "Content-Type must be application/scim+json",
        });
    }
    reject_oversized_content_length(request, BODY_LIMIT).map_err(|_| LifecycleError {
        status: 413,
        code: "tooLarge",
        detail: "SCIM body exceeds 32 KiB",
    })?;
    let mut stream = request
        .stream()
        .map_err(|_| LifecycleError::invalid("invalid SCIM request body"))?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| LifecycleError::invalid("invalid SCIM request body"))?;
        if chunk.len() > BODY_LIMIT.saturating_sub(bytes.len()) {
            return Err(LifecycleError {
                status: 413,
                code: "tooLarge",
                detail: "SCIM body exceeds 32 KiB",
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| LifecycleError {
        status: 400,
        code: "invalidSyntax",
        detail: "invalid SCIM JSON",
    })
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn scim(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.scheme() != "https" && !loopback {
        return error_response(LifecycleError::invalid("SCIM provisioning requires HTTPS"));
    }
    let Some((_, tail)) = url.path().split_once("/scim/v2/") else {
        return error_response(LifecycleError::missing());
    };
    let parts: Vec<&str> = tail.trim_end_matches('/').split('/').collect();
    if parts.is_empty()
        || parts.len() > 3
        || parts[0].is_empty()
        || parts[0].len() > 128
        || !parts[0]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return error_response(LifecycleError::missing());
    }
    let db = env.d1(D1_BINDING)?;
    let unauthorized = || LifecycleError {
        status: 401,
        code: "unauthorized",
        detail: "valid tenant provisioning credentials are required",
    };
    let source = match provisioning::get_source(&db, parts[0]).await {
        Ok(Some(source)) if source.provider_id == "entra" => source,
        Ok(_) => return error_response(unauthorized()),
        Err(error) => return error_response(error),
    };
    let binding = source
        .token_binding
        .as_deref()
        .filter(|binding| provisioning::valid_scim_token_binding(binding));
    let token = if let Some(binding) = binding {
        match provisioning_admin::credential_for_tenant(&db, &env, &source.tenant_id, binding).await
        {
            Ok(token) => token,
            Err(error) if error.status >= 500 => return error_response(error),
            Err(_) => return error_response(unauthorized()),
        }
    } else {
        None
    };
    if !token.as_deref().is_some_and(|token| {
        bearer_matches(
            token,
            request_header(&request, "Authorization")
                .ok()
                .flatten()
                .as_deref(),
        )
    }) {
        return error_response(unauthorized());
    }
    let authority = DirectoryAuthority {
        tenant_id: source.tenant_id.clone(),
        provider_id: source.provider_id.clone(),
        authority_id: source.authority_id.clone(),
    };
    let tenant = db
        .prepare("SELECT * FROM zeroth_tenants WHERE id=?")
        .bind_refs(&[worker::d1::D1Type::Text(&source.tenant_id)])?
        .first::<tenants::TenantRow>(None)
        .await?;
    if tenant.is_none_or(|tenant| {
        tenant.disabled != 0
            || tenant.enterprise_provider.as_deref() != Some("entra")
            || tenant.entra_tenant_id.as_deref() != Some(&source.authority_id)
    }) {
        return error_response(unauthorized());
    }
    let config = server_config(&env, &url);
    let base = format!(
        "{}/scim/v2/{}",
        config.public_base_url.trim_end_matches('/'),
        authority.tenant_id
    );
    let resource_type = parts.get(1).copied().unwrap_or("ServiceProviderConfig");
    if request.method() == Method::Get
        && resource_type.eq_ignore_ascii_case("ServiceProviderConfig")
        && parts.len() <= 2
    {
        return scim_json(
            &serde_json::json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch":{"supported":true},"bulk":{"supported":false,"maxOperations":0,"maxPayloadSize":0},
            "filter":{"supported":true,"maxResults":100},"changePassword":{"supported":false},"sort":{"supported":false},"etag":{"supported":false},
            "authenticationSchemes":[{"type":"oauthbearertoken","name":"Tenant provisioning bearer token","description":"Dedicated tenant provisioning credential"}]}),
            200,
        );
    }
    if request.method() == Method::Get
        && resource_type.eq_ignore_ascii_case("Schemas")
        && parts.len() == 2
    {
        let attributes = vec![
            serde_json::json!({"name":"userName","type":"string","required":true,"multiValued":false,"mutability":"readWrite","uniqueness":"server"}),
            serde_json::json!({"name":"externalId","type":"string","required":true,"multiValued":false,"mutability":"immutable"}),
            serde_json::json!({"name":"active","type":"boolean","required":false,"multiValued":false}),
            serde_json::json!({"name":"displayName","type":"string","required":false,"multiValued":false}),
            serde_json::json!({"name":"name","type":"complex","required":false,"multiValued":false}),
            serde_json::json!({"name":"emails","type":"complex","required":false,"multiValued":true}),
        ];
        return scim_json(
            &serde_json::json!({"schemas":[LIST_SCHEMA],"totalResults":1,"startIndex":1,"itemsPerPage":1,
            "Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Schema"],"id":USER_SCHEMA,"name":"User","attributes":attributes}]}),
            200,
        );
    }
    if !resource_type.eq_ignore_ascii_case("Users") {
        return error_response(LifecycleError::missing());
    }
    let now = unix_timestamp_seconds();
    if parts.len() == 2 {
        match request.method() {
            Method::Get => {
                let query = match list_query(&url) {
                    Ok(query) => query,
                    Err(error) => return error_response(error),
                };
                let (user_name, external_id) = match &query.filter {
                    None => (None, None),
                    Some(Filter::UserName(name)) => (Some(name.as_str()), None),
                    Some(Filter::ExternalId(id)) => (None, Some(id.as_str())),
                };
                let (total, users) = match provisioning::list_directory_page(
                    &db,
                    &authority,
                    user_name,
                    external_id,
                    query.start,
                    query.count,
                )
                .await
                {
                    Ok(page) => page,
                    Err(error) => return error_response(error),
                };
                let page: Vec<_> = users.iter().map(|user| resource(user, &base)).collect();
                return scim_json(
                    &serde_json::json!({"schemas":[LIST_SCHEMA],"totalResults":total,"startIndex":query.start,"itemsPerPage":page.len(),"Resources":page}),
                    200,
                );
            }
            Method::Post => {
                let body = match read_body(&mut request).await {
                    Ok(body) => body,
                    Err(error) => return error_response(error),
                };
                let change = match user_change(&body) {
                    Ok(change) => change,
                    Err(error) => return error_response(error),
                };
                let existed =
                    match provisioning::get_external_user(&db, &authority, &change.external_id)
                        .await
                    {
                        Ok(row) => row.is_some(),
                        Err(error) => return error_response(error),
                    };
                return match provisioning::apply_user_change(&db, &authority, &change, now).await {
                    Ok(user) => {
                        let response =
                            scim_json(&resource(&user, &base), if existed { 200 } else { 201 })?;
                        response
                            .headers()
                            .set("Location", &format!("{base}/Users/{}", user.id))?;
                        Ok(response)
                    }
                    Err(error) => error_response(error),
                };
            }
            _ => {
                return error_response(LifecycleError {
                    status: 405,
                    code: "invalidSyntax",
                    detail: "method is not supported for SCIM Users",
                });
            }
        }
    }
    let id = parts[2];
    let current = match provisioning::get_directory_user(&db, &authority, id).await {
        Ok(Some(user)) if !user.deleted || request.method() == Method::Delete => user,
        Ok(_) => return error_response(LifecycleError::missing()),
        Err(error) => return error_response(error),
    };
    if request.method() == Method::Get {
        return scim_json(&resource(&current, &base), 200);
    }
    let change = match request.method() {
        Method::Delete => DirectoryUserChange {
            external_id: current.external_id.clone(),
            user_name: current.user_name.clone(),
            display_name: current.display_name.clone(),
            profile_json: None,
            active: false,
            deleted: true,
        },
        Method::Put | Method::Patch => {
            let body = match read_body(&mut request).await {
                Ok(body) => body,
                Err(error) => return error_response(error),
            };
            if body
                .get("id")
                .and_then(|value| value.as_str())
                .is_some_and(|provided| provided != current.id)
            {
                return error_response(LifecycleError::invalid("SCIM resource id is read-only"));
            }
            let change = if request.method() == Method::Put {
                user_change(&body)
            } else {
                patched_user(&current, &body)
            };
            let change = match change {
                Ok(change) => change,
                Err(error) => return error_response(error),
            };
            if change.external_id != current.external_id {
                return error_response(LifecycleError {
                    status: 400,
                    code: "mutability",
                    detail: "externalId is immutable",
                });
            }
            change
        }
        _ => {
            return error_response(LifecycleError {
                status: 405,
                code: "invalidSyntax",
                detail: "unsupported SCIM method",
            });
        }
    };
    match provisioning::apply_user_change_if_version(&db, &authority, &change, current.version, now)
        .await
    {
        Ok(_) if request.method() == Method::Delete => {
            let response = Response::empty()?.with_status(204);
            response.headers().set("Cache-Control", "no-store")?;
            Ok(response)
        }
        Ok(user) => scim_json(&resource(&user, &base), 200),
        Err(error) => error_response(error),
    }
}

#[cfg(test)]
mod tests;
