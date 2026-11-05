use super::*;
use worker::d1::{D1Database, D1PreparedStatement, D1Type as V};

pub(crate) async fn get_source(
    db: &D1Database,
    tenant_id: &str,
) -> Result<Option<DirectorySource>, LifecycleError> {
    db.prepare("SELECT * FROM zeroth_directory_sources WHERE tenant_id=?")
        .bind_refs(&[V::Text(tenant_id)])
        .map_err(|_| LifecycleError::storage())?
        .first::<DirectorySource>(None)
        .await
        .map_err(|_| LifecycleError::storage())
}

async fn validate_tenant(
    db: &D1Database,
    authority: &DirectoryAuthority,
    allow_disabled: bool,
) -> Result<(), LifecycleError> {
    authority.validate()?;
    #[derive(Deserialize)]
    struct Tenant {
        disabled: i32,
        enterprise_provider: Option<String>,
        entra_tenant_id: Option<String>,
    }
    let tenant = db
        .prepare(
            "SELECT disabled,enterprise_provider,entra_tenant_id FROM zeroth_tenants WHERE id=?",
        )
        .bind_refs(&[V::Text(&authority.tenant_id)])
        .map_err(|_| LifecycleError::storage())?
        .first::<Tenant>(None)
        .await
        .map_err(|_| LifecycleError::storage())?
        .ok_or_else(|| LifecycleError::denied("directory tenant was not found"))?;
    if (!allow_disabled && tenant.disabled != 0)
        || tenant.enterprise_provider.as_deref() != Some(&authority.provider_id)
        || (authority.provider_id == "entra"
            && tenant.entra_tenant_id.as_deref() != Some(&authority.authority_id))
    {
        return Err(LifecycleError::denied(
            "directory authority does not match the active tenant connection",
        ));
    }
    Ok(())
}

fn source_matches(source: &DirectorySource, authority: &DirectoryAuthority) -> bool {
    source.provider_id == authority.provider_id && source.authority_id == authority.authority_id
}

pub(crate) async fn authority_locked(
    db: &D1Database,
    authority: &DirectoryAuthority,
) -> Result<bool, LifecycleError> {
    #[derive(Deserialize)]
    struct Count {
        value: i32,
    }
    let row=db.prepare("SELECT CASE WHEN EXISTS(SELECT 1 FROM zeroth_directory_users WHERE tenant_id=?1)
        OR EXISTS(SELECT 1 FROM zeroth_directory_links WHERE tenant_id=?1) THEN 1 ELSE 0 END AS value")
        .bind_refs(&[V::Text(&authority.tenant_id)]).map_err(|_|LifecycleError::storage())?
        .first::<Count>(None).await.map_err(|_|LifecycleError::storage())?;
    Ok(row.is_some_and(|row| row.value != 0))
}

pub(crate) fn valid_scim_token_binding(value: &str) -> bool {
    value.len() <= 128
        && value.starts_with("TENANT_")
        && value.ends_with("_SCIM_TOKEN")
        && value.len() > "TENANT__SCIM_TOKEN".len()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

pub(crate) async fn configure_authority(
    db: &D1Database,
    authority: &DirectoryAuthority,
    enabled: bool,
    token_binding: Option<&str>,
    actor: AuditActor,
    mut additional_business: Vec<D1PreparedStatement>,
    now: i32,
) -> Result<(), LifecycleError> {
    validate_tenant(db, authority, true).await?;
    if token_binding.is_some_and(|binding| !valid_scim_token_binding(binding))
        || (authority.provider_id != "entra" && token_binding.is_some())
        || (authority.provider_id == "entra" && enabled && token_binding.is_none())
    {
        return Err(LifecycleError::invalid(
            "Entra provisioning requires its dedicated TENANT_*_SCIM_TOKEN reference",
        ));
    }
    let previous = get_source(db, &authority.tenant_id).await?;
    if previous
        .as_ref()
        .is_some_and(|source| !source_matches(source, authority))
        && authority_locked(db, authority).await?
    {
        return Err(LifecycleError::conflict(
            "directory authority is immutable after identities or tombstones exist",
        ));
    }
    let changed = previous.as_ref().is_none_or(|source| {
        !source_matches(source, authority)
            || source.enabled != i32::from(enabled)
            || source.token_binding.as_deref() != token_binding
    }) || !additional_business.is_empty();
    if !changed {
        return Ok(());
    }
    let mut event = lifecycle_event(
        format!(
            "evt_{}",
            random_token().map_err(|_| LifecycleError::storage())?
        ),
        authority,
        &authority.tenant_id,
        None,
        "directory.source.configure",
        actor,
        now,
    )?;
    event.targets[0].kind = "directory_source".into();
    event
        .details
        .insert(DetailKey::PolicyChanged, DetailValue::Bool(true))
        .map_err(|_| LifecycleError::storage())?;
    event
        .details
        .insert(DetailKey::Disabled, DetailValue::Bool(!enabled))
        .map_err(|_| LifecycleError::storage())?;
    let guard = format!("config_{}", event.event_id);
    let tenant_guard = format!("tenant_{}", event.event_id);
    additional_business.insert(
        0,
        db.prepare(CONFIG_TENANT_GUARD_SQL)
            .bind_refs(&[
                V::Text(&tenant_guard),
                V::Text(&authority.tenant_id),
                V::Text(&authority.provider_id),
                V::Text(&authority.authority_id),
            ])
            .map_err(|_| LifecycleError::storage())?,
    );
    additional_business.insert(0,db.prepare("INSERT INTO zeroth_audit_write_guards(id,valid)
       SELECT ?1,CASE WHEN (?3=0 AND NOT EXISTS(SELECT 1 FROM zeroth_directory_sources WHERE tenant_id=?2))
        OR (?3>0 AND EXISTS(SELECT 1 FROM zeroth_directory_sources WHERE tenant_id=?2 AND config_version=?3))
       THEN 1 ELSE 0 END")
        .bind_refs(&[V::Text(&guard),V::Text(&authority.tenant_id),V::Integer(previous.as_ref().map_or(0,|source|source.config_version as i32))])
        .map_err(|_|LifecycleError::storage())?);
    // Source replacement must remain impossible if an identity arrives after
    // the preliminary lock check, including in an otherwise disabled draft.
    if previous
        .as_ref()
        .is_some_and(|source| !source_matches(source, authority))
    {
        additional_business.push(db.prepare("INSERT INTO zeroth_audit_write_guards(id,valid)
          SELECT ?1,CASE WHEN NOT EXISTS(SELECT 1 FROM zeroth_directory_users WHERE tenant_id=?2)
            AND NOT EXISTS(SELECT 1 FROM zeroth_directory_links WHERE tenant_id=?2) THEN 1 ELSE 0 END")
            .bind_refs(&[V::Text(&event.event_id),V::Text(&authority.tenant_id)]).map_err(|_|LifecycleError::storage())?);
    }
    additional_business.push(db.prepare("INSERT INTO zeroth_directory_sources
        (tenant_id,provider_id,authority_id,enabled,token_binding,created_at,updated_at,config_version)
        VALUES (?1,?2,?3,?4,?5,?6,?6,1)
        ON CONFLICT(tenant_id) DO UPDATE SET provider_id=excluded.provider_id,authority_id=excluded.authority_id,
          enabled=excluded.enabled,token_binding=excluded.token_binding,updated_at=excluded.updated_at,
          config_version=zeroth_directory_sources.config_version+1,sync_fence=NULL,
          last_full_sync_at=CASE WHEN zeroth_directory_sources.provider_id=excluded.provider_id
            AND zeroth_directory_sources.authority_id=excluded.authority_id THEN zeroth_directory_sources.last_full_sync_at ELSE NULL END")
        .bind_refs(&[V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id),V::Integer(i32::from(enabled)),d1_optional_text(token_binding),V::Integer(now)])
        .map_err(|_|LifecycleError::storage())?);
    // Even a first non-strict source configuration invalidates pre-existing
    // legacy grants, because they may never have recorded a signed object ID.
    for sql in INVALIDATE_TENANT_GRANTS_SQL {
        additional_business.push(
            db.prepare(*sql)
                .bind_refs(&[V::Text(&authority.tenant_id), V::Integer(now)])
                .map_err(|_| LifecycleError::storage())?,
        );
    }
    for id in [&guard, &tenant_guard, &event.event_id] {
        additional_business.push(
            db.prepare("DELETE FROM zeroth_audit_write_guards WHERE id=?")
                .bind_refs(&[V::Text(id)])
                .map_err(|_| LifecycleError::storage())?,
        );
    }
    audit_capture::commit(db, additional_business, &[(event, None)])
        .await
        .map_err(|_| LifecycleError::storage())
}

pub(crate) async fn get_directory_user(
    db: &D1Database,
    authority: &DirectoryAuthority,
    id: &str,
) -> Result<Option<DirectoryUser>, LifecycleError> {
    db.prepare("SELECT * FROM zeroth_directory_users WHERE tenant_id=?1 AND provider_id=?2 AND authority_id=?3 AND id=?4")
        .bind_refs(&[V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id),V::Text(id)])
        .map_err(|_|LifecycleError::storage())?.first::<DirectoryUser>(None).await.map_err(|_|LifecycleError::storage())
}

pub(crate) async fn get_external_user(
    db: &D1Database,
    authority: &DirectoryAuthority,
    external_id: &str,
) -> Result<Option<DirectoryUser>, LifecycleError> {
    db.prepare("SELECT * FROM zeroth_directory_users WHERE tenant_id=?1 AND provider_id=?2 AND authority_id=?3 AND external_id=?4")
        .bind_refs(&[V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id),V::Text(external_id)])
        .map_err(|_|LifecycleError::storage())?.first::<DirectoryUser>(None).await.map_err(|_|LifecycleError::storage())
}

pub(crate) async fn all_directory_users(
    db: &D1Database,
    authority: &DirectoryAuthority,
) -> Result<Vec<DirectoryUser>, LifecycleError> {
    let rows=db.prepare("SELECT * FROM zeroth_directory_users WHERE tenant_id=?1 AND provider_id=?2 AND authority_id=?3 ORDER BY id LIMIT 10001")
        .bind_refs(&[V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id)])
        .map_err(|_|LifecycleError::storage())?.all().await.map_err(|_|LifecycleError::storage())?
        .results::<DirectoryUser>().map_err(|_|LifecycleError::storage())?;
    if rows.len() > MAX_SNAPSHOT_USERS {
        return Err(LifecycleError::invalid(
            "directory exceeds the supported user limit",
        ));
    }
    Ok(rows)
}

pub(crate) async fn list_directory_page(
    db: &D1Database,
    authority: &DirectoryAuthority,
    user_name: Option<&str>,
    external_id: Option<&str>,
    start: usize,
    count: usize,
) -> Result<(usize, Vec<DirectoryUser>), LifecycleError> {
    if start == 0 || count > 100 || user_name.is_some() && external_id.is_some() {
        return Err(LifecycleError::invalid("invalid directory page"));
    }
    #[derive(Deserialize)]
    struct Count {
        total: i64,
    }
    let name = user_name.map(str::to_lowercase);
    let predicate = "tenant_id=?1 AND provider_id=?2 AND authority_id=?3 AND deleted=0 AND (?4 IS NULL OR user_name_key=?4) AND (?5 IS NULL OR external_id=?5)";
    let args = [
        V::Text(&authority.tenant_id),
        V::Text(&authority.provider_id),
        V::Text(&authority.authority_id),
        d1_optional_text(name.as_deref()),
        d1_optional_text(external_id),
    ];
    let total = db
        .prepare(format!(
            "SELECT COUNT(*) AS total FROM zeroth_directory_users WHERE {predicate}"
        ))
        .bind_refs(&args)
        .map_err(|_| LifecycleError::storage())?
        .first::<Count>(None)
        .await
        .map_err(|_| LifecycleError::storage())?
        .ok_or_else(LifecycleError::storage)?
        .total;
    let page = db
        .prepare(format!(
            "SELECT * FROM zeroth_directory_users WHERE {predicate} ORDER BY id LIMIT ?6 OFFSET ?7"
        ))
        .bind_refs(&[
            V::Text(&authority.tenant_id),
            V::Text(&authority.provider_id),
            V::Text(&authority.authority_id),
            d1_optional_text(name.as_deref()),
            d1_optional_text(external_id),
            V::Integer(count as i32),
            V::Integer((start - 1).min(i32::MAX as usize) as i32),
        ])
        .map_err(|_| LifecycleError::storage())?
        .all()
        .await
        .map_err(|_| LifecycleError::storage())?
        .results::<DirectoryUser>()
        .map_err(|_| LifecycleError::storage())?;
    Ok((total as usize, page))
}

#[derive(Deserialize)]
struct UserLink {
    user_id: String,
}

async fn linked_user(
    db: &D1Database,
    authority: &DirectoryAuthority,
    external_id: &str,
) -> Result<Option<String>, LifecycleError> {
    let stored=db.prepare("SELECT user_id FROM zeroth_directory_links WHERE tenant_id=?1 AND provider_id=?2 AND authority_id=?3 AND external_id=?4")
        .bind_refs(&[V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id),V::Text(external_id)])
        .map_err(|_|LifecycleError::storage())?.first::<UserLink>(None).await.map_err(|_|LifecycleError::storage())?;
    if let Some(stored) = stored {
        return Ok(Some(stored.user_id));
    }
    if authority.provider_id == "google_workspace" {
        let namespace = format!("tenant:{}", authority.tenant_id);
        return db.prepare("SELECT user_id FROM zeroth_account_identities WHERE account_namespace=?1 AND provider_id='google_workspace' AND provider_subject=?2")
            .bind_refs(&[V::Text(&namespace),V::Text(external_id)]).map_err(|_|LifecycleError::storage())?
            .first::<UserLink>(None).await.map(|row|row.map(|row|row.user_id)).map_err(|_|LifecycleError::storage());
    }
    Ok(None)
}

fn source_guard(
    db: &D1Database,
    authority: &DirectoryAuthority,
    source: &DirectorySource,
    id: &str,
    fence: Option<&str>,
) -> Result<D1PreparedStatement, LifecycleError> {
    db.prepare(SOURCE_GUARD_SQL)
        .bind_refs(&[
            V::Text(id),
            V::Text(&authority.tenant_id),
            V::Text(&authority.provider_id),
            V::Text(&authority.authority_id),
            V::Integer(source.config_version as i32),
            d1_optional_text(fence),
        ])
        .map_err(|_| LifecycleError::storage())
}

fn unchanged(current: &DirectoryUser, change: &DirectoryUserChange, pinned: Option<&str>) -> bool {
    current.external_id == change.external_id
        && current.user_name == change.user_name
        && current.display_name == change.display_name
        && change
            .profile_json
            .as_ref()
            .is_none_or(|profile| &current.profile_json == profile)
        && current.active == change.active
        && current.deleted == change.deleted
        && current.user_id.as_deref() == pinned
}

pub(crate) async fn apply_user_change(
    db: &D1Database,
    authority: &DirectoryAuthority,
    change: &DirectoryUserChange,
    now: i32,
) -> Result<DirectoryUser, LifecycleError> {
    apply_change(db, authority, change, now, None, None).await
}

/// Resource-bound SCIM mutations must use the version from which PATCH/PUT was
/// prepared. Re-reading a newer row must never rebase an earlier active=true
/// value over a concurrently processed deactivation.
pub(crate) async fn apply_user_change_if_version(
    db: &D1Database,
    authority: &DirectoryAuthority,
    change: &DirectoryUserChange,
    expected_version: i64,
    now: i32,
) -> Result<DirectoryUser, LifecycleError> {
    apply_change(db, authority, change, now, None, Some(expected_version)).await
}

type PreparedChange = (Vec<D1PreparedStatement>, AuditEvent, Option<String>);

fn prepare_change(
    db: &D1Database,
    authority: &DirectoryAuthority,
    source: &DirectorySource,
    existing: Option<&DirectoryUser>,
    pinned: Option<String>,
    change: &DirectoryUserChange,
    now: i32,
    fence: Option<&str>,
) -> Result<Option<PreparedChange>, LifecycleError> {
    if existing.is_some_and(|current| unchanged(current, change, pinned.as_deref())) {
        return Ok(None);
    }
    let id = existing
        .as_ref()
        .map(|row| row.id.clone())
        .unwrap_or(format!(
            "dir_{}",
            random_token().map_err(|_| LifecycleError::storage())?
        ));
    let action = if change.deleted {
        "directory.user.delete"
    } else if !change.active {
        "directory.user.disable"
    } else if existing.is_some() {
        "directory.user.update"
    } else {
        "directory.user.create"
    };
    let actor = AuditActor::new("service", format!("directory:{}", authority.provider_id))
        .map_err(|_| LifecycleError::storage())?;
    let event = lifecycle_event(
        format!(
            "evt_{}",
            random_token().map_err(|_| LifecycleError::storage())?
        ),
        authority,
        &id,
        pinned.as_deref(),
        action,
        actor,
        now,
    )?;
    let source_guard_id = format!("source_{}", event.event_id);
    let link_guard_id = format!("link_{}", event.event_id);
    let mut changes = vec![
        source_guard(db, authority, source, &source_guard_id, fence)?,
        // If a signed login pins an object after our read, retry with that
        // exact local owner so deprovisioning cannot miss its live grants.
        db.prepare(LINK_PREIMAGE_GUARD_SQL)
            .bind_refs(&[
                V::Text(&link_guard_id),
                V::Text(&authority.tenant_id),
                V::Text(&authority.provider_id),
                V::Text(&authority.authority_id),
                V::Text(&change.external_id),
                d1_optional_text(pinned.as_deref()),
            ])
            .map_err(|_| LifecycleError::storage())?,
        db.prepare(USER_PREIMAGE_GUARD_SQL)
            .bind_refs(&[
                V::Text(&event.event_id),
                V::Text(&authority.tenant_id),
                V::Text(&authority.provider_id),
                V::Text(&authority.authority_id),
                V::Text(&change.external_id),
                V::Integer(existing.as_ref().map_or(0, |row| row.version as i32)),
            ])
            .map_err(|_| LifecycleError::storage())?,
    ];
    let name_key = change.user_name.to_lowercase();
    changes.push(
        db.prepare(UPSERT_DIRECTORY_USER_SQL)
            .bind_refs(&[
                V::Text(&id),
                V::Text(&authority.tenant_id),
                V::Text(&authority.provider_id),
                V::Text(&authority.authority_id),
                V::Text(&change.external_id),
                V::Text(&change.user_name),
                V::Text(&name_key),
                d1_optional_text(change.display_name.as_deref()),
                V::Integer(i32::from(change.active)),
                V::Integer(i32::from(change.deleted)),
                d1_optional_text(pinned.as_deref()),
                V::Integer(now),
                d1_optional_text(change.profile_json.as_deref()),
            ])
            .map_err(|_| LifecycleError::storage())?,
    );
    if let Some(user) = &pinned {
        changes.push(
            db.prepare(PIN_DIRECTORY_LINK_SQL)
                .bind_refs(&[
                    V::Text(&authority.tenant_id),
                    V::Text(&authority.provider_id),
                    V::Text(&authority.authority_id),
                    V::Text(&change.external_id),
                    V::Text(user),
                    V::Integer(now),
                ])
                .map_err(|_| LifecycleError::storage())?,
        );
        if !change.active || change.deleted {
            for sql in REVOKE_DIRECTORY_USER_SQL {
                changes.push(
                    db.prepare(*sql)
                        .bind_refs(&[
                            V::Text(&authority.tenant_id),
                            V::Text(user),
                            V::Integer(now),
                        ])
                        .map_err(|_| LifecycleError::storage())?,
                );
            }
        }
    }
    changes.push(db.prepare("UPDATE zeroth_directory_sources SET last_activity_at=?2,last_error_code=NULL WHERE tenant_id=?1")
        .bind_refs(&[V::Text(&authority.tenant_id),V::Integer(now)]).map_err(|_|LifecycleError::storage())?);
    for guard in [&source_guard_id, &link_guard_id, &event.event_id] {
        changes.push(
            db.prepare("DELETE FROM zeroth_audit_write_guards WHERE id=?")
                .bind_refs(&[V::Text(guard)])
                .map_err(|_| LifecycleError::storage())?,
        );
    }
    Ok(Some((changes, event, pinned)))
}

async fn apply_change(
    db: &D1Database,
    authority: &DirectoryAuthority,
    change: &DirectoryUserChange,
    now: i32,
    fence: Option<&str>,
    expected_version: Option<i64>,
) -> Result<DirectoryUser, LifecycleError> {
    change.validate(authority)?;
    validate_tenant(db, authority, false).await?;
    let source = get_source(db, &authority.tenant_id)
        .await?
        .filter(|source| source_matches(source, authority))
        .ok_or_else(|| {
            LifecycleError::denied("directory source is not configured for this authority")
        })?;
    if fence.is_some_and(|fence| source.sync_fence.as_deref() != Some(fence)) {
        return Err(LifecycleError::conflict(
            "directory synchronization was superseded",
        ));
    }
    let existing = get_external_user(db, authority, &change.external_id).await?;
    if expected_version
        .is_some_and(|version| existing.as_ref().is_none_or(|row| row.version != version))
    {
        return Err(LifecycleError::conflict(
            "directory user changed while the request was being processed; retry the operation",
        ));
    }
    let linked = linked_user(db, authority, &change.external_id).await?;
    if existing
        .as_ref()
        .and_then(|row| row.user_id.as_deref())
        .zip(linked.as_deref())
        .is_some_and(|(a, b)| a != b)
    {
        return Err(LifecycleError::conflict(
            "directory object is linked to a different account",
        ));
    }
    let pinned = existing
        .as_ref()
        .and_then(|row| row.user_id.clone())
        .or(linked);
    let prepared = prepare_change(
        db,
        authority,
        &source,
        existing.as_ref(),
        pinned.clone(),
        change,
        now,
        fence,
    )?;
    let Some((changes, event, _)) = prepared else {
        // A repeated delivery is idempotent; retain source activity without
        // manufacturing another business-state transition audit event.
        db.prepare("UPDATE zeroth_directory_sources SET last_activity_at=?2 WHERE tenant_id=?1")
            .bind_refs(&[V::Text(&authority.tenant_id), V::Integer(now)])
            .map_err(|_| LifecycleError::storage())?
            .run()
            .await
            .map_err(|_| LifecycleError::storage())?;
        return existing.ok_or_else(LifecycleError::storage);
    };
    let name_key = change.user_name.to_lowercase();
    let committed = audit_capture::commit(db, changes, &[(event, pinned.clone())]).await;
    let after = get_external_user(db, authority, &change.external_id).await?;
    if let Some(after) = after {
        if unchanged(&after, change, pinned.as_deref()) {
            return Ok(after);
        }
    }
    if committed.is_err() {
        #[derive(Deserialize)]
        struct Other {
            external_id: String,
        }
        let other=db.prepare("SELECT external_id FROM zeroth_directory_users WHERE tenant_id=?1 AND provider_id=?2 AND authority_id=?3 AND user_name_key=?4 AND deleted=0")
            .bind_refs(&[V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id),V::Text(&name_key)])
            .map_err(|_|LifecycleError::storage())?.first::<Other>(None).await.map_err(|_|LifecycleError::storage())?;
        if other.is_some_and(|row| row.external_id != change.external_id) {
            return Err(LifecycleError::conflict(
                "directory userName belongs to another immutable object",
            ));
        }
    }
    Err(LifecycleError::storage())
}

pub(crate) async fn list_external_ids(
    db: &D1Database,
    authority: &DirectoryAuthority,
) -> Result<Vec<String>, LifecycleError> {
    let mut values: BTreeSet<String> = all_directory_users(db, authority)
        .await?
        .into_iter()
        .map(|row| row.external_id)
        .collect();
    #[derive(Deserialize)]
    struct Id {
        external_id: String,
    }
    let links=db.prepare("SELECT external_id FROM zeroth_directory_links WHERE tenant_id=?1 AND provider_id=?2 AND authority_id=?3 LIMIT 10001")
        .bind_refs(&[V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id)])
        .map_err(|_|LifecycleError::storage())?.all().await.map_err(|_|LifecycleError::storage())?.results::<Id>().map_err(|_|LifecycleError::storage())?;
    values.extend(links.into_iter().map(|row| row.external_id));
    if authority.provider_id == "google_workspace" {
        let namespace = format!("tenant:{}", authority.tenant_id);
        let identities=db.prepare("SELECT provider_subject AS external_id FROM zeroth_account_identities WHERE account_namespace=?1 AND provider_id='google_workspace' LIMIT 10001")
            .bind_refs(&[V::Text(&namespace)]).map_err(|_|LifecycleError::storage())?.all().await.map_err(|_|LifecycleError::storage())?.results::<Id>().map_err(|_|LifecycleError::storage())?;
        values.extend(identities.into_iter().map(|row| row.external_id));
    }
    if values.len() > MAX_SNAPSHOT_USERS {
        return Err(LifecycleError::invalid(
            "directory exceeds the supported user limit",
        ));
    }
    Ok(values.into_iter().collect())
}

pub(crate) fn snapshot_fence_statement(
    db: &D1Database,
    authority: &DirectoryAuthority,
    lease_id: &str,
) -> Result<D1PreparedStatement, LifecycleError> {
    db.prepare("UPDATE zeroth_directory_sources SET sync_fence=?4 WHERE tenant_id=?1 AND provider_id=?2 AND authority_id=?3")
        .bind_refs(&[V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id),V::Text(lease_id)])
        .map_err(|_|LifecycleError::storage())
}

pub(crate) async fn apply_snapshot(
    db: &D1Database,
    authority: &DirectoryAuthority,
    changes: Vec<DirectoryUserChange>,
    now: i32,
) -> Result<LifecycleSummary, LifecycleError> {
    apply_snapshot_inner(db, authority, changes, now, None).await
}

pub(crate) async fn apply_snapshot_guarded(
    db: &D1Database,
    authority: &DirectoryAuthority,
    changes: Vec<DirectoryUserChange>,
    now: i32,
    lease_id: &str,
) -> Result<LifecycleSummary, LifecycleError> {
    apply_snapshot_inner(db, authority, changes, now, Some(lease_id)).await
}

async fn apply_snapshot_inner(
    db: &D1Database,
    authority: &DirectoryAuthority,
    mut changes: Vec<DirectoryUserChange>,
    now: i32,
    fence: Option<&str>,
) -> Result<LifecycleSummary, LifecycleError> {
    let present = validate_snapshot(authority, &changes)?;
    validate_tenant(db, authority, false).await?;
    let source = get_source(db, &authority.tenant_id)
        .await?
        .filter(|source| source_matches(source, authority))
        .ok_or_else(LifecycleError::storage)?;
    if fence.is_some_and(|fence| source.sync_fence.as_deref() != Some(fence)) {
        return Err(LifecycleError::conflict(
            "directory synchronization was superseded",
        ));
    }
    let existing: std::collections::BTreeMap<String, DirectoryUser> =
        all_directory_users(db, authority)
            .await?
            .into_iter()
            .map(|row| (row.external_id.clone(), row))
            .collect();
    #[derive(Deserialize)]
    struct Link {
        external_id: String,
        user_id: String,
    }
    let rows=db.prepare("SELECT external_id,user_id FROM zeroth_directory_links WHERE tenant_id=?1 AND provider_id=?2 AND authority_id=?3 LIMIT 10001")
      .bind_refs(&[V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id)]).map_err(|_|LifecycleError::storage())?
      .all().await.map_err(|_|LifecycleError::storage())?.results::<Link>().map_err(|_|LifecycleError::storage())?;
    if rows.len() > MAX_SNAPSHOT_USERS {
        return Err(LifecycleError::invalid(
            "directory exceeds the supported user limit",
        ));
    }
    let mut links: std::collections::BTreeMap<String, String> = rows
        .into_iter()
        .map(|row| (row.external_id, row.user_id))
        .collect();
    if authority.provider_id == "google_workspace" {
        let namespace = format!("tenant:{}", authority.tenant_id);
        let rows=db.prepare("SELECT provider_subject AS external_id,user_id FROM zeroth_account_identities WHERE account_namespace=?1 AND provider_id='google_workspace' LIMIT 10001")
          .bind_refs(&[V::Text(&namespace)]).map_err(|_|LifecycleError::storage())?.all().await.map_err(|_|LifecycleError::storage())?
          .results::<Link>().map_err(|_|LifecycleError::storage())?;
        if rows.len() > MAX_SNAPSHOT_USERS {
            return Err(LifecycleError::invalid(
                "directory exceeds the supported user limit",
            ));
        }
        for row in rows {
            if links
                .get(&row.external_id)
                .is_some_and(|owner| owner != &row.user_id)
            {
                return Err(LifecycleError::conflict(
                    "directory identity has conflicting local owners",
                ));
            }
            links.entry(row.external_id).or_insert(row.user_id);
        }
    }
    for old in existing.values() {
        if !present.contains(&old.external_id) && old.active && !old.deleted {
            changes.push(DirectoryUserChange {
                external_id: old.external_id.clone(),
                user_name: old.user_name.clone(),
                display_name: old.display_name.clone(),
                profile_json: None,
                active: false,
                deleted: false,
            });
        }
    }
    if changes.len() > MAX_SNAPSHOT_USERS {
        return Err(LifecycleError::invalid(
            "directory snapshot exceeds the supported user limit",
        ));
    }
    // Bulk reads above avoid per-user network queries. Each bounded chunk is
    // one D1 batch; every changed user and its audit/outbox record share it.
    // Later failure leaves the previous completed-sync timestamp untouched.
    let mut summary = LifecycleSummary::default();
    let mut statements = Vec::new();
    let mut events = Vec::new();
    for change in &changes {
        let current = existing.get(&change.external_id);
        let linked = links.get(&change.external_id);
        if current
            .and_then(|row| row.user_id.as_deref())
            .zip(linked.map(String::as_str))
            .is_some_and(|(a, b)| a != b)
        {
            return Err(LifecycleError::conflict(
                "directory object is linked to another account",
            ));
        }
        let pinned = current
            .and_then(|row| row.user_id.clone())
            .or_else(|| linked.cloned());
        if let Some((business, event, user)) =
            prepare_change(db, authority, &source, current, pinned, change, now, fence)?
        {
            statements.extend(business);
            events.push((event, user));
        }
        summary.processed += 1;
        if (!change.active || change.deleted)
            && current.is_none_or(|row| row.active && !row.deleted)
        {
            summary.deactivated += 1;
        }
        if events.len() >= 100 {
            audit_capture::commit(
                db,
                std::mem::take(&mut statements),
                &std::mem::take(&mut events),
            )
            .await
            .map_err(|_| LifecycleError::storage())?;
        }
    }
    if !events.is_empty() {
        audit_capture::commit(db, statements, &events)
            .await
            .map_err(|_| LifecycleError::storage())?;
    }
    let guard = format!(
        "snapshot_{}",
        random_token().map_err(|_| LifecycleError::storage())?
    );
    let completed = unix_timestamp_seconds().max(now);
    // Completion/freshness is committed only after every transition succeeded,
    // with the same source generation/fence as the full scan.
    let actor = AuditActor::new("service", format!("directory:{}", authority.provider_id))
        .map_err(|_| LifecycleError::storage())?;
    let mut event = lifecycle_event(
        format!(
            "evt_{}",
            random_token().map_err(|_| LifecycleError::storage())?
        ),
        authority,
        &authority.tenant_id,
        None,
        "directory.sync.complete",
        actor,
        completed,
    )?;
    event.targets[0].kind = "directory_source".into();
    event
        .details
        .insert(
            DetailKey::Count,
            DetailValue::Integer(summary.processed as i64),
        )
        .map_err(|_| LifecycleError::storage())?;
    // Freshness describes when the complete upstream roster was observed, not
    // when its possibly lengthy local application finished.
    let business = vec![
        source_guard(db, authority, &source, &guard, fence)?,
        db.prepare(MARK_SNAPSHOT_COMPLETE_SQL)
            .bind_refs(&[
                V::Text(&authority.tenant_id),
                V::Integer(now),
                V::Integer(completed),
            ])
            .map_err(|_| LifecycleError::storage())?,
        db.prepare("DELETE FROM zeroth_audit_write_guards WHERE id=?")
            .bind_refs(&[V::Text(&guard)])
            .map_err(|_| LifecycleError::storage())?,
    ];
    audit_capture::commit(db, business, &[(event, None)])
        .await
        .map_err(|_| LifecycleError::storage())?;
    Ok(summary)
}

pub(crate) async fn admit_login(
    db: &D1Database,
    client_id: &str,
    identity: Option<&VerifiedDirectoryIdentity>,
) -> Result<LoginAdmission, LifecycleError> {
    let empty = || LoginAdmission {
        authority: None,
        external_id: None,
        directory_id: None,
        linked_user_id: None,
        source_version: None,
        directory_version: None,
    };
    #[derive(Deserialize)]
    struct Bound {
        tenant_id: String,
        enterprise_provider: String,
        entra_tenant_id: Option<String>,
        disabled: i32,
    }
    let bound=db.prepare("SELECT t.id AS tenant_id,t.enterprise_provider,t.entra_tenant_id,t.disabled FROM zeroth_tenant_clients tc JOIN zeroth_tenants t ON t.id=tc.tenant_id WHERE tc.client_id=?")
        .bind_refs(&[V::Text(client_id)]).map_err(|_|LifecycleError::storage())?.first::<Bound>(None).await.map_err(|_|LifecycleError::storage())?;
    let Some(bound) = bound else {
        return Ok(empty());
    };
    if bound.disabled != 0 {
        return Err(LifecycleError::denied("tenant is disabled"));
    }
    let source = get_source(db, &bound.tenant_id).await?;
    let Some(identity) = identity else {
        if source.as_ref().is_some_and(|source| source.enabled != 0) {
            return Err(LifecycleError::denied(
                "provisioned login requires a verified immutable directory identity",
            ));
        }
        return Ok(empty());
    };
    if identity.provider_id != bound.enterprise_provider {
        return Err(LifecycleError::denied(
            "signed directory identity did not match the tenant provider",
        ));
    }
    let realm = if identity.provider_id == "entra" {
        let signed = identity
            .authority_id
            .as_deref()
            .ok_or_else(|| LifecycleError::denied("signed Entra tenant identity is missing"))?;
        if bound.entra_tenant_id.as_deref() != Some(signed) {
            return Err(LifecycleError::denied(
                "signed Entra tenant did not match the connection",
            ));
        }
        signed.to_owned()
    } else {
        let Some(source) = &source else {
            return Ok(empty());
        };
        source.authority_id.clone()
    };
    let authority = DirectoryAuthority {
        tenant_id: bound.tenant_id,
        provider_id: identity.provider_id.clone(),
        authority_id: realm,
    };
    authority.validate()?;
    let external_id = normalize_external_id(&authority.provider_id, &identity.external_id)?;
    if let Some(source) = &source {
        if !source_matches(source, &authority) {
            return Err(LifecycleError::denied(
                "provisioning authority did not match signed login",
            ));
        }
    }
    let directory = get_external_user(db, &authority, &external_id).await?;
    check_directory_state(
        source.as_ref(),
        directory.as_ref(),
        unix_timestamp_seconds(),
    )?;

    let link = linked_user(db, &authority, &external_id).await?;
    if directory
        .as_ref()
        .and_then(|row| row.user_id.as_deref())
        .zip(link.as_deref())
        .is_some_and(|(a, b)| a != b)
    {
        return Err(LifecycleError::conflict(
            "directory identity has conflicting account links",
        ));
    }
    let pinned = directory
        .as_ref()
        .and_then(|row| row.user_id.clone())
        .or(link);
    if let Some(user) = &pinned {
        let existing = get_user(db, user)
            .await
            .map_err(|_| LifecycleError::storage())?
            .ok_or_else(|| LifecycleError::denied("the linked account no longer exists"))?;
        if existing.disabled_at.is_some() {
            return Err(LifecycleError::denied("the linked account is disabled"));
        }
    }
    Ok(LoginAdmission {
        authority: Some(authority),
        external_id: Some(external_id),
        directory_id: directory.as_ref().map(|row| row.id.clone()),
        linked_user_id: pinned,
        source_version: source.map(|source| source.config_version),
        directory_version: directory.map(|row| row.version),
    })
}

pub(crate) fn link_login_statements(
    db: &D1Database,
    admission: &LoginAdmission,
    user_id: &str,
    event_id: &str,
    now: i32,
) -> Result<Vec<D1PreparedStatement>, LifecycleError> {
    let (Some(authority), Some(external)) = (&admission.authority, &admission.external_id) else {
        return Ok(Vec::new());
    };
    if admission
        .linked_user_id
        .as_deref()
        .is_some_and(|linked| linked != user_id)
    {
        return Err(LifecycleError::conflict(
            "signed directory identity is pinned to another account",
        ));
    }
    let guard = format!("directory_link_{event_id}");
    let config_guard = format!("directory_config_{event_id}");
    let mut statements=vec![db.prepare("INSERT INTO zeroth_audit_write_guards(id,valid)
        SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM zeroth_tenants WHERE id=?2 AND disabled=0 AND enterprise_provider=?3 AND (?3<>'entra' OR entra_tenant_id=?4))
          AND ((?5=0 AND NOT EXISTS(SELECT 1 FROM zeroth_directory_sources WHERE tenant_id=?2)) OR EXISTS (
            SELECT 1 FROM zeroth_directory_sources WHERE tenant_id=?2 AND provider_id=?3 AND authority_id=?4 AND config_version=?5))
          AND NOT EXISTS(SELECT 1 FROM zeroth_directory_users WHERE tenant_id=?2 AND provider_id=?3 AND authority_id=?4 AND external_id=?6 AND (active=0 OR deleted=1 OR (user_id IS NOT NULL AND user_id<>?7)))
          AND NOT EXISTS(SELECT 1 FROM zeroth_directory_links WHERE tenant_id=?2 AND provider_id=?3 AND authority_id=?4 AND external_id=?6 AND user_id<>?7)
          AND (?8=0 OR EXISTS(SELECT 1 FROM zeroth_directory_users WHERE tenant_id=?2 AND provider_id=?3 AND authority_id=?4 AND external_id=?6 AND version=?8 AND active=1 AND deleted=0))
        THEN 1 ELSE 0 END")
        .bind_refs(&[V::Text(&guard),V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id),
            V::Integer(admission.source_version.unwrap_or(0) as i32),V::Text(external),V::Text(user_id),V::Integer(admission.directory_version.unwrap_or(0) as i32)])
        .map_err(|_|LifecycleError::storage())?,
        db.prepare(PIN_DIRECTORY_LINK_SQL).bind_refs(&[V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id),V::Text(external),V::Text(user_id),V::Integer(now)]).map_err(|_|LifecycleError::storage())?,
        db.prepare("UPDATE zeroth_directory_users SET user_id=COALESCE(user_id,?5),version=version+1,updated_at=?6
          WHERE tenant_id=?1 AND provider_id=?2 AND authority_id=?3 AND external_id=?4 AND active=1 AND deleted=0 AND user_id IS NULL")
          .bind_refs(&[V::Text(&authority.tenant_id),V::Text(&authority.provider_id),V::Text(&authority.authority_id),V::Text(external),V::Text(user_id),V::Integer(now)]).map_err(|_|LifecycleError::storage())?,
    ];
    // A concurrent first source enable cannot bypass strict unknown-user gating.
    statements.push(db.prepare("INSERT INTO zeroth_audit_write_guards(id,valid)
      SELECT ?1,CASE WHEN NOT EXISTS (SELECT 1 FROM zeroth_directory_sources s WHERE s.tenant_id=?2 AND s.enabled=1
        AND (NOT EXISTS(SELECT 1 FROM zeroth_directory_users d WHERE d.tenant_id=s.tenant_id AND d.provider_id=s.provider_id AND d.authority_id=s.authority_id AND d.external_id=?3 AND d.user_id=?4 AND d.active=1 AND d.deleted=0)
          OR (s.provider_id='google_workspace' AND (s.last_full_sync_at IS NULL OR s.last_full_sync_at<?5-900)))) THEN 1 ELSE 0 END")
      .bind_refs(&[V::Text(&config_guard),V::Text(&authority.tenant_id),V::Text(external),V::Text(user_id),V::Integer(now)]).map_err(|_|LifecycleError::storage())?);
    for id in [&guard, &config_guard] {
        statements.push(
            db.prepare("DELETE FROM zeroth_audit_write_guards WHERE id=?")
                .bind_refs(&[V::Text(id)])
                .map_err(|_| LifecycleError::storage())?,
        );
    }
    Ok(statements)
}
