use super::*;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use zeroth_audit::{AuditActor, AuditOutcome};

type ItemKey = (String, String);
type Item = HashMap<String, AttributeValue>;

#[derive(Default)]
struct FakeDynamo {
    items: RefCell<HashMap<ItemKey, Item>>,
    transaction_calls: Cell<usize>,
    commit_then_lose_ack: Cell<bool>,
    fail_complete: Cell<bool>,
    calls: Rc<RefCell<Vec<&'static str>>>,
}

fn text<'a>(item: &'a Item, key: &str) -> &'a str {
    item[key].as_s().unwrap()
}

impl DynamoBackend for FakeDynamo {
    fn get_event<'a>(&'a self, event_id: &'a str) -> AwsFuture<'a, Option<String>> {
        Box::pin(async move {
            Ok(self
                .items
                .borrow()
                .get(&("audit".into(), format!("event#{event_id}")))
                .map(|item| text(item, "event_json").to_owned()))
        })
    }

    fn transact<'a>(&'a self, items: Vec<TransactWriteItem>, token: String) -> AwsFuture<'a, ()> {
        Box::pin(async move {
            self.transaction_calls.set(self.transaction_calls.get() + 1);
            assert_eq!(token.len(), 32);
            // Model the service's all-or-nothing conditional Put transaction.
            // Production sends the same SDK items to TransactWriteItems.
            let mut proposed = self.items.borrow().clone();
            for item in items {
                let put = item.put().unwrap();
                let key = (
                    put.table_name().to_owned(),
                    text(put.item(), "pk").to_owned(),
                );
                if put.condition_expression() == Some("attribute_not_exists(pk)")
                    && proposed.contains_key(&key)
                {
                    return Err(AuditError::Storage);
                }
                proposed.insert(key, put.item().clone());
            }
            *self.items.borrow_mut() = proposed;
            if self.commit_then_lose_ack.replace(false) {
                return Err(AuditError::Storage);
            }
            Ok(())
        })
    }

    fn pending(&self, limit: usize) -> AwsFuture<'_, Vec<PendingEvent>> {
        Box::pin(async move {
            Ok(self
                .items
                .borrow()
                .values()
                .filter(|item| item.contains_key("pending_partition"))
                .take(limit)
                .map(|item| PendingEvent {
                    event_id: text(item, "event_id").into(),
                    event_json: text(item, "event_json").into(),
                })
                .collect())
        })
    }

    fn complete<'a>(&'a self, event: &'a PendingEvent) -> AwsFuture<'a, ()> {
        Box::pin(async move {
            self.calls.borrow_mut().push("complete");
            if self.fail_complete.get() {
                return Err(AuditError::Storage);
            }
            let key = ("audit".into(), format!("outbox#{}", event.event_id));
            let mut items = self.items.borrow_mut();
            let item = items.get_mut(&key).ok_or(AuditError::Storage)?;
            if text(item, "event_json") != event.event_json {
                return Err(AuditError::EventIdCollision);
            }
            item.remove("pending_partition");
            item.remove("pending_sort");
            item.insert("status".into(), AttributeValue::S("delivered".into()));
            Ok(())
        })
    }
}

fn event() -> AuditEvent {
    AuditEvent::new(
        "evt_1",
        4_000_000_000,
        4_000_000_001,
        "user.disable",
        AuditActor::new("administrator", "usr_admin").unwrap(),
        AuditOutcome::Success,
    )
    .unwrap()
}

fn business_put(table: &str, pk: &str, conditional: bool) -> TransactWriteItem {
    let mut put = Put::builder()
        .table_name(table)
        .item("pk", AttributeValue::S(pk.into()));
    if conditional {
        put = put.condition_expression("attribute_not_exists(pk)");
    }
    TransactWriteItem::builder()
        .put(put.build().unwrap())
        .build()
}

#[test]
fn sdk_transaction_has_two_conditional_audit_writes_and_preserves_business_condition() {
    let event = event();
    let canonical = event.canonical_json().unwrap();
    let writes = build_transaction(
        "audit",
        &event,
        &canonical,
        vec![business_put("business", "usr_1", true)],
    )
    .unwrap();
    assert_eq!(writes.len(), 3);
    assert_eq!(writes[0].put().unwrap().table_name(), "business");
    for write in &writes {
        assert_eq!(
            write.put().unwrap().condition_expression(),
            Some("attribute_not_exists(pk)")
        );
    }
    assert_eq!(text(writes[1].put().unwrap().item(), "pk"), "event#evt_1");
    let pending = writes[2].put().unwrap().item();
    assert_eq!(text(pending, "pk"), "outbox#evt_1");
    assert_eq!(text(pending, "pending_partition"), "pending");
    assert_eq!(text(pending, "event_json"), canonical);
    assert!(!writes[1]
        .put()
        .unwrap()
        .item()
        .contains_key("pending_partition"));
}

#[tokio::test]
async fn rejected_business_write_leaves_no_event_or_outbox() {
    let fake = FakeDynamo::default();
    let existing = HashMap::from([("pk".into(), AttributeValue::S("usr_1".into()))]);
    fake.items
        .borrow_mut()
        .insert(("business".into(), "usr_1".into()), existing.clone());
    assert_eq!(
        capture_with(
            &fake,
            "audit",
            &event(),
            vec![business_put("business", "usr_1", true)]
        )
        .await,
        Err(AuditError::Storage)
    );
    assert!(fake.get_event("evt_1").await.unwrap().is_none());
    assert!(fake.pending(100).await.unwrap().is_empty());
    assert_eq!(
        fake.items.borrow()[&("business".into(), "usr_1".into())],
        existing
    );
}

#[tokio::test]
async fn exact_retry_skips_business_writes_and_changed_payload_is_a_collision() {
    let fake = FakeDynamo::default();
    let mut event = event();
    assert_eq!(
        capture_with(
            &fake,
            "audit",
            &event,
            vec![business_put("business", "usr_1", true)]
        )
        .await,
        Ok(AppendResult::Inserted)
    );
    // The repeated conditional business write would fail if it were reapplied.
    assert_eq!(
        capture_with(
            &fake,
            "audit",
            &event,
            vec![business_put("business", "usr_1", true)]
        )
        .await,
        Ok(AppendResult::Duplicate)
    );
    assert_eq!(fake.transaction_calls.get(), 1);
    event.outcome = AuditOutcome::Denied;
    assert_eq!(
        capture_with(
            &fake,
            "audit",
            &event,
            vec![business_put("business", "usr_2", false)]
        )
        .await,
        Err(AuditError::EventIdCollision)
    );
    assert_eq!(fake.transaction_calls.get(), 1);
    assert!(!fake
        .items
        .borrow()
        .contains_key(&("business".into(), "usr_2".into())));
}

#[tokio::test]
async fn lost_transaction_ack_resolves_by_consistent_read_without_reapplying_business() {
    let fake = FakeDynamo::default();
    fake.commit_then_lose_ack.set(true);
    let event = event();
    assert_eq!(
        capture_with(
            &fake,
            "audit",
            &event,
            vec![business_put("business", "usr_1", true)]
        )
        .await,
        Ok(AppendResult::Duplicate)
    );
    assert_eq!(fake.transaction_calls.get(), 1);
    assert_eq!(fake.items.borrow().len(), 3);
    assert_eq!(fake.pending(100).await.unwrap().len(), 1);
}

#[test]
fn business_mutations_cannot_touch_audit_rows_via_name_or_arn_or_exceed_transaction_limit() {
    let event = event();
    let canonical = event.canonical_json().unwrap();
    for table in [
        "audit",
        "arn:aws:dynamodb:us-east-1:123456789012:table/audit",
    ] {
        assert!(matches!(
            build_transaction(
                "audit",
                &event,
                &canonical,
                vec![business_put(table, "event#evt_1", false)]
            ),
            Err(AuditError::InvalidField("business_mutations"))
        ));
    }
    assert!(build_transaction(
        "audit",
        &event,
        &canonical,
        (0..99)
            .map(|n| business_put("business", &format!("usr_{n}"), false))
            .collect()
    )
    .is_err());
}

struct FakeDestination {
    calls: Rc<RefCell<Vec<&'static str>>>,
    fail: Cell<bool>,
    payloads: RefCell<Vec<String>>,
}

impl AuditSink for FakeDestination {
    fn append<'a>(&'a self, event: &'a AuditEvent) -> AuditFuture<'a> {
        Box::pin(async move {
            self.calls.borrow_mut().push("send");
            if self.fail.get() {
                return Err(AuditError::Storage);
            }
            self.payloads.borrow_mut().push(event.canonical_json()?);
            Ok(AppendResult::Accepted)
        })
    }
}

#[tokio::test]
async fn send_failure_never_completes_outbox_and_is_observable() {
    let fake = FakeDynamo::default();
    capture_with(&fake, "audit", &event(), vec![])
        .await
        .unwrap();
    let destination = FakeDestination {
        calls: fake.calls.clone(),
        fail: Cell::new(true),
        payloads: RefCell::new(vec![]),
    };
    let report = drain_with(&fake, &destination, 10).await.unwrap();
    assert_eq!(
        (report.scanned, report.acknowledged, report.completed),
        (1, 0, 0)
    );
    assert_eq!(report.failures[0].stage, DeliveryStage::Send);
    assert_eq!(fake.calls.borrow().as_slice(), &["send"]);
    assert_eq!(fake.pending(10).await.unwrap().len(), 1);
    destination.fail.set(false);
    let retry = drain_with(&fake, &destination, 10).await.unwrap();
    assert_eq!(retry.completed, 1);
    assert_eq!(
        fake.calls.borrow().as_slice(),
        &["send", "send", "complete"]
    );
    assert!(fake.pending(10).await.unwrap().is_empty());
}

#[tokio::test]
async fn completion_failure_replays_identical_envelope_after_ack() {
    let fake = FakeDynamo::default();
    capture_with(&fake, "audit", &event(), vec![])
        .await
        .unwrap();
    let destination = FakeDestination {
        calls: fake.calls.clone(),
        fail: Cell::new(false),
        payloads: RefCell::new(vec![]),
    };
    fake.fail_complete.set(true);
    let report = drain_with(&fake, &destination, 10).await.unwrap();
    assert_eq!((report.acknowledged, report.completed), (1, 0));
    assert_eq!(report.failures[0].stage, DeliveryStage::Complete);
    assert_eq!(fake.pending(10).await.unwrap().len(), 1);
    fake.fail_complete.set(false);
    assert_eq!(
        drain_with(&fake, &destination, 10).await.unwrap().completed,
        1
    );
    let payloads = destination.payloads.borrow();
    assert_eq!(payloads.len(), 2);
    assert_eq!(payloads[0], payloads[1]);
    assert_eq!(
        fake.calls.borrow().as_slice(),
        &["send", "complete", "send", "complete"]
    );
}

#[tokio::test]
async fn malformed_outbox_data_is_reported_without_delivery_or_completion() {
    let fake = FakeDynamo::default();
    capture_with(&fake, "audit", &event(), vec![])
        .await
        .unwrap();
    fake.items
        .borrow_mut()
        .get_mut(&("audit".into(), "outbox#evt_1".into()))
        .unwrap()
        .insert(
            "event_json".into(),
            AttributeValue::S("{bad secret-token".into()),
        );
    let destination = FakeDestination {
        calls: fake.calls.clone(),
        fail: Cell::new(false),
        payloads: RefCell::new(vec![]),
    };
    let report = drain_with(&fake, &destination, 10).await.unwrap();
    assert_eq!(report.failures[0].stage, DeliveryStage::Decode);
    assert!(fake.calls.borrow().is_empty());
    assert!(!format!("{report:?}").contains("secret-token"));
    assert!(drain_with(&fake, &destination, 0).await.is_err());
}
