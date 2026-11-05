//! The Worker console receives a small JSON tracing mirror. It is never a sink
//! acknowledgement and never includes the durable event body.
#[cfg(target_arch = "wasm32")]
pub(super) fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = tracing::subscriber::set_global_default(ConsoleSubscriber);
    });
}

#[cfg(target_arch = "wasm32")]
struct ConsoleSubscriber;

#[cfg(target_arch = "wasm32")]
impl tracing::Subscriber for ConsoleSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().starts_with("zeroth.audit")
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields(serde_json::Map::new());
        fields
            .0
            .insert("target".into(), event.metadata().target().into());
        fields
            .0
            .insert("level".into(), event.metadata().level().as_str().into());
        event.record(&mut fields);
        worker::console_log!("{}", serde_json::Value::Object(fields.0));
    }
}

#[cfg(target_arch = "wasm32")]
struct Fields(serde_json::Map<String, serde_json::Value>);

#[cfg(target_arch = "wasm32")]
impl tracing::field::Visit for Fields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().into(), format!("{value:?}").into());
    }
}
