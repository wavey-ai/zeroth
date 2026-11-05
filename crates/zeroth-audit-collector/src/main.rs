#[cfg(not(target_arch = "wasm32"))]
mod native;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    native::run()
}

// This optional executable only runs on a native host; allow workspace-wide
// wasm checks without introducing native SDKs into the Worker dependency tree.
#[cfg(target_arch = "wasm32")]
fn main() {}
