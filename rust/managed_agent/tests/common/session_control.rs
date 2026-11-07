//! Real managed service and framed conversation fixture shared by host adapters.

use std::sync::Arc;
use std::time::{Duration, Instant};

use a2a::session::{SessionCodec, SessionEndpoint, SessionPayload};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, OperationContext};
use serde_json::Value;

pub(super) fn call(kernel: &Kernel, method: &str, payload: Value) -> Result<Value, String> {
    let mut ctx = OperationContext::new("operator", "root", false, Some("operator"), false);
    // The fixture's operator holds an explicit root grant: under the
    // caller-context rules an ordinary agent credential reaches the root
    // default only through a grant, never by omitting the field.
    ctx.zone_perms = vec![("root".to_string(), "rw".to_string())];
    let response = kernel
        .dispatch_rust_call(
            "managed_agent",
            method,
            payload.to_string().as_bytes(),
            &ctx,
        )
        .expect("installed service")
        .map_err(|e| format!("{e:?}"))?;
    serde_json::from_slice(&response).map_err(|e| e.to_string())
}

pub(super) fn receive(
    kernel: &Kernel,
    endpoint: &SessionEndpoint,
    codec: &mut SessionCodec,
    offset: &mut usize,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some((data, next)) = kernel
            .stream_read_at(&endpoint.transcript, *offset)
            .unwrap()
        {
            *offset = next;
            match codec.decode(&data).unwrap() {
                Some(SessionPayload::Rpc { message }) => return message,
                Some(SessionPayload::Closed { reason }) => panic!("unexpected closure: {reason}"),
                None => {}
            }
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    panic!("timed out waiting for a session message")
}

pub(super) fn send(
    kernel: &Kernel,
    endpoint: &SessionEndpoint,
    codec: &mut SessionCodec,
    message: Value,
) -> Vec<u8> {
    let bytes = codec.encode(SessionPayload::Rpc { message }).unwrap();
    let ctx = OperationContext::new("operator", "root", false, Some("operator"), false);
    assert!(
        KernelSyscall::sys_write(kernel, &endpoint.transcript, &ctx, &bytes, 0)
            .unwrap()
            .hit
    );
    bytes
}

pub(super) fn session_kernel(agent: &str) -> Arc<Kernel> {
    let kernel = Arc::new(Kernel::new());
    kernel.vfs_router_arc().add_mount("/", "root", None, false);
    a2a::install_a2a_stamp_hook(&kernel, true).unwrap();
    managed_agent::install_managed_agent(&kernel).unwrap();
    // This fixture has no raft WAL. Use the kernel's framed memory stream;
    // production provisions the same record API over the replicated WAL.
    let path = a2a::conversation_transcript_path(&a2a::conversation_id(agent, "operator"));
    let parent = path.rsplit_once('/').unwrap().0;
    // Fixture provisioning: the kernel-level ctx the typed sys_setattr
    // requires; not the subject under test.
    let ctx = contracts::OperationContext::new("system", "root", true, None, true);
    kernel
        .sys_setattr(
            parent, &ctx, 1, "", None, None, None, "balanced", "root", false, 0, None, None, None,
            None, None, None, None, None, None, None, None,
        )
        .unwrap();
    kernel
        .sys_setattr(
            &path,
            &ctx,
            4,
            "",
            None,
            None,
            None,
            "memory",
            "root",
            false,
            1 << 20,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    kernel
}
