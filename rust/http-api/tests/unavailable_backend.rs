mod support;

use std::io::ErrorKind;
use support::UnavailableBackend;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn unavailable_backend_reserves_its_address_without_accepting_connections() {
    let backend = UnavailableBackend::bind();
    let endpoint = backend.endpoint();
    let address = endpoint.strip_prefix("http://").unwrap();

    for _ in 0..2 {
        let competing_listener = TcpListener::bind(address).await;
        assert!(
            competing_listener.is_err(),
            "another service must not acquire the unavailable backend address"
        );
        let error = TcpStream::connect(address)
            .await
            .expect_err("reserved backend must refuse connections");
        // macOS hosted runners can time out on a bound, non-listening port.
        // Both outcomes keep the endpoint unavailable; the HTTP fixtures
        // independently require the original 503 response.
        assert!(
            matches!(
                error.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::TimedOut
            ),
            "reserved backend must remain unreachable: {error}"
        );
    }
    drop(backend);
}
