mod support;

use std::io::ErrorKind;
use support::UnavailableBackend;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn unavailable_backend_reserves_its_address_while_connections_are_refused() {
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
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
    }
    drop(backend);
}
