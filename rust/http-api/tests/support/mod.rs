use tokio::net::TcpSocket;

/// Reserve an address that refuses connections for the entire request lifetime.
pub struct UnavailableBackend {
    socket: TcpSocket,
}

impl UnavailableBackend {
    pub fn bind() -> Self {
        let socket = TcpSocket::new_v4().expect("create unavailable backend socket");
        socket
            .bind("127.0.0.1:0".parse().unwrap())
            .expect("reserve unavailable backend address");
        Self { socket }
    }

    pub fn endpoint(&self) -> String {
        format!(
            "http://{}",
            self.socket.local_addr().expect("reserved backend address")
        )
    }
}
