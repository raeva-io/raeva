//! Network endpoints for transport failure tests.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

/// A loopback port that refuses every connection.
///
/// The port is the local end of an established loopback connection, so it
/// stays reserved while this value lives and nothing listens on it. A socket
/// that is only bound would do on Linux, but macOS silently drops connection
/// attempts to one, and they time out instead of being refused.
pub struct RefusingPort {
    _connection: TcpStream,
    _peer: TcpStream,
    addr: SocketAddr,
}

impl RefusingPort {
    pub fn bind() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind peer listener");
        let connection = TcpStream::connect(listener.local_addr().expect("peer address"))
            .expect("connect reserved port");
        let (peer, _) = listener.accept().expect("accept reserved connection");
        let addr = connection.local_addr().expect("refusing port address");
        Self {
            _connection: connection,
            _peer: peer,
            addr,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}
