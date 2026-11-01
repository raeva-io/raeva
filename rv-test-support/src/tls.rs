//! Servers that fail a TLS handshake on purpose. A fatal alert in answer to
//! the ClientHello fails the handshake inside rustls the way an untrusted
//! certificate does, without a certificate.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};

/// The `bad_certificate` alert description, which a server that rejects
/// the handshake on trust grounds sends.
pub const BAD_CERTIFICATE: u8 = 0x2a;

pub fn fatal_alert(description: u8) -> [u8; 7] {
    [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, description]
}

/// Reads the ClientHello on `stream` and answers it with a fatal alert.
pub fn reject_handshake(stream: &mut TcpStream, description: u8) {
    let mut hello = [0u8; 512];
    let _ = stream.read(&mut hello);
    let _ = stream.write_all(&fatal_alert(description));
}

/// Accepts one connection on loopback and rejects its handshake with a
/// fatal alert. Join the handle once the client's request has failed.
pub fn reject_one_handshake(description: u8) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS reject server");
    let address = listener.local_addr().expect("TLS reject server address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        reject_handshake(&mut stream, description);
    });
    (address, server)
}
