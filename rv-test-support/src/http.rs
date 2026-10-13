//! Ordinary HTTP/1.1 fixtures. Transport failures belong in individual tests.

use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;
use tokio::task::JoinSet;

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Request text, including the body, for credential and payload assertions.
    pub raw: String,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

#[derive(Default)]
struct State {
    connections: AtomicUsize,
    answered: AtomicUsize,
    requests: Mutex<Vec<Request>>,
}

/// Runs on its own thread so synchronous tests and subprocesses can use it too.
/// Dropping the fixture stops the listener and all open connections, then joins.
pub struct StubServer {
    addr: SocketAddr,
    state: Arc<State>,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl StubServer {
    /// The handler runs on the server's only runtime thread. It must not wait
    /// for anything the test releases after `stop()` or drop, which join that
    /// thread.
    pub fn start(handler: impl Fn(&Request) -> Response + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP stub");
        let addr = listener.local_addr().expect("HTTP stub address");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let state = Arc::new(State::default());
        let serving = state.clone();
        let (shutdown, mut stopped) = oneshot::channel();
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("HTTP stub runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("listener");
                let handler = Arc::new(handler);
                let mut tasks = JoinSet::new();
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        result = tasks.join_next(), if !tasks.is_empty() => {
                            result.expect("connection task").expect("HTTP handler panicked");
                        }
                        accepted = listener.accept() => {
                            let (socket, _) = accepted.expect("accept HTTP connection");
                            serving.connections.fetch_add(1, Ordering::SeqCst);
                            let handler = handler.clone();
                            let state = serving.clone();
                            tasks.spawn(async move {
                                let _ = serve(socket, &*handler, &state).await;
                            });
                        }
                    }
                }
                tasks.abort_all();
                while let Some(result) = tasks.join_next().await {
                    if let Err(error) = result {
                        assert!(error.is_cancelled(), "HTTP handler panicked: {error}");
                    }
                }
            });
        });
        Self {
            addr,
            state,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    pub fn answered(&self) -> usize {
        self.state.answered.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> Vec<Request> {
        self.state.requests.lock().expect("request log").clone()
    }

    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for StubServer {
    fn drop(&mut self) {
        let _ = self.shutdown.take().expect("shutdown sender").send(());
        let result = self.thread.take().expect("server thread").join();
        if !thread::panicking() {
            result.expect("HTTP stub panicked");
        }
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

async fn serve(
    socket: tokio::net::TcpStream,
    handler: &impl Fn(&Request) -> Response,
    state: &State,
) -> std::io::Result<()> {
    let mut socket = BufReader::new(socket);
    loop {
        let mut raw = String::new();
        if socket.read_line(&mut raw).await? == 0 {
            return Ok(());
        }
        let mut parts = raw.split_whitespace();
        let method = parts.next().expect("request method").to_string();
        let path = parts.next().expect("request path").to_string();
        let mut headers = Vec::new();
        loop {
            let start = raw.len();
            let read = socket.read_line(&mut raw).await?;
            assert_ne!(read, 0, "request ended before its headers were complete");
            let line = raw[start..].trim_end();
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').expect("request header");
            headers.push((name.to_string(), value.trim().to_string()));
        }
        let length = header(&headers, "Content-Length")
            .map(|value| value.parse().expect("request Content-Length"))
            .unwrap_or(0);
        let mut body = vec![0; length];
        socket
            .read_exact(&mut body)
            .await
            .expect("request ended before its body was complete");
        raw.push_str(&String::from_utf8_lossy(&body));
        let request = Request {
            method,
            path,
            headers,
            body,
            raw,
        };
        state
            .requests
            .lock()
            .expect("request log")
            .push(request.clone());
        let response = handler(&request);
        let keep_alive = header(&response.headers, "Connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("keep-alive"))
            && !request
                .header("Connection")
                .is_some_and(|value| value.eq_ignore_ascii_case("close"));
        let mut head = format!("HTTP/1.1 {} Stub\r\n", response.status);
        for (name, value) in &response.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if header(&response.headers, "Content-Length").is_none() {
            head.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
        }
        if header(&response.headers, "Connection").is_none() {
            head.push_str("Connection: close\r\n");
        }
        head.push_str("\r\n");
        // Counted before writing: a client that has read the response must
        // already see it in `answered()`.
        state.answered.fetch_add(1, Ordering::SeqCst);
        socket.get_mut().write_all(head.as_bytes()).await?;
        if request.method != "HEAD" {
            socket.get_mut().write_all(&response.body).await?;
        }
        if !keep_alive {
            return socket.get_mut().shutdown().await;
        }
    }
}
