#![allow(missing_docs)]

pub mod fixtures;
pub mod golden;
pub mod http;
pub mod net;
pub mod tls;

use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use tracing::Dispatch;
use tracing::subscriber::NoSubscriber;

/// Run a synchronous body with a deterministic thread-local subscriber,
/// without losing events to callsite races.
///
/// tracing-core's single-dispatcher fast path initializes process-wide callsite
/// interest from the registering thread's default. A thread without a subscriber
/// can cache `Interest::never()` while another captures that callsite.
/// Serializing captures cannot prevent uncaptured tests from registering callsites.
///
/// Retain two inert dispatchers for the process lifetime so registration always
/// consults all live subscribers. Neither is installed as a default or receives
/// events. Actual capture and filtering remain scoped to the calling thread.
pub fn with_default<T>(
    subscriber: impl tracing::Subscriber + Send + Sync + 'static,
    body: impl FnOnce() -> T,
) -> T {
    static DISPATCHERS: OnceLock<[Dispatch; 2]> = OnceLock::new();
    DISPATCHERS.get_or_init(|| {
        [
            Dispatch::new(NoSubscriber::default()),
            Dispatch::new(NoSubscriber::default()),
        ]
    });
    tracing::subscriber::with_default(subscriber, body)
}

/// Run `body` under [`with_default`] and return the events it logged at
/// WARN and above, formatted without color, one line each.
pub fn capture_warnings(body: impl FnOnce()) -> String {
    let log = Log::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    with_default(subscriber, body);
    let bytes = std::mem::take(&mut *log.0.lock().unwrap_or_else(PoisonError::into_inner));
    String::from_utf8(bytes).expect("UTF-8 log")
}

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Log {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut log = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        log.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Make `link`, which must not exist yet, a directory junction to `target`.
/// The target is stored exactly as given, so a `\\?\` path can name a
/// directory such as `project.` that a plain Windows path cannot reach;
/// `mklink /J` and PowerShell normalize such a target away.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn create_junction(link: &std::path::Path, target: &std::path::Path) -> std::io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn DeviceIoControl(
            device: *mut c_void,
            code: u32,
            input: *const c_void,
            input_size: u32,
            output: *mut c_void,
            output_size: u32,
            returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }

    let target = target.to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-Unicode target")
    })?;
    let target = target.strip_prefix(r"\\?\").unwrap_or(target);
    let substitute: Vec<u16> = format!(r"\??\{target}").encode_utf16().collect();
    let print: Vec<u16> = target.encode_utf16().collect();
    let names: Vec<u16> = substitute
        .iter()
        .chain([&0])
        .chain(&print)
        .chain([&0])
        .copied()
        .collect();
    let length = |units: usize| {
        u16::try_from(units * 2).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "junction target too long")
        })
    };
    let substitute_length = length(substitute.len())?;
    let header = [
        0,
        substitute_length,
        substitute_length + 2,
        length(print.len())?,
    ];
    let data_length = length(header.len() + names.len())?;

    let mut buffer = Vec::new();
    buffer.extend(IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buffer.extend(data_length.to_le_bytes());
    buffer.extend(0u16.to_le_bytes());
    for unit in header.into_iter().chain(names) {
        buffer.extend(unit.to_le_bytes());
    }

    std::fs::create_dir(link)?;
    let directory = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(link)?;
    let mut returned = 0;
    // SAFETY: the handle is open for the call, the input buffer outlives it,
    // and no output buffer or overlapped I/O is passed.
    let succeeded = unsafe {
        DeviceIoControl(
            directory.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            buffer.as_ptr().cast(),
            buffer.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
