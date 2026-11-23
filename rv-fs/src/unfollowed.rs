use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Open `path`, creating it, as a file raeva locks and writes in place. A
/// symlink or anything else that is not a regular file is refused, so
/// neither the lock nor the write lands on another file.
pub fn open_lock_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    let file =
        unfollowed(&mut options)
            .open(path)
            .map_err(|err| match is_nofollow_symlink(&err) {
                true => io::Error::other("it is a symbolic link, which raeva does not follow"),
                false => err,
            })?;
    if !opened_is_regular(&file.metadata()?) {
        return Err(io::Error::other("it is not a regular file"));
    }
    Ok(file)
}

/// `options` that neither follow a final symlink or reparse point nor wait
/// for a FIFO's other end.
pub fn unfollowed(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        options,
        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
    );
    #[cfg(windows)]
    {
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        std::os::windows::fs::OpenOptionsExt::custom_flags(options, FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
}

/// Whether a file opened with [`unfollowed`] options is a regular file,
/// not a reparse point opened as itself.
pub fn opened_is_regular(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        meta.is_file() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
    }
    #[cfg(not(windows))]
    {
        meta.is_file()
    }
}

/// `O_NOFOLLOW` on a symlink is `ELOOP` (`ErrorKind::FilesystemLoop` is
/// unstable on the MSRV).
pub fn is_nofollow_symlink(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        rustix::io::Errno::from_io_error(err) == Some(rustix::io::Errno::LOOP)
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}
