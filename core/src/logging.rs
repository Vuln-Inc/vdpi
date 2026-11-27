use std::fs;
use std::io::{self, BufWriter, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

pub const DEFAULT_LOG_FILE_NAME: &str = "vdpi.log";
pub const MAX_LOG_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_LOG_BACKUPS: usize = 3;

const CHANNEL_CAPACITY: usize = 512;
const BUF_WRITER_CAPACITY: usize = 8192;
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const FLUSH_WAIT_TIMEOUT: Duration = Duration::from_secs(3);
const ROTATION_RETRY_BACKOFF: Duration = Duration::from_secs(5);

static GLOBAL_SERVICE_LOG: Mutex<Option<Arc<ServiceLogFlushHandle>>> = Mutex::new(None);

#[cfg(windows)]
mod win_fs {
    use std::ffi::OsStr;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, ErrorKind};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    pub(super) const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    pub(super) const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    pub(super) const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PATH_NOT_FOUND: i32 = 3;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileAttributesW(lp_file_name: *const u16) -> u32;
    }

    pub(super) fn is_reparse_point_attrs(attrs: u32) -> bool {
        attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }

    pub(super) fn is_sharing_violation(err: &io::Error) -> bool {
        matches!(
            err.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
        )
    }

    fn encode_wide_nul(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn path_attributes_no_follow(path: &Path) -> io::Result<Option<u32>> {
        let wide = encode_wide_nul(path.as_os_str());
        // SAFETY: `wide` is valid NUL-terminated UTF-16 for the synchronous `GetFileAttributesW` call.
        let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attrs != INVALID_FILE_ATTRIBUTES {
            return Ok(Some(attrs));
        }
        let err = io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
        ) || err.kind() == ErrorKind::NotFound
        {
            return Ok(None);
        }
        Err(err)
    }

    pub(super) fn reject_reparse_point(path: &Path) -> io::Result<()> {
        if let Some(attrs) = path_attributes_no_follow(path)? {
            if is_reparse_point_attrs(attrs) {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!("refusing to access NTFS reparse point: {}", path.display()),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn reject_reparse_point_or_dir(path: &Path) -> io::Result<()> {
        if let Some(attrs) = path_attributes_no_follow(path)? {
            if is_reparse_point_attrs(attrs) {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!("refusing to access NTFS reparse point: {}", path.display()),
                ));
            }
            if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!("refusing to open directory as log file: {}", path.display()),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn ensure_safe_log_dir(dir: &Path) -> io::Result<()> {
        reject_reparse_point(dir)?;
        if !dir.exists() {
            fs::create_dir_all(dir)?;
        }
        let attrs = path_attributes_no_follow(dir)?.ok_or_else(|| {
            io::Error::new(
                ErrorKind::NotFound,
                format!("log directory missing after creation: {}", dir.display()),
            )
        })?;
        if is_reparse_point_attrs(attrs) {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "refusing to use NTFS reparse point as log directory: {}",
                    dir.display()
                ),
            ));
        }
        if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!("log directory path is not a directory: {}", dir.display()),
            ));
        }
        Ok(())
    }

    pub(super) fn open_safe_log_file(path: &Path) -> io::Result<(File, u64)> {
        reject_reparse_point_or_dir(path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let meta = file.metadata()?;
        if is_reparse_point_attrs(meta.file_attributes()) || !meta.is_file() {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "refusing to write log file: opened handle is a reparse point or non-file: {}",
                    path.display()
                ),
            ));
        }
        Ok((file, meta.len()))
    }
}

#[cfg(not(windows))]
mod unix_fs {
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, ErrorKind};
    use std::path::Path;

    pub(super) fn is_sharing_violation(_err: &io::Error) -> bool {
        false
    }

    pub(super) fn reject_reparse_point_or_dir(path: &Path) -> io::Result<()> {
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(io::Error::new(
                        ErrorKind::PermissionDenied,
                        format!("refusing to access symlink log path: {}", path.display()),
                    ));
                }
                if meta.is_dir() {
                    return Err(io::Error::new(
                        ErrorKind::PermissionDenied,
                        format!("refusing to open directory as log file: {}", path.display()),
                    ));
                }
                Ok(())
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub(super) fn ensure_safe_log_dir(dir: &Path) -> io::Result<()> {
        match fs::symlink_metadata(dir) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(io::Error::new(
                        ErrorKind::PermissionDenied,
                        format!(
                            "refusing to use non-directory or symlink as log directory: {}",
                            dir.display()
                        ),
                    ));
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                fs::create_dir_all(dir)?;
            }
            Err(err) => return Err(err),
        }
        Ok(())
    }

    pub(super) fn open_safe_log_file(path: &Path) -> io::Result<(File, u64)> {
        reject_reparse_point_or_dir(path)?;
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!("refusing to write non-regular log file: {}", path.display()),
            ));
        }
        Ok((file, meta.len()))
    }
}

#[cfg(windows)]
use win_fs as platform_fs;
#[cfg(not(windows))]
use unix_fs as platform_fs;

struct FlushState {
    requested_gen: u64,
    completed_gen: u64,
    exited: bool,
}

struct FlushNotifier {
    state: Mutex<FlushState>,
    cvar: Condvar,
}

impl FlushNotifier {
    fn new() -> Self {
        Self {
            state: Mutex::new(FlushState {
                requested_gen: 0,
                completed_gen: 0,
                exited: false,
            }),
            cvar: Condvar::new(),
        }
    }

    fn requested_gen(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .requested_gen
    }

    fn request_flush(&self) -> Option<u64> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.exited {
            return None;
        }
        st.requested_gen = st.requested_gen.saturating_add(1);
        Some(st.requested_gen)
    }

    fn wait_for_gen(&self, target: u64, timeout: Duration) {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self.cvar.wait_timeout_while(st, timeout, |s| {
            !s.exited && s.completed_gen < target
        });
    }

    fn mark_completed(&self, generation: u64) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if generation > st.completed_gen {
            st.completed_gen = generation;
        }
        self.cvar.notify_all();
    }

    fn mark_exited(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.completed_gen = st.requested_gen;
        st.exited = true;
        self.cvar.notify_all();
    }
}

struct ServiceLogFlushHandle {
    wake_tx: SyncSender<Vec<u8>>,
    notifier: Arc<FlushNotifier>,
}

impl ServiceLogFlushHandle {
    fn flush(&self) {
        let Some(target) = self.notifier.request_flush() else {
            return;
        };
        // Best-effort wakeup for the worker thread if it is sleeping in `recv_timeout`.
        // If the channel is already full, the worker is actively draining it.
        let _ = self.wake_tx.try_send(Vec::new());
        self.notifier.wait_for_gen(target, FLUSH_WAIT_TIMEOUT);
    }
}

/// Guard returned by [`init_service_file_tracing`] or [`SizeRotatingWriter::open`].
/// Flushes buffered service log entries cleanly when [`Self::flush`] is called or on [`Drop`].
pub struct ServiceLogGuard {
    flush_handle: Arc<ServiceLogFlushHandle>,
}

impl ServiceLogGuard {
    pub fn flush(&self) {
        self.flush_handle.flush();
    }
}

impl Drop for ServiceLogGuard {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Bounded, non-blocking, size-rotating file writer for Windows/background service logging.
///
/// Writers push formatted log records into a bounded `sync_channel` using `try_send` so
/// hot-path TUN, proxy, and real-time audio threads never block on disk I/O.
#[derive(Clone)]
pub struct SizeRotatingWriter {
    tx: SyncSender<Vec<u8>>,
    flush_handle: Arc<ServiceLogFlushHandle>,
    dropped: Arc<AtomicU64>,
}

impl SizeRotatingWriter {
    pub fn open(
        log_dir: &Path,
        max_bytes: u64,
        max_backups: usize,
    ) -> io::Result<(Self, ServiceLogGuard)> {
        Self::open_with_options(
            log_dir,
            DEFAULT_LOG_FILE_NAME,
            max_bytes,
            max_backups,
            ROTATION_RETRY_BACKOFF,
        )
    }

    fn open_with_options(
        log_dir: &Path,
        file_name: &str,
        max_bytes: u64,
        max_backups: usize,
        rotation_retry_backoff: Duration,
    ) -> io::Result<(Self, ServiceLogGuard)> {
        let sink = RotatingFileSink::open(
            log_dir.to_path_buf(),
            file_name.to_string(),
            max_bytes,
            max_backups,
            rotation_retry_backoff,
        )?;
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_CAPACITY);
        let notifier = Arc::new(FlushNotifier::new());
        let worker_notifier = Arc::clone(&notifier);

        thread::Builder::new()
            .name("vdpi-log-writer".to_string())
            .spawn(move || run_log_worker(rx, sink, worker_notifier))?;

        let flush_handle = Arc::new(ServiceLogFlushHandle {
            wake_tx: tx.clone(),
            notifier,
        });
        let writer = Self {
            tx,
            flush_handle: Arc::clone(&flush_handle),
            dropped: Arc::new(AtomicU64::new(0)),
        };
        let guard = ServiceLogGuard { flush_handle };
        Ok((writer, guard))
    }

    pub fn flush_blocking(&self) {
        self.flush_handle.flush();
    }

    pub fn dropped_records(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn try_enqueue(&self, chunk: Vec<u8>) {
        if chunk.is_empty() {
            return;
        }
        if let Err(TrySendError::Full(_)) = self.tx.try_send(chunk) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Write for SizeRotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !buf.is_empty() {
            self.try_enqueue(buf.to_vec());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_blocking();
        Ok(())
    }
}

/// Per-event writer handed out by [`MakeWriter`] so each formatted log line is sent
/// atomically as a single non-blocking `try_send`.
pub struct SizeRotatingLineWriter {
    tx: SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
    buf: Vec<u8>,
}

impl SizeRotatingLineWriter {
    fn flush_line(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let chunk = std::mem::take(&mut self.buf);
        if let Err(TrySendError::Full(_)) = self.tx.try_send(chunk) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Write for SizeRotatingLineWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_line();
        Ok(())
    }
}

impl Drop for SizeRotatingLineWriter {
    fn drop(&mut self) {
        self.flush_line();
    }
}

impl<'a> MakeWriter<'a> for SizeRotatingWriter {
    type Writer = SizeRotatingLineWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SizeRotatingLineWriter {
            tx: self.tx.clone(),
            dropped: Arc::clone(&self.dropped),
            buf: Vec::with_capacity(256),
        }
    }
}

struct RotatingFileSink {
    log_dir: PathBuf,
    file_name: String,
    max_bytes: u64,
    max_backups: usize,
    writer: Option<BufWriter<fs::File>>,
    current_bytes: u64,
    dirty: bool,
    last_flush: Instant,
    rotation_retry_after: Option<Instant>,
    rotation_retry_backoff: Duration,
}

impl RotatingFileSink {
    fn open(
        log_dir: PathBuf,
        file_name: String,
        max_bytes: u64,
        max_backups: usize,
        rotation_retry_backoff: Duration,
    ) -> io::Result<Self> {
        platform_fs::ensure_safe_log_dir(&log_dir)?;
        let active_path = log_dir.join(&file_name);
        let (file, current_bytes) = platform_fs::open_safe_log_file(&active_path)?;
        Ok(Self {
            log_dir,
            file_name,
            max_bytes,
            max_backups,
            writer: Some(BufWriter::with_capacity(BUF_WRITER_CAPACITY, file)),
            current_bytes,
            dirty: false,
            last_flush: Instant::now(),
            rotation_retry_after: None,
            rotation_retry_backoff,
        })
    }

    fn active_path(&self) -> PathBuf {
        self.log_dir.join(&self.file_name)
    }

    fn backup_path(&self, index: usize) -> PathBuf {
        self.log_dir.join(format!("{}.{}", self.file_name, index))
    }

    fn staging_path(&self) -> PathBuf {
        self.log_dir.join(format!("{}.rotating", self.file_name))
    }

    fn reopen_active(&mut self) {
        if platform_fs::ensure_safe_log_dir(&self.log_dir).is_err() {
            self.writer = None;
            return;
        }
        let active = self.active_path();
        match platform_fs::open_safe_log_file(&active) {
            Ok((file, len)) => {
                self.writer = Some(BufWriter::with_capacity(BUF_WRITER_CAPACITY, file));
                self.current_bytes = len;
            }
            Err(_) => {
                self.writer = None;
            }
        }
    }

    fn defer_rotation(&mut self) {
        self.rotation_retry_after = Some(Instant::now() + self.rotation_retry_backoff);
        self.reopen_active();
    }

    fn write_chunk(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        let needs_rotation = self.max_bytes > 0
            && self.current_bytes > 0
            && self.current_bytes.saturating_add(chunk.len() as u64) > self.max_bytes;
        if needs_rotation {
            let retry_ready = self
                .rotation_retry_after
                .is_none_or(|retry_at| Instant::now() >= retry_at);
            if retry_ready {
                self.rotate();
            }
        }

        if self.writer.is_none() {
            self.reopen_active();
        }
        if let Some(ref mut w) = self.writer {
            if w.write_all(chunk).is_ok() {
                self.current_bytes = self.current_bytes.saturating_add(chunk.len() as u64);
                self.dirty = true;
            }
        }
    }

    fn flush(&mut self) {
        if let Some(ref mut w) = self.writer {
            let _ = w.flush();
        }
        self.dirty = false;
        self.last_flush = Instant::now();
    }

    fn rotate(&mut self) {
        if let Some(mut w) = self.writer.take() {
            let _ = w.flush();
        }
        self.dirty = false;
        self.last_flush = Instant::now();

        if platform_fs::ensure_safe_log_dir(&self.log_dir).is_err() {
            self.rotation_retry_after = Some(Instant::now() + self.rotation_retry_backoff);
            return;
        }

        let active = self.active_path();
        if platform_fs::reject_reparse_point_or_dir(&active).is_err() {
            self.rotation_retry_after = Some(Instant::now() + self.rotation_retry_backoff);
            return;
        }

        if self.max_backups == 0 {
            match fs::remove_file(&active) {
                Ok(()) => {
                    self.rotation_retry_after = None;
                    self.reopen_active();
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {
                    self.rotation_retry_after = None;
                    self.reopen_active();
                }
                Err(err) => {
                    let _ = platform_fs::is_sharing_violation(&err);
                    self.defer_rotation();
                }
            }
            return;
        }

        let staging = self.staging_path();
        if platform_fs::reject_reparse_point_or_dir(&staging).is_err() {
            self.defer_rotation();
            return;
        }

        // Move active file to a temporary staging name first so that if an external reader
        // holds `vdpi.log` open without FILE_SHARE_DELETE (ERROR_SHARING_VIOLATION on Windows),
        // we defer rotation cleanly without disturbing existing backups `vdpi.log.1..N`.
        match fs::rename(&active, &staging) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {
                self.rotation_retry_after = None;
                self.reopen_active();
                return;
            }
            Err(err) => {
                let _ = platform_fs::is_sharing_violation(&err);
                self.defer_rotation();
                return;
            }
        }

        let oldest = self.backup_path(self.max_backups);
        if platform_fs::reject_reparse_point_or_dir(&oldest).is_err() {
            let _ = fs::rename(&staging, &active);
            self.defer_rotation();
            return;
        }
        if let Err(err) = fs::remove_file(&oldest) {
            if err.kind() != ErrorKind::NotFound {
                let _ = platform_fs::is_sharing_violation(&err);
                let _ = fs::rename(&staging, &active);
                self.defer_rotation();
                return;
            }
        }

        for i in (1..self.max_backups).rev() {
            let src = self.backup_path(i);
            let dst = self.backup_path(i + 1);
            if platform_fs::reject_reparse_point_or_dir(&src).is_err()
                || platform_fs::reject_reparse_point_or_dir(&dst).is_err()
            {
                let _ = fs::rename(&staging, &active);
                self.defer_rotation();
                return;
            }
            match fs::rename(&src, &dst) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => {
                    let _ = platform_fs::is_sharing_violation(&err);
                    let _ = fs::rename(&staging, &active);
                    self.defer_rotation();
                    return;
                }
            }
        }

        let first_backup = self.backup_path(1);
        if platform_fs::reject_reparse_point_or_dir(&first_backup).is_err()
            || fs::rename(&staging, &first_backup).is_err()
        {
            let _ = fs::rename(&staging, &active);
            self.defer_rotation();
            return;
        }

        self.rotation_retry_after = None;
        self.reopen_active();
    }
}

fn run_log_worker(
    rx: mpsc::Receiver<Vec<u8>>,
    mut sink: RotatingFileSink,
    notifier: Arc<FlushNotifier>,
) {
    let mut completed_gen: u64 = 0;

    loop {
        let pending_req = notifier.requested_gen();
        let mut disconnected = false;

        if pending_req <= completed_gen {
            let wait = if sink.dirty {
                FLUSH_INTERVAL.saturating_sub(sink.last_flush.elapsed())
            } else {
                FLUSH_INTERVAL
            };
            match rx.recv_timeout(wait) {
                Ok(chunk) => {
                    if !chunk.is_empty() {
                        sink.write_chunk(&chunk);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if sink.dirty {
                        sink.flush();
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    disconnected = true;
                }
            }
        }

        let req_gen = notifier.requested_gen();
        let mut drained_count: usize = 0;

        if !disconnected {
            loop {
                match rx.try_recv() {
                    Ok(chunk) => {
                        if !chunk.is_empty() {
                            sink.write_chunk(&chunk);
                        }
                        drained_count += 1;
                        if sink.dirty && sink.last_flush.elapsed() >= FLUSH_INTERVAL {
                            sink.flush();
                        }
                        if drained_count >= CHANNEL_CAPACITY {
                            break;
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }

        if sink.dirty || req_gen > completed_gen || disconnected {
            sink.flush();
        }

        if req_gen > completed_gen {
            completed_gen = req_gen;
            notifier.mark_completed(completed_gen);
        }

        if disconnected {
            notifier.mark_exited();
            break;
        }
    }
}

fn default_service_log_filter(debug: bool) -> &'static str {
    if debug {
        "vdpi=debug,vdpi_core=debug,vdpi_tun=debug"
    } else {
        "vdpi=info,vdpi_core=warn,vdpi_tun=warn"
    }
}

/// Initializes non-blocking size-rotating file tracing for the background service in `log_dir`
/// (`vdpi.log`, rotating at 2 MiB with 3 backups `vdpi.log.1`..`vdpi.log.3`).
///
/// Honors `RUST_LOG` when set; otherwise defaults to `"vdpi=info,vdpi_core=warn,vdpi_tun=warn"`
/// (or `"vdpi=debug,vdpi_core=debug,vdpi_tun=debug"` when `debug` is `true`).
pub fn init_service_file_tracing(log_dir: &Path, debug: bool) -> Option<ServiceLogGuard> {
    let (writer, guard) =
        SizeRotatingWriter::open(log_dir, MAX_LOG_FILE_BYTES, MAX_LOG_BACKUPS).ok()?;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_service_log_filter(debug)));

    let init_res = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_env_filter(filter)
        .with_ansi(false)
        .try_init();

    if init_res.is_err() {
        return None;
    }

    if let Ok(mut slot) = GLOBAL_SERVICE_LOG.lock() {
        *slot = Some(Arc::clone(&guard.flush_handle));
    }

    Some(guard)
}

/// Flushes the global service file logger initialized by [`init_service_file_tracing`], if active.
pub fn flush_global_service_log() {
    let handle = GLOBAL_SERVICE_LOG
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(handle) = handle {
        handle.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "vdpi-logging-test-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    #[test]
    fn default_filters_and_constants_match_spec() {
        assert_eq!(DEFAULT_LOG_FILE_NAME, "vdpi.log");
        assert_eq!(MAX_LOG_FILE_BYTES, 2 * 1024 * 1024);
        assert_eq!(MAX_LOG_BACKUPS, 3);
        assert_eq!(CHANNEL_CAPACITY, 512);
        assert_eq!(BUF_WRITER_CAPACITY, 8192);
        assert_eq!(
            default_service_log_filter(false),
            "vdpi=info,vdpi_core=warn,vdpi_tun=warn"
        );
        assert_eq!(
            default_service_log_filter(true),
            "vdpi=debug,vdpi_core=debug,vdpi_tun=debug"
        );
        // Should be a safe no-op when uninitialized.
        flush_global_service_log();
    }

    #[test]
    fn size_rotation_and_backup_cap_work_end_to_end() {
        let dir = unique_test_dir("rotate");
        let max_bytes = 128;
        let max_backups = 3;
        let (mut writer, guard) = SizeRotatingWriter::open(&dir, max_bytes, max_backups)
            .expect("open rotating writer");

        // Write 20 lines of 40 bytes each (800 bytes total) -> triggers >5 rotations,
        // so backups 1..=3 must all exist while backup 4 must NOT exist.
        for i in 0..20u32 {
            let line = format!("line-{i:02}-0123456789abcdef0123456789abcde\n");
            assert_eq!(line.len(), 40);
            writer.write_all(line.as_bytes()).expect("write line");
        }
        guard.flush();

        let active = dir.join("vdpi.log");
        let b1 = dir.join("vdpi.log.1");
        let b2 = dir.join("vdpi.log.2");
        let b3 = dir.join("vdpi.log.3");
        let b4 = dir.join("vdpi.log.4");

        assert!(active.is_file(), "active vdpi.log must exist");
        assert!(b1.is_file(), "vdpi.log.1 must exist");
        assert!(b2.is_file(), "vdpi.log.2 must exist");
        assert!(b3.is_file(), "vdpi.log.3 must exist");
        assert!(!b4.exists(), "vdpi.log.4 must NOT exist (backup cap = 3)");

        let active_len = fs::metadata(&active).expect("active metadata").len();
        assert!(
            active_len > 0 && active_len <= max_bytes,
            "active log length {active_len} must be within 1..={max_bytes}"
        );
        let active_content = fs::read_to_string(&active).expect("read active log");
        assert!(
            active_content.contains("line-19-"),
            "most recent line must be in active vdpi.log, got: {active_content:?}"
        );

        drop(writer);
        drop(guard);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn guard_flush_and_drop_persist_buffered_records() {
        let dir = unique_test_dir("flush");
        {
            let (writer, guard) = SizeRotatingWriter::open(&dir, 64 * 1024, 3)
                .expect("open rotating writer");
            {
                let mut line_writer = writer.make_writer();
                line_writer
                    .write_all(b"first flushed line\n")
                    .expect("write first line");
            }
            guard.flush();

            let content_after_flush =
                fs::read_to_string(dir.join("vdpi.log")).expect("read after flush");
            assert!(content_after_flush.contains("first flushed line\n"));

            {
                let mut line_writer = writer.make_writer();
                line_writer
                    .write_all(b"second drop-flushed line\n")
                    .expect("write second line");
            }
            // Dropping `guard` must flush `second drop-flushed line`.
        }

        let content_after_drop =
            fs::read_to_string(dir.join("vdpi.log")).expect("read after drop");
        assert!(content_after_drop.contains("first flushed line\n"));
        assert!(content_after_drop.contains("second drop-flushed line\n"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn windows_sharing_violation_defers_rotation_without_panicking() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = unique_test_dir("sharing");
        let (mut writer, guard) = SizeRotatingWriter::open_with_options(
            &dir,
            DEFAULT_LOG_FILE_NAME,
            64,
            3,
            Duration::ZERO,
        )
        .expect("open rotating writer");

        writer
            .write_all(b"initial-40-byte-log-record-012345678901\n")
            .expect("write initial");
        guard.flush();

        // Hold vdpi.log open WITHOUT FILE_SHARE_DELETE so rename fails with ERROR_SHARING_VIOLATION.
        let lock_file = fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001 | 0x0000_0002)
            .open(dir.join("vdpi.log"))
            .expect("open lock handle");

        // Exceed 64 bytes while locked: must defer rotation instead of panicking and keep appending.
        writer
            .write_all(b"during-lock-40-byte-record-012345678901\n")
            .expect("write while locked");
        guard.flush();
        assert!(
            !dir.join("vdpi.log.1").exists(),
            "rotation should be deferred while vdpi.log is locked"
        );
        let during = fs::read_to_string(dir.join("vdpi.log")).expect("read during lock");
        assert!(during.contains("initial-40-byte-log-record"));
        assert!(during.contains("during-lock-40-byte-record"));

        // Release external lock; the next write should rotate cleanly.
        drop(lock_file);
        writer
            .write_all(b"after-unlock-record-0123456789012345678\n")
            .expect("write after unlock");
        guard.flush();

        assert!(
            dir.join("vdpi.log.1").is_file(),
            "vdpi.log.1 should be created once sharing violation clears"
        );
        let active = fs::read_to_string(dir.join("vdpi.log")).expect("read active after unlock");
        assert!(active.contains("after-unlock-record"));

        drop(writer);
        drop(guard);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_point_attr_helper_detects_reparse_bits() {
        assert!(win_fs::is_reparse_point_attrs(
            win_fs::FILE_ATTRIBUTE_REPARSE_POINT
        ));
        assert!(win_fs::is_reparse_point_attrs(
            win_fs::FILE_ATTRIBUTE_DIRECTORY | win_fs::FILE_ATTRIBUTE_REPARSE_POINT
        ));
        assert!(!win_fs::is_reparse_point_attrs(
            win_fs::FILE_ATTRIBUTE_DIRECTORY
        ));
        assert!(!win_fs::is_reparse_point_attrs(
            win_fs::INVALID_FILE_ATTRIBUTES
        ));
        assert!(win_fs::is_sharing_violation(
            &io::Error::from_raw_os_error(32)
        ));
        assert!(!win_fs::is_sharing_violation(
            &io::Error::from_raw_os_error(2)
        ));
    }
}
