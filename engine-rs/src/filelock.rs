// filelock.rs — advisory file locks.
// Linux: flock(2), exactly like the Go engine. Non-Linux (dev/test only):
// in-process per-path mutex, like Go's filelock_other.go.
#[cfg(not(target_os = "linux"))]
use std::sync::{Arc, Mutex, OnceLock};

pub struct FileLock {
    #[cfg(target_os = "linux")]
    file: std::fs::File,
    #[cfg(not(target_os = "linux"))]
    state: Arc<LocalLock>,
}

#[cfg(target_os = "linux")]
pub fn acquire_file_lock(path: &str) -> Result<FileLock, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o640)
        .open(path)
        .map_err(crate::util::io_err)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|e| e.to_string())?;
    Ok(FileLock { file })
}

#[cfg(target_os = "linux")]
impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

#[cfg(not(target_os = "linux"))]
struct LocalLock {
    locked: Mutex<bool>,
    cv: std::sync::Condvar,
}

#[cfg(not(target_os = "linux"))]
impl Drop for FileLock {
    fn drop(&mut self) {
        let mut g = self.state.locked.lock().unwrap_or_else(|e| e.into_inner());
        *g = false;
        drop(g);
        self.state.cv.notify_all();
    }
}

#[cfg(not(target_os = "linux"))]
pub fn acquire_file_lock(path: &str) -> Result<FileLock, String> {
    static LOCKS: OnceLock<Mutex<std::collections::HashMap<String, Arc<LocalLock>>>> =
        OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let state = {
        let mut m = locks.lock().unwrap_or_else(|e| e.into_inner());
        m.entry(path.to_string())
            .or_insert_with(|| {
                Arc::new(LocalLock {
                    locked: Mutex::new(false),
                    cv: std::sync::Condvar::new(),
                })
            })
            .clone()
    };
    {
        let mut g = state.locked.lock().unwrap_or_else(|e| e.into_inner());
        while *g {
            g = state.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        *g = true;
    }
    Ok(FileLock { state })
}

#[cfg(target_os = "linux")]
pub fn acquire_policy_lock(path: &str, timeout: std::time::Duration) -> Result<FileLock, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o640)
        .open(path)
        .map_err(|e| format!("无法创建策略锁 {}：{}", path, e))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(FileLock { file }),
            Err(rustix::io::Errno::WOULDBLOCK) => {}
            Err(e) => return Err(format!("无法锁定策略锁 {}：{}", path, e)),
        }
        if std::time::Instant::now() > deadline {
            return Err("另一个策略操作仍在运行（等待锁超时）。".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(not(target_os = "linux"))]
pub fn acquire_policy_lock(_path: &str, _timeout: std::time::Duration) -> Result<FileLock, String> {
    // policy-apply prints 仅支持 Linux before this is ever called; this stub
    // exists only so the engine builds off-Linux, like Go's policy_lock_other.go.
    Err("policy-apply is not supported on this platform".to_string())
}
