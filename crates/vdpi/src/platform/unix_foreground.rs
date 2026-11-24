use super::SystemProxySession;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

pub const GUARD_ARG: &str = "--internal-foreground-proxy-guard";

extern "C" {
    fn setsid() -> i32;
    fn flock(fd: i32, operation: i32) -> i32;
}

#[derive(Serialize, Deserialize)]
struct Request {
    addr: SocketAddr,
    socks_port: Option<u16>,
    bypass: Vec<String>,
}

pub struct ForegroundProxy {
    child: Child,
    pub summary: String,
}

impl ForegroundProxy {
    pub fn activate(addr: SocketAddr, socks_port: Option<u16>, bypass: &[String]) -> Result<Self> {
        let mut cmd = Command::new(std::env::current_exe()?);
        cmd.arg(GUARD_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // Detach before exec so a terminal hangup only reaches the proxy, not its lease keeper.
        unsafe {
            cmd.pre_exec(|| {
                if setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut guard = Self {
            child: cmd.spawn().context("starting proxy cleanup process")?,
            summary: String::new(),
        };
        let pipe = guard.child.stdin.as_mut().expect("guard stdin was piped");
        serde_json::to_writer(
            &mut *pipe,
            &Request {
                addr,
                socks_port,
                bypass: bypass.to_vec(),
            },
        )?;
        pipe.write_all(b"\n")?;
        let mut response = String::new();
        BufReader::new(guard.child.stdout.take().expect("guard stdout was piped"))
            .read_line(&mut response)?;
        let Some(summary) = response.trim_end().strip_prefix("ready: ") else {
            bail!("system proxy could not start safely: {}", response.trim());
        };
        guard.summary = summary.to_owned();
        Ok(guard)
    }
}

impl Drop for ForegroundProxy {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        match self.child.wait() {
            Ok(status) if status.success() => {}
            result => tracing::warn!(?result, "foreground proxy cleanup failed"),
        }
    }
}

pub fn run_guard() -> Result<()> {
    let result = guard_inner();
    if let Err(e) = &result {
        let _ = writeln!(
            io::stdout(),
            "{}",
            format!("{e:#}").replace(['\r', '\n'], " ")
        );
    }
    result
}

fn guard_inner() -> Result<()> {
    let mut input = io::stdin().lock();
    let mut request = String::new();
    input.read_line(&mut request)?;
    let req: Request = serde_json::from_str(&request)?;
    let root = crate::service::vdpi_root_dir()?;
    fs::create_dir_all(&root)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join("proxy-lease.lock"))?;
    // LOCK_EX | LOCK_NB. The open file holds the lock until cleanup completes.
    if unsafe { flock(lock.as_raw_fd(), 2 | 4) } == -1 {
        return Err(io::Error::last_os_error())
            .context("acquiring the desktop proxy lease (another vdpi may already be running)");
    }

    let session = SystemProxySession::activate(
        req.addr.ip(),
        req.addr.port(),
        req.socks_port,
        req.socks_port.is_some(),
        false,
        &req.bypass,
    )?;
    let result = (|| -> Result<()> {
        let mut output = io::stdout().lock();
        writeln!(
            output,
            "ready: {}",
            session.summary().replace(['\r', '\n'], " ")
        )?;
        output.flush()?;
        drop(output);
        let _ = input.fill_buf();
        Ok(())
    })();
    session.deactivate_foreground();
    result
}
