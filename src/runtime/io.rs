use std::fmt::Debug;

use async_trait::async_trait;
use tokio::{
    fs::OpenOptions,
    io::{AsyncRead, AsyncWrite},
    process::Command,
};

/// Async IO trait for setting up container process stdio.
/// Inlined from the runc crate to remove the runc binary dependency.
#[async_trait]
pub trait Io: Debug + Send + Sync {
    fn stdin(&self) -> Option<Box<dyn AsyncWrite + Send + Sync + Unpin>> {
        None
    }

    fn stdout(&self) -> Option<Box<dyn AsyncRead + Send + Sync + Unpin>> {
        None
    }

    fn stderr(&self) -> Option<Box<dyn AsyncRead + Send + Sync + Unpin>> {
        None
    }

    /// Set IO for passed command.
    async fn set(&self, cmd: &mut Command) -> std::io::Result<()>;

    /// Close write side after process start.
    async fn close_after_start(&self);
}

/// Redirects all output to /dev/null.
#[derive(Debug)]
pub struct NullIo {
    dev_null: std::sync::Mutex<Option<std::fs::File>>,
}

impl NullIo {
    pub fn new() -> std::io::Result<Self> {
        let f = std::fs::OpenOptions::new().read(true).open("/dev/null")?;
        let dev_null = std::sync::Mutex::new(Some(f));
        Ok(Self { dev_null })
    }
}

#[async_trait]
impl Io for NullIo {
    async fn set(&self, cmd: &mut Command) -> std::io::Result<()> {
        if let Some(null) = self.dev_null.lock().unwrap().as_ref() {
            cmd.stdout(null.try_clone()?);
            cmd.stderr(null.try_clone()?);
        }
        Ok(())
    }

    async fn close_after_start(&self) {
        let mut m = self.dev_null.lock().unwrap();
        let _ = m.take();
    }
}

/// Uses named pipes (FIFOs) for container stdio.
#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub struct FIFO {
    pub stdin: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

#[async_trait]
impl Io for FIFO {
    async fn set(&self, cmd: &mut Command) -> std::io::Result<()> {
        if let Some(path) = self.stdin.as_ref() {
            let stdin = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path)
                .await?;
            cmd.stdin(stdin.into_std().await);
        }

        if let Some(path) = self.stdout.as_ref() {
            let stdout = OpenOptions::new().write(true).open(path).await?;
            cmd.stdout(stdout.into_std().await);
        }

        if let Some(path) = self.stderr.as_ref() {
            let stderr = OpenOptions::new().write(true).open(path).await?;
            cmd.stderr(stderr.into_std().await);
        }

        Ok(())
    }

    async fn close_after_start(&self) {}
}
