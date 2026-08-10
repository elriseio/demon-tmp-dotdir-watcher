#![cfg(test)]

// DE-003 fixture extraction: shared TempDir / TempFile RAII types
// for tests in ioc.rs and subsystem.rs. Both modules previously
// copy-pasted the same ~30-line fixture; this file is the single
// source of truth and is gated to `#[cfg(test)]` so it never ships
// in the runtime binary.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "demon_{}_{}_{}_{}",
            label,
            pid,
            nanos,
            std::any::type_name::<Self>()
        ));
        fs::create_dir_all(&dir).expect("create tempdir");
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub struct TempFile(PathBuf);

impl TempFile {
    pub fn with_content(label: &str, content: &[u8]) -> Self {
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "demon_{}_{}_{}_{}",
            label,
            pid,
            nanos,
            std::any::type_name::<Self>()
        ));
        fs::write(&path, content).expect("write temp file");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    #[allow(dead_code)]
    pub fn open(&self) -> File {
        File::open(&self.0).expect("open temp file")
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}