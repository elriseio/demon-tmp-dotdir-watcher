#![allow(dead_code)]

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

pub struct Matcher {
    // HashSet<String> keeps the wire form (lowercase hex) for
    // trivial Debug output and future "show me what matched"
    // diagnostics. HashSet<[u8;32]> would drop the heap allocation
    // per IOC, but the IOC list is bounded and lookups dominate the
    // runtime cost; keep strings.
    hashes: HashSet<String>,
}

impl std::fmt::Debug for Matcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Matcher")
            .field("hash_count", &self.hashes.len())
            .finish()
    }
}

impl Matcher {
    /// Empty matcher with no IOCs. Used by the runtime when the
    /// IOC list file is missing (per ARCHITECTURE.md § Failure
    /// modes: "IOC list missing: ... skip scan; exit 0"); all
    /// candidates classify as Unknown.
    pub fn empty() -> Self {
        Self {
            hashes: HashSet::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Matcher> {
        let file =
            File::open(path).with_context(|| format!("open IOC list {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut hashes = HashSet::new();
        for (lineno, line_result) in reader.lines().enumerate() {
            let line = line_result
                .with_context(|| format!("read line {} of {}", lineno + 1, path.display()))?;
            let trimmed_end = line.trim_end();
            if trimmed_end.is_empty() || trimmed_end.starts_with('#') {
                continue;
            }
            let token = trimmed_end.split_whitespace().next().unwrap_or("");
            if token.is_empty() {
                continue;
            }
            if token.len() != 64 {
                continue;
            }
            if !is_valid_sha256_hex(token) {
                anyhow::bail!(
                    "invalid SHA-256 hex on line {} of {}: {:?}",
                    lineno + 1,
                    path.display(),
                    token
                );
            }
            hashes.insert(token.to_string());
        }
        Ok(Matcher { hashes })
    }

    pub fn contains(&self, sha256_hex: &str) -> bool {
        self.hashes.contains(sha256_hex)
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}

pub fn hash_file(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let file = File::open(path)
        .with_context(|| format!("open file to hash {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut buf = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut buf)
            .with_context(|| format!("read chunk from {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn is_valid_sha256_hex(s: &str) -> bool {
    if s.len() != 64 {
        return false;
    }
    s.bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempFile;
    use std::fs;

    const VALID_HASH: &str =
        "db338d19241c95d42c4da2888ade4d8bc6286e3b5689e3746771918c6c3b1b8c";

    #[test]
    fn is_valid_sha256_hex_truth_table() {
        assert!(is_valid_sha256_hex(VALID_HASH));
        assert!(!is_valid_sha256_hex(""));
        assert!(!is_valid_sha256_hex("deadbeef"));
        assert!(!is_valid_sha256_hex(
            "g338d19241c95d42c4da2888ade4d8bc6286e3b5689e3746771918c6c3b1b8c"
        ));
        assert!(!is_valid_sha256_hex(
            "DB338D19241C95D42C4DA2888ADE4D8BC6286E3B5689E3746771918C6C3B1B8C"
        ));
        assert!(!is_valid_sha256_hex(&format!("{}0", VALID_HASH)));
    }

    #[test]
    fn load_skips_comments_and_blank_lines() {
        let content = b"\
# Azazel trunk binary (from notes/2026-08-09-elrise-compromise-malware-analysis.md)


db338d19241c95d42c4da2888ade4d8bc6286e3b5689e3746771918c6c3b1b8c  trunk.sha256
";
        let f = TempFile::with_content("skip", content);
        let m = Matcher::load(f.path()).expect("load must succeed");
        assert_eq!(m.len(), 1);
        assert!(m.contains(VALID_HASH));
    }

    #[test]
    fn load_skips_legacy_md5_and_other_non_64_char_lines() {
        let content = b"\
b02ad43cfa407a01c376c7a904104b03  trunk.md5
sha256=db338d19241c95d42c4da2888ade4d8bc6286e3b5689e3746771918c6c3b1b8c
\
db338d19241c95d42c4da2888ade4d8bc6286e3b5689e3746771918c6c3b1b8c  trunk.sha256
";
        let f = TempFile::with_content("legacy", content);
        let m = Matcher::load(f.path()).expect("load must succeed");
        assert_eq!(m.len(), 1);
        assert!(m.contains(VALID_HASH));
    }

    #[test]
    fn load_rejects_malformed_line() {
        let upper: String = VALID_HASH.chars().map(|c| c.to_ascii_uppercase()).collect();
        let content = format!("{VALID_HASH}\n{upper}\n");
        let f = TempFile::with_content("malformed", content.as_bytes());
        let res = Matcher::load(f.path());
        assert!(res.is_err(), "expected Err on malformed line, got {res:?}");
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("invalid SHA-256 hex"));
    }

    #[test]
    fn contains_round_trip() {
        let content = format!(
            "# Azazel trunk\n\
             {VALID_HASH}  trunk.sha256\n"
        );
        let f = TempFile::with_content("roundtrip", content.as_bytes());
        let m = Matcher::load(f.path()).expect("load");
        assert!(m.contains(VALID_HASH));
        assert!(!m.contains(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn load_rejects_uppercase_hash() {
        let upper: String = VALID_HASH.chars().map(|c| c.to_ascii_uppercase()).collect();
        let content = format!("{upper}\n");
        let f = TempFile::with_content("uppercase", content.as_bytes());
        let res = Matcher::load(f.path());
        assert!(
            res.is_err(),
            "uppercase hex must be rejected per contract"
        );
    }

    #[test]
    fn load_ignores_filename_token() {
        let content = format!("{VALID_HASH}  trunk.sha256\n");
        let f = TempFile::with_content("filename_token", content.as_bytes());
        let m = Matcher::load(f.path()).expect("load");
        assert_eq!(m.len(), 1);
        assert!(m.contains(VALID_HASH));
    }

    #[test]
    fn load_handles_missing_file() {
        let bogus = std::env::temp_dir().join("demon_ioc_definitely_missing_12345");
        let _ = fs::remove_file(&bogus);
        let res = Matcher::load(&bogus);
        assert!(res.is_err(), "missing file must be Err");
    }

    #[test]
    fn hash_file_known_value() {
        let expected =
            "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119";
        let f = TempFile::with_content("hash_known", &[0u8, 0u8, 0u8, 0u8]);
        let got = hash_file(f.path()).expect("hash_file");
        assert_eq!(got, expected);
    }

    #[test]
    fn hash_file_is_lowercase_hex() {
        let f = TempFile::with_content("hash_case", b"hello world\n");
        let result = hash_file(f.path()).expect("hash");
        assert_eq!(result.len(), 64);
        assert!(result.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn hash_file_matches_sha2_crate_directly() {
        use sha2::{Digest, Sha256};
        let payload = b"the quick brown fox jumps over the lazy dog";
        let expected = format!("{:x}", Sha256::digest(payload));

        let f = TempFile::with_content("hash_indep", payload);
        let got = hash_file(f.path()).expect("hash");
        assert_eq!(got, expected);
    }
}
