use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{Read, BufReader};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct HashResult {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub is_suspicious: bool,
}

pub struct HashEngine {
    entropy_threshold: f64,
}

impl HashEngine {
    pub fn new(entropy_threshold: f64) -> Self {
        Self { entropy_threshold }
    }

    pub fn hash_file(&self, path: &Path) -> Result<HashResult, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        let mut total_size = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
            total_size += bytes_read as u64;
        }

        let hash = hex::encode(hasher.finalize());
        let entropy = self.calculate_file_entropy(path)?;

        Ok(HashResult {
            path: path.to_string_lossy().to_string(),
            sha256: hash,
            size: total_size,
            is_suspicious: entropy > self.entropy_threshold,
        })
    }

    pub fn calculate_file_entropy(&self, path: &Path) -> Result<f64, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut buffer = [0u8; 65536];
        let mut freq = [0u64; 256];
        let mut total = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            for &byte in &buffer[..bytes_read] {
                freq[byte as usize] += 1;
            }
            total += bytes_read as u64;
        }

        if total == 0 {
            return Ok(0.0);
        }

        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / total as f64;
                entropy -= p * p.log2();
            }
        }

        Ok(entropy)
    }

    pub fn hash_bytes(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    pub fn is_known_malicious(&self, hash: &str, blacklist: &[String]) -> bool {
        blacklist.iter().any(|h| h.eq_ignore_ascii_case(hash))
    }

    pub fn is_whitelisted(&self, hash: &str, whitelist: &[String]) -> bool {
        whitelist.iter().any(|h| h.eq_ignore_ascii_case(hash))
    }

    pub fn quick_hash(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hex::encode(hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_hash_bytes() {
        let engine = HashEngine::new(7.5);
        let hash = engine.hash_bytes(b"hello world");
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn test_known_malicious() {
        let engine = HashEngine::new(7.5);
        let blacklist = vec!["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()];
        assert!(engine.is_known_malicious("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &blacklist));
        assert!(!engine.is_known_malicious("abc123", &blacklist));
    }

    #[test]
    fn test_whitelist() {
        let engine = HashEngine::new(7.5);
        let whitelist = vec!["abc123".to_string()];
        assert!(engine.is_whitelisted("abc123", &whitelist));
        assert!(!engine.is_whitelisted("def456", &whitelist));
    }

    #[test]
    fn test_entropy_calculation() {
        let engine = HashEngine::new(7.5);
        let tmp = std::env::temp_dir().join("test_entropy.bin");
        let mut f = File::create(&tmp).unwrap();
        f.write_all(&[0u8; 1000]).unwrap();
        drop(f);

        let entropy = engine.calculate_file_entropy(&tmp).unwrap();
        assert_eq!(entropy, 0.0);
        std::fs::remove_file(&tmp).unwrap();
    }
}
