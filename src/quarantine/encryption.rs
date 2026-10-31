use crate::error::{CoreError, Result};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::RngCore;

const MAGIC: &[u8; 4] = b"CQ01";
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| CoreError::Encryption(format!("Argon2 key derivation failed: {}", e)))?;
    Ok(key)
}

fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt_bytes(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let salt = generate_salt();
    let nonce_bytes = generate_nonce();
    let key = derive_key(password, &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CoreError::Encryption(format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| CoreError::Encryption(format!("Encryption failed: {}", e)))?;

    let mut output = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

pub fn decrypt_bytes(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let min_len = MAGIC.len() + SALT_LEN + NONCE_LEN + TAG_LEN;
    if data.len() < min_len {
        return Err(CoreError::Encryption(
            "Encrypted data too short".to_string(),
        ));
    }

    if &data[..MAGIC.len()] != MAGIC {
        return Err(CoreError::Encryption("Invalid magic bytes".to_string()));
    }

    let mut offset = MAGIC.len();

    let salt = &data[offset..offset + SALT_LEN];
    offset += SALT_LEN;

    let nonce_bytes = &data[offset..offset + NONCE_LEN];
    offset += NONCE_LEN;

    let ciphertext = &data[offset..];

    let key = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CoreError::Encryption(format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CoreError::Encryption(format!("Decryption failed: {}", e)))?;

    Ok(plaintext)
}

pub fn encrypt_file(
    input: &std::path::Path,
    output: &std::path::Path,
    password: &[u8],
) -> Result<()> {
    let data = std::fs::read(input).map_err(|e| {
        CoreError::Encryption(format!(
            "Failed to read input file {}: {}",
            input.display(),
            e
        ))
    })?;

    let encrypted = encrypt_bytes(&data, password)?;

    std::fs::write(output, &encrypted).map_err(|e| {
        CoreError::Encryption(format!(
            "Failed to write encrypted file {}: {}",
            output.display(),
            e
        ))
    })?;

    Ok(())
}

pub fn decrypt_file(
    input: &std::path::Path,
    output: &std::path::Path,
    password: &[u8],
) -> Result<()> {
    let data = std::fs::read(input).map_err(|e| {
        CoreError::Encryption(format!(
            "Failed to read encrypted file {}: {}",
            input.display(),
            e
        ))
    })?;

    let decrypted = decrypt_bytes(&data, password)?;

    std::fs::write(output, &decrypted).map_err(|e| {
        CoreError::Encryption(format!(
            "Failed to write decrypted file {}: {}",
            output.display(),
            e
        ))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = b"test_password_123";
        let plaintext = b"Hello, CoreEDR encryption test!";

        let encrypted = encrypt_bytes(plaintext, password).unwrap();
        assert_ne!(encrypted, plaintext);
        assert_eq!(&encrypted[..4], MAGIC);

        let decrypted = decrypt_bytes(&encrypted, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_password_fails() {
        let password = b"correct_password";
        let wrong_password = b"wrong_password";
        let plaintext = b"Secret data";

        let encrypted = encrypt_bytes(plaintext, password).unwrap();
        let result = decrypt_bytes(&encrypted, wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_encrypt_decrypt() {
        let password = b"file_test_pass";
        let plaintext = b"File encryption test content for CoreEDR";

        let input = NamedTempFile::new().unwrap();
        let encrypted_path = input.path().with_extension("enc");
        let decrypted_path = input.path().with_extension("dec");

        input.as_file().write_all(plaintext).unwrap();

        encrypt_file(input.path(), &encrypted_path, password).unwrap();
        decrypt_file(&encrypted_path, &decrypted_path, password).unwrap();

        let result = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(result, plaintext);

        std::fs::remove_file(&encrypted_path).ok();
        std::fs::remove_file(&decrypted_path).ok();
    }

    #[test]
    fn test_corrupted_data_fails() {
        let password = b"test_pass";
        let mut data = encrypt_bytes(b"test", password).unwrap();
        data[20] ^= 0xFF;
        assert!(decrypt_bytes(&data, password).is_err());
    }
}
