use crate::error::{CoreError, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn verify_signature_hmac(data: &[u8], signature: &[u8], secret_key: &[u8]) -> Result<bool> {
    let mut mac = HmacSha256::new_from_slice(secret_key)
        .map_err(|e| CoreError::CryptoError(format!("Failed to create HMAC: {}", e)))?;

    mac.update(data);

    if signature.len() != 32 {
        return Ok(false);
    }

    Ok(mac.verify_slice(signature).is_ok())
}

pub fn compute_hmac(data: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(secret_key)
        .map_err(|e| CoreError::CryptoError(format!("Failed to create HMAC: {}", e)))?;

    mac.update(data);

    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(feature = "ed25519")]
pub fn verify_signature_ed25519(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    use ed25519_dalek::{Verifier, VerifyingKey};

    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| CoreError::CryptoError("Invalid public key length".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| CoreError::CryptoError(format!("Invalid public key: {}", e)))?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| CoreError::CryptoError("Invalid signature length".to_string()))?;

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    Ok(verifying_key.verify(data, &signature).is_ok())
}
