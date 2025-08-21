use crate::error::{KaijuError, Result};
use crate::protocol::{SessionKeys, DeviceInfo};
use ed25519_dalek::{SigningKey, Signature, Signer, VerifyingKey, Verifier};
use x25519_dalek::{StaticSecret, PublicKey};
use aes_gcm::{
    aead::{AeadInPlace, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;

pub struct CryptoContext {
    pub identity_key: SigningKey,
    pub ephemeral_secret: StaticSecret,
    pub session_keys: Option<SessionKeys>,
}

impl CryptoContext {
    pub fn new() -> Self {
        let mut rng = OsRng;
        let identity_key = SigningKey::generate(&mut rng);
        let ephemeral_secret = StaticSecret::random_from_rng(&mut rng);
        
        Self {
            identity_key,
            ephemeral_secret,
            session_keys: None,
        }
    }
    
    pub fn from_keys(identity_key: SigningKey, ephemeral_secret: StaticSecret) -> Self {
        Self {
            identity_key,
            ephemeral_secret,
            session_keys: None,
        }
    }
    
    pub fn get_device_info(&self, device_id: String) -> DeviceInfo {
        let identity_public = self.identity_key.verifying_key();
        let ephemeral_public = PublicKey::from(&self.ephemeral_secret);
        
        DeviceInfo {
            device_id,
            identity_key: identity_public.to_bytes(),
            ephemeral_key: ephemeral_public.to_bytes(),
        }
    }
    
    pub fn derive_session_keys(&mut self, peer_ephemeral_key: &[u8; 32]) -> Result<()> {
        let peer_public = PublicKey::from(*peer_ephemeral_key);
        let shared_secret = self.ephemeral_secret.diffie_hellman(&peer_public);
        
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        
        let mut encryption_key = [0u8; 32];
        let mut hmac_key = [0u8; 32];
        
        hkdf.expand(b"kaiju-encryption", &mut encryption_key)
            .map_err(|e| KaijuError::Crypto(format!("HKDF expansion failed: {}", e)))?;
        
        hkdf.expand(b"kaiju-hmac", &mut hmac_key)
            .map_err(|e| KaijuError::Crypto(format!("HKDF expansion failed: {}", e)))?;
        
        self.session_keys = Some(SessionKeys {
            encryption_key,
            hmac_key,
        });
        
        Ok(())
    }
    
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
        let keys = self.session_keys
            .as_ref()
            .ok_or_else(|| KaijuError::Crypto("Session keys not established".to_string()))?;
        
        let cipher = Aes256Gcm::new_from_slice(&keys.encryption_key)
            .map_err(|e| KaijuError::Crypto(format!("Cipher creation failed: {}", e)))?;
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, aad, &mut buffer)
            .map_err(|e| KaijuError::Crypto(format!("Encryption failed: {}", e)))?;
        
        buffer.extend_from_slice(&tag);
        
        Ok((buffer, nonce_bytes))
    }
    
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>> {
        let keys = self.session_keys
            .as_ref()
            .ok_or_else(|| KaijuError::Crypto("Session keys not established".to_string()))?;
        
        let cipher = Aes256Gcm::new_from_slice(&keys.encryption_key)
            .map_err(|e| KaijuError::Crypto(format!("Cipher creation failed: {}", e)))?;
        
        let nonce = Nonce::from_slice(nonce);
        
        if ciphertext.len() < 16 {
            return Err(KaijuError::DecryptionFailed);
        }
        
        let (data, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let mut buffer = data.to_vec();
        
        cipher
            .decrypt_in_place_detached(nonce, aad, &mut buffer, tag.into())
            .map_err(|_| KaijuError::DecryptionFailed)?;
        
        Ok(buffer)
    }
    
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.identity_key.sign(message);
        signature.to_bytes().to_vec()
    }
    
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8; 32],
    ) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| KaijuError::Crypto(format!("Invalid public key: {}", e)))?;
        
        let signature = Signature::from_slice(signature)
            .map_err(|e| KaijuError::Crypto(format!("Invalid signature: {}", e)))?;
        
        verifying_key
            .verify(message, &signature)
            .map_err(|_| KaijuError::SignatureVerificationFailed)?;
        
        Ok(())
    }
    
    pub fn get_hmac_key(&self) -> Result<&[u8; 32]> {
        self.session_keys
            .as_ref()
            .map(|keys| &keys.hmac_key)
            .ok_or_else(|| KaijuError::Crypto("Session keys not established".to_string()))
    }
}

pub fn generate_message_id() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        result |= byte_a ^ byte_b;
    }
    
    result == 0
}