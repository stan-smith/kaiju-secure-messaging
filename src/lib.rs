pub mod error;
pub mod protocol;
pub mod crypto;
pub mod transport;
pub mod message;

pub use error::{KaijuError, Result};
pub use protocol::{
    DeviceInfo, MessageType, EncryptedEnvelope, PlaintextMessage, 
    PlaintextMessageType, SessionKeys, TrustedDevice,
    MAX_MESSAGE_SIZE, MESSAGE_EXPIRATION_SECS, DEFAULT_PORT
};
pub use crypto::{CryptoContext, constant_time_compare};
pub use transport::QuicTransport;
pub use message::MessageHandler;

use std::path::PathBuf;
use std::fs;
use dirs;
use ed25519_dalek::SigningKey;
use serde::{Serialize, Deserialize};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use colored::Colorize;

pub fn get_trust_store_path() -> PathBuf {
    let mut path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("kaiju-secure-messaging");
    path.push("trusted_devices.json");
    path
}

pub fn load_trusted_devices() -> Vec<TrustedDevice> {
    let path = get_trust_store_path();
    if !path.exists() {
        return Vec::new();
    }
    
    let data = fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&data).unwrap_or_default()
}

pub fn save_trusted_devices(devices: &[TrustedDevice]) -> Result<()> {
    let path = get_trust_store_path();
    
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    let data = serde_json::to_string_pretty(devices)
        .map_err(|e| KaijuError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    
    fs::write(&path, data)?;
    Ok(())
}

pub fn is_device_trusted(device_id: &str, identity_key: &[u8; 32]) -> bool {
    let devices = load_trusted_devices();
    devices.iter().any(|d| {
        d.device_id == device_id && 
        crypto::constant_time_compare(&d.identity_key, identity_key)
    })
}

pub fn add_trusted_device(device: TrustedDevice) -> Result<()> {
    let mut devices = load_trusted_devices();
    
    // Remove old entry if exists
    devices.retain(|d| d.device_id != device.device_id);
    
    // Add new entry
    devices.push(device);
    
    save_trusted_devices(&devices)
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyFile {
    pub encrypted_key: Vec<u8>,
    pub nonce: [u8; 12],
    pub salt: String,
    pub has_passphrase: bool,
}
pub fn get_device_key_path(device_id: &str) -> PathBuf {
    let mut path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("kaiju-secure-messaging");
    path.push("device_keys");
    path.push(format!("{}.key", device_id));
    path
}

pub fn save_device_identity(device_id: &str, signing_key: &SigningKey, passphrase: Option<&str>) -> Result<()> {
    use argon2::Argon2;
    use argon2::password_hash::{SaltString, rand_core::OsRng as ArgonOsRng};
    
    let path = get_device_key_path(device_id);
    
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    let key_bytes = signing_key.to_bytes();
    
    let key_file = if let Some(pass) = passphrase {
        let salt = SaltString::generate(&mut ArgonOsRng);
        let argon2 = Argon2::default();
        
        let mut derived_key = [0u8; 32];
        argon2.hash_password_into(pass.as_bytes(), salt.as_str().as_bytes(), &mut derived_key)
            .map_err(|e| KaijuError::Crypto(format!("Key derivation failed: {}", e)))?;
        
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
        let mut nonce = [0u8; 12];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        
        let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), key_bytes.as_ref())
            .map_err(|e| KaijuError::Crypto(format!("Key encryption failed: {}", e)))?;
        
        EncryptedKeyFile {
            encrypted_key: encrypted,
            nonce,
            salt: salt.to_string(),
            has_passphrase: true,
        }
    } else {
        EncryptedKeyFile {
            encrypted_key: key_bytes.to_vec(),
            nonce: [0u8; 12],
            salt: String::new(),
            has_passphrase: false,
        }
    };
    
    let json = serde_json::to_string_pretty(&key_file)
        .map_err(|e| KaijuError::Crypto(format!("Serialization failed: {}", e)))?;
    
    fs::write(&path, json)?;
    
    if passphrase.is_some() {
        println!("{} {}", "Saved passphrase-protected identity for device".green(), device_id.yellow());
    } else {
        println!("{} {}", "Saved identity key for device".green(), device_id.yellow());
    }
    Ok(())
}

pub fn load_device_identity(device_id: &str, passphrase: Option<&str>) -> Result<SigningKey> {
    use argon2::Argon2;
    
    let path = get_device_key_path(device_id);
    
    if !path.exists() {
        return Err(KaijuError::Crypto(format!("No saved identity for device '{}'", device_id)));
    }
    
    let json = fs::read_to_string(&path)?;
    let key_file: EncryptedKeyFile = serde_json::from_str(&json)
        .map_err(|e| KaijuError::Crypto(format!("Invalid key file: {}", e)))?;
    
    let key_bytes = if key_file.has_passphrase {
        let pass = passphrase.ok_or_else(|| 
            KaijuError::Crypto("This identity requires a passphrase".to_string()))?;
        
        let argon2 = Argon2::default();
        let mut derived_key = [0u8; 32];
        argon2.hash_password_into(pass.as_bytes(), key_file.salt.as_bytes(), &mut derived_key)
            .map_err(|e| KaijuError::Crypto(format!("Key derivation failed: {}", e)))?;
        
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
        cipher.decrypt(Nonce::from_slice(&key_file.nonce), key_file.encrypted_key.as_ref())
            .map_err(|_| KaijuError::Crypto("Invalid passphrase".to_string()))?
    } else {
        if passphrase.is_some() {
            return Err(KaijuError::Crypto("This identity does not use a passphrase".to_string()));
        }
        key_file.encrypted_key
    };
    
    if key_bytes.len() != 32 {
        return Err(KaijuError::Crypto("Invalid key size".to_string()));
    }
    
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    
    Ok(SigningKey::from_bytes(&key_array))
}

pub fn check_device_has_passphrase(device_id: &str) -> Option<bool> {
    let path = get_device_key_path(device_id);
    
    if !path.exists() {
        return None;
    }
    
    if let Ok(json) = fs::read_to_string(&path) {
        if let Ok(key_file) = serde_json::from_str::<EncryptedKeyFile>(&json) {
            return Some(key_file.has_passphrase);
        }
    }
    
    None
}

