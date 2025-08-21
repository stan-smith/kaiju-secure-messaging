use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

pub const MAX_MESSAGE_SIZE: usize = 2_500_000; // 2.5MB
pub const MESSAGE_EXPIRATION_SECS: i64 = 300; // 5 minutes
pub const DEFAULT_PORT: u16 = 5555;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub identity_key: [u8; 32], // Ed25519 public key
    pub ephemeral_key: [u8; 32], // X25519 public key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Hello(DeviceInfo),
    HelloResponse {
        bridge_info: DeviceInfo,
        session_established: bool,
    },
    EncryptedMessage(EncryptedEnvelope),
    Disconnect,
    Ping,
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub message_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub sender_id: String,
    pub recipient_id: Option<String>, // None for broadcast
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>, // Additional authenticated data
    pub signature: Vec<u8>, // Ed25519 signature
    pub hmac: [u8; 32], // HMAC-SHA256
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaintextMessage {
    pub content: String,
    pub message_type: PlaintextMessageType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlaintextMessageType {
    Text,
    Command,
    SystemMessage,
}

#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub encryption_key: [u8; 32],
    pub hmac_key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub device_id: String,
    pub identity_key: [u8; 32],
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl EncryptedEnvelope {
    pub fn is_expired(&self) -> bool {
        let now = Utc::now();
        let age = now.signed_duration_since(self.timestamp);
        age.num_seconds() > MESSAGE_EXPIRATION_SECS
    }
    
    pub fn verify_hmac(&self, key: &[u8; 32]) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key size");
        
        // Include all fields except the HMAC itself
        mac.update(self.message_id.as_bytes());
        mac.update(self.timestamp.to_rfc3339().as_bytes());
        mac.update(self.sender_id.as_bytes());
        if let Some(ref recipient) = self.recipient_id {
            mac.update(recipient.as_bytes());
        }
        mac.update(&self.nonce);
        mac.update(&self.ciphertext);
        mac.update(&self.aad);
        mac.update(&self.signature);
        
        mac.verify_slice(&self.hmac).is_ok()
    }
    
    pub fn compute_hmac(&mut self, key: &[u8; 32]) {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key size");
        
        mac.update(self.message_id.as_bytes());
        mac.update(self.timestamp.to_rfc3339().as_bytes());
        mac.update(self.sender_id.as_bytes());
        if let Some(ref recipient) = self.recipient_id {
            mac.update(recipient.as_bytes());
        }
        mac.update(&self.nonce);
        mac.update(&self.ciphertext);
        mac.update(&self.aad);
        mac.update(&self.signature);
        
        let result = mac.finalize();
        self.hmac.copy_from_slice(&result.into_bytes());
    }
}