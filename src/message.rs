use crate::error::{KaijuError, Result};
use crate::protocol::*;
use crate::crypto::{CryptoContext, generate_message_id};
use quinn::{Connection, RecvStream};
use tokio::io::AsyncWriteExt;
use chrono::Utc;
use lru::LruCache;
use std::sync::{Arc, Mutex};
use std::num::NonZeroUsize;
use uuid::Uuid;

#[derive(Clone)]
pub struct MessageHandler {
    crypto: Arc<Mutex<CryptoContext>>,
    replay_cache: Arc<Mutex<LruCache<Uuid, ()>>>,
    device_id: String,
}

impl MessageHandler {
    pub fn new(crypto: CryptoContext, device_id: String) -> Self {
        let cache_size = NonZeroUsize::new(10000).unwrap();
        Self {
            crypto: Arc::new(Mutex::new(crypto)),
            replay_cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
            device_id,
        }
    }
    
    pub async fn send_message(
        &self,
        connection: &Connection,
        message: MessageType,
    ) -> Result<()> {
        let serialized = bincode::serialize(&message)?;
        
        if serialized.len() > MAX_MESSAGE_SIZE {
            return Err(KaijuError::MessageTooLarge);
        }
        
        let (mut send, _) = connection.open_bi().await
            .map_err(|e| KaijuError::Transport(format!("Failed to open stream: {}", e)))?;
        
        // Send message length first
        send.write_u32(serialized.len() as u32).await?;
        send.write_all(&serialized).await?;
        send.finish()?;
        
        Ok(())
    }
    
    pub async fn receive_message(
        &self,
        mut recv: RecvStream,
    ) -> Result<MessageType> {
        // Read message length
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        if len > MAX_MESSAGE_SIZE {
            return Err(KaijuError::MessageTooLarge);
        }
        
        // Read message
        let mut buffer = vec![0u8; len];
        recv.read_exact(&mut buffer).await?;
        
        let message: MessageType = bincode::deserialize(&buffer)?;
        Ok(message)
    }
    
    pub fn create_encrypted_message(
        &self,
        content: String,
        recipient_id: Option<String>,
    ) -> Result<EncryptedEnvelope> {
        let plaintext = PlaintextMessage {
            content,
            message_type: PlaintextMessageType::Text,
        };
        
        let serialized = bincode::serialize(&plaintext)?;
        
        let crypto = self.crypto.lock().unwrap();
        
        // Check if session is established
        if crypto.session_keys.is_none() {
            return Err(KaijuError::Crypto("Session not established".to_string()));
        }
        
        // Create AAD
        let message_id = generate_message_id();
        let timestamp = Utc::now();
        let aad = format!("{}{}{}", 
            message_id, 
            timestamp.to_rfc3339(),
            self.device_id
        ).into_bytes();
        
        // Encrypt
        let (ciphertext, nonce) = crypto.encrypt(&serialized, &aad)?;
        
        // Sign the envelope
        let mut envelope_data = Vec::new();
        envelope_data.extend_from_slice(message_id.as_bytes());
        envelope_data.extend_from_slice(timestamp.to_rfc3339().as_bytes());
        envelope_data.extend_from_slice(self.device_id.as_bytes());
        if let Some(ref recipient) = recipient_id {
            envelope_data.extend_from_slice(recipient.as_bytes());
        }
        envelope_data.extend_from_slice(&nonce);
        envelope_data.extend_from_slice(&ciphertext);
        envelope_data.extend_from_slice(&aad);
        
        let signature = crypto.sign(&envelope_data);
        
        // Create envelope
        let mut envelope = EncryptedEnvelope {
            message_id,
            timestamp,
            sender_id: self.device_id.clone(),
            recipient_id,
            nonce,
            ciphertext,
            aad,
            signature,
            hmac: [0u8; 32],
        };
        
        // Compute HMAC
        let hmac_key = crypto.get_hmac_key()?;
        envelope.compute_hmac(hmac_key);
        
        Ok(envelope)
    }
    
    pub fn decrypt_and_verify_message(
        &self,
        envelope: &EncryptedEnvelope,
        sender_public_key: &[u8; 32],
    ) -> Result<PlaintextMessage> {
        // Check expiration
        if envelope.is_expired() {
            return Err(KaijuError::MessageExpired);
        }
        
        // Check replay
        {
            let mut cache = self.replay_cache.lock().unwrap();
            if cache.contains(&envelope.message_id) {
                return Err(KaijuError::ReplayDetected);
            }
            cache.put(envelope.message_id, ());
        }
        
        let crypto = self.crypto.lock().unwrap();
        
        // Verify HMAC
        let hmac_key = crypto.get_hmac_key()?;
        if !envelope.verify_hmac(hmac_key) {
            return Err(KaijuError::HmacVerificationFailed);
        }
        
        // Verify signature
        let mut envelope_data = Vec::new();
        envelope_data.extend_from_slice(envelope.message_id.as_bytes());
        envelope_data.extend_from_slice(envelope.timestamp.to_rfc3339().as_bytes());
        envelope_data.extend_from_slice(envelope.sender_id.as_bytes());
        if let Some(ref recipient) = envelope.recipient_id {
            envelope_data.extend_from_slice(recipient.as_bytes());
        }
        envelope_data.extend_from_slice(&envelope.nonce);
        envelope_data.extend_from_slice(&envelope.ciphertext);
        envelope_data.extend_from_slice(&envelope.aad);
        
        crypto.verify_signature(&envelope_data, &envelope.signature, sender_public_key)?;
        
        // Decrypt
        let plaintext = crypto.decrypt(&envelope.ciphertext, &envelope.nonce, &envelope.aad)?;
        
        let message: PlaintextMessage = bincode::deserialize(&plaintext)?;
        Ok(message)
    }
    
    pub fn get_device_info(&self) -> DeviceInfo {
        let crypto = self.crypto.lock().unwrap();
        crypto.get_device_info(self.device_id.clone())
    }
    
    pub fn establish_session(&self, peer_ephemeral_key: &[u8; 32]) -> Result<()> {
        let mut crypto = self.crypto.lock().unwrap();
        crypto.derive_session_keys(peer_ephemeral_key)
    }
    
    #[cfg(test)]
    pub fn crypto(&self) -> Arc<Mutex<CryptoContext>> {
        self.crypto.clone()
    }
}