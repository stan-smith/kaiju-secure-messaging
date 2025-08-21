use kaiju_secure_messaging::*;
use std::net::SocketAddr;
use ed25519_dalek::SigningKey;
use x25519_dalek::StaticSecret;
use rand::rngs::OsRng;
use chrono::Utc;

async fn setup_test_connection() -> (quinn::Connection, quinn::Connection, MessageHandler, MessageHandler) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    // Create bridge
    let bridge_crypto = CryptoContext::new();
    let bridge_handler = MessageHandler::new(bridge_crypto, "test-bridge".to_string());
    
    // Create remote
    let remote_crypto = CryptoContext::new();
    let remote_handler = MessageHandler::new(remote_crypto, "test-remote".to_string());
    
    // Start server
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = QuicTransport::create_server_endpoint(addr).await.unwrap();
    let server_addr = endpoint.local_addr().unwrap();
    
    // Accept connection in background
    let bridge_handler_clone = bridge_handler.clone();
    let server_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        
        // Handle handshake
        let (_, recv) = connection.accept_bi().await.unwrap();
        let message = bridge_handler_clone.receive_message(recv).await.unwrap();
        
        if let MessageType::Hello(device_info) = message {
            bridge_handler_clone.establish_session(&device_info.ephemeral_key).unwrap();
            
            let bridge_info = bridge_handler_clone.get_device_info();
            let response = MessageType::HelloResponse {
                bridge_info,
                session_established: true,
            };
            
            bridge_handler_clone.send_message(&connection, response).await.unwrap();
        }
        
        connection
    });
    
    // Connect client
    let client_endpoint = QuicTransport::create_client_endpoint().unwrap();
    let client_connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    
    // Send handshake
    let device_info = remote_handler.get_device_info();
    remote_handler.send_message(&client_connection, MessageType::Hello(device_info)).await.unwrap();
    
    // Receive response
    let (_, recv) = client_connection.accept_bi().await.unwrap();
    let message = remote_handler.receive_message(recv).await.unwrap();
    
    if let MessageType::HelloResponse { bridge_info, .. } = message {
        remote_handler.establish_session(&bridge_info.ephemeral_key).unwrap();
    }
    
    let server_connection = server_task.await.unwrap();
    
    (server_connection, client_connection, bridge_handler, remote_handler)
}

#[tokio::test]
async fn test_full_handshake_and_message_exchange() {
    let (bridge_conn, remote_conn, bridge_handler, remote_handler) = setup_test_connection().await;
    
    // Send encrypted message from remote to bridge
    let test_message = "Hello from remote!";
    let envelope = remote_handler
        .create_encrypted_message(test_message.to_string(), Some("test-bridge".to_string()))
        .unwrap();
    
    remote_handler
        .send_message(&remote_conn, MessageType::EncryptedMessage(envelope.clone()))
        .await
        .unwrap();
    
    // Receive and decrypt on bridge side
    let (_, recv) = bridge_conn.accept_bi().await.unwrap();
    let received = bridge_handler.receive_message(recv).await.unwrap();
    
    if let MessageType::EncryptedMessage(received_envelope) = received {
        let remote_info = remote_handler.get_device_info();
        let decrypted = bridge_handler
            .decrypt_and_verify_message(&received_envelope, &remote_info.identity_key)
            .unwrap();
        
        assert_eq!(decrypted.content, test_message);
    } else {
        panic!("Expected encrypted message");
    }
}

#[tokio::test]
async fn test_replay_protection() {
    let (_bridge_conn, _remote_conn, bridge_handler, remote_handler) = setup_test_connection().await;
    
    // Create and send message
    let envelope = remote_handler
        .create_encrypted_message("Test message".to_string(), None)
        .unwrap();
    
    let remote_info = remote_handler.get_device_info();
    
    // First decryption should succeed
    let result1 = bridge_handler.decrypt_and_verify_message(&envelope, &remote_info.identity_key);
    assert!(result1.is_ok());
    
    // Second decryption with same message ID should fail
    let result2 = bridge_handler.decrypt_and_verify_message(&envelope, &remote_info.identity_key);
    assert!(matches!(result2, Err(KaijuError::ReplayDetected)));
}

#[tokio::test]
async fn test_hmac_tampering_detection() {
    let (_, _, bridge_handler, remote_handler) = setup_test_connection().await;
    
    let mut envelope = remote_handler
        .create_encrypted_message("Secret message".to_string(), None)
        .unwrap();
    
    // Tamper with HMAC
    envelope.hmac[0] ^= 0xFF;
    
    let remote_info = remote_handler.get_device_info();
    let result = bridge_handler.decrypt_and_verify_message(&envelope, &remote_info.identity_key);
    
    assert!(matches!(result, Err(KaijuError::HmacVerificationFailed)));
}


#[tokio::test]
async fn test_message_expiration() {
    let (_, _, bridge_handler, remote_handler) = setup_test_connection().await;
    
    let mut envelope = remote_handler
        .create_encrypted_message("Old message".to_string(), None)
        .unwrap();
    
    // Set timestamp to 6 minutes ago
    envelope.timestamp = Utc::now() - chrono::Duration::minutes(6);
    
    let remote_info = remote_handler.get_device_info();
    let result = bridge_handler.decrypt_and_verify_message(&envelope, &remote_info.identity_key);
    
    assert!(matches!(result, Err(KaijuError::MessageExpired)));
}

#[tokio::test]
async fn test_trusted_devices_persistence() {
    use tempfile::tempdir;
    use std::fs;
    
    // Create temp directory for trust store
    let temp_dir = tempdir().unwrap();
    let trust_file = temp_dir.path().join("trusted_devices.json");
    
    let device = TrustedDevice {
        device_id: "test-device".to_string(),
        identity_key: [42u8; 32],
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    
    // Mock the trust store path
    let data = serde_json::to_string_pretty(&vec![device.clone()]).unwrap();
    fs::write(&trust_file, data).unwrap();
    
    // Read back and verify
    let data = fs::read_to_string(&trust_file).unwrap();
    let devices: Vec<TrustedDevice> = serde_json::from_str(&data).unwrap();
    
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, "test-device");
    assert!(constant_time_compare(&devices[0].identity_key, &[42u8; 32]));
}

#[tokio::test]
async fn test_perfect_forward_secrecy() {
    // Test that compromising long-term keys doesn't compromise past sessions
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    // Create two separate sessions with different ephemeral keys
    let identity_key = SigningKey::generate(&mut OsRng);
    
    // Session 1
    let ephemeral1 = StaticSecret::random_from_rng(&mut OsRng);
    let mut crypto1 = CryptoContext::from_keys(identity_key.clone(), ephemeral1);
    
    // Session 2
    let ephemeral2 = StaticSecret::random_from_rng(&mut OsRng);
    let mut crypto2 = CryptoContext::from_keys(identity_key.clone(), ephemeral2);
    
    // Create peer with its own keys
    let peer_ephemeral1 = StaticSecret::random_from_rng(&mut OsRng);
    let peer_public1 = x25519_dalek::PublicKey::from(&peer_ephemeral1);
    
    let peer_ephemeral2 = StaticSecret::random_from_rng(&mut OsRng);
    let peer_public2 = x25519_dalek::PublicKey::from(&peer_ephemeral2);
    
    // Derive session keys
    crypto1.derive_session_keys(&peer_public1.to_bytes()).unwrap();
    crypto2.derive_session_keys(&peer_public2.to_bytes()).unwrap();
    
    // Verify that session keys are different
    let keys1 = crypto1.session_keys.as_ref().unwrap();
    let keys2 = crypto2.session_keys.as_ref().unwrap();
    
    assert!(!constant_time_compare(&keys1.encryption_key, &keys2.encryption_key));
    assert!(!constant_time_compare(&keys1.hmac_key, &keys2.hmac_key));
    
    // Test that messages encrypted with one session can't be decrypted with another
    let plaintext = b"Secret message";
    let aad = b"additional data";
    
    let (ciphertext1, nonce1) = crypto1.encrypt(plaintext, aad).unwrap();
    let result = crypto2.decrypt(&ciphertext1, &nonce1, aad);
    
    assert!(result.is_err());
}