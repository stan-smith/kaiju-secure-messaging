use kaiju_secure_messaging::*;
use std::io::{self, Write};
use std::net::SocketAddr;
use tokio::io::AsyncBufReadExt;
use tracing::{error, info};
use x25519_dalek::StaticSecret;
use rand::rngs::OsRng;
use colored::Colorize;
use rpassword::prompt_password;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();
    
    println!("{}", "=== Kaiju Secure Messaging Remote ===".cyan().bold());
    
    // Get device ID
    print!("{} ", "Enter your device ID:".white());
    io::stdout().flush()?;
    let mut device_id = String::new();
    io::stdin().read_line(&mut device_id)?;
    let device_id = device_id.trim().to_string();
    
    if device_id.is_empty() {
        println!("{}", "Device ID cannot be empty".red());
        return Ok(());
    }
    
    // Get bridge address
    print!("{} ", "Enter bridge address (default: 127.0.0.1:5555):".white());
    io::stdout().flush()?;
    let mut addr_str = String::new();
    io::stdin().read_line(&mut addr_str)?;
    let addr_str = addr_str.trim();
    let addr_str = if addr_str.is_empty() {
        "127.0.0.1:5555"
    } else {
        addr_str
    };
    
    let addr: SocketAddr = addr_str.parse()
        .map_err(|_| anyhow::anyhow!("Invalid address format"))?;
    
    println!("{} {}...", "Connecting to bridge at".white(), addr.to_string().yellow());
    
    // Load or create persistent identity for this device
    let identity_key = match check_device_has_passphrase(&device_id) {
        Some(true) => {
            // Device exists with passphrase
            let prompt = format!("{} {}: ", "Enter passphrase for device".white(), device_id.yellow());
            let passphrase = prompt_password(prompt)?;
            
            match load_device_identity(&device_id, Some(&passphrase)) {
                Ok(key) => {
                    println!("{} {}", "Unlocked identity for device".green(), device_id.yellow());
                    key
                }
                Err(e) => {
                    println!("{} {}", "Error:".red(), e);
                    return Ok(());
                }
            }
        }
        Some(false) => {
            // Device exists without passphrase
            match load_device_identity(&device_id, None) {
                Ok(key) => {
                    println!("{} {}", "Loaded identity for device".green(), device_id.yellow());
                    key
                }
                Err(e) => {
                    println!("{} {}", "Failed to load device identity:".red(), e);
                    return Ok(());
                }
            }
        }
        None => {
            // New device - ask if they want passphrase protection
            println!("\n{} {}", "Creating new identity for device".yellow(), device_id.cyan());
            print!("{} ", "Protect this identity with a passphrase? (yes/no):".white());
            io::stdout().flush()?;
            
            let mut response = String::new();
            io::stdin().read_line(&mut response)?;
            
            let passphrase = if response.trim().to_lowercase() == "yes" || response.trim().to_lowercase() == "y" {
                let pass1 = prompt_password(format!("{} ", "Enter passphrase:".white()))?;
                let pass2 = prompt_password(format!("{} ", "Confirm passphrase:".white()))?;
                
                if pass1 != pass2 {
                    println!("{}", "Passphrases do not match".red());
                    return Ok(());
                }
                
                if pass1.is_empty() {
                    println!("{}", "Passphrase cannot be empty".red());
                    return Ok(());
                }
                
                Some(pass1)
            } else {
                None
            };
            
            // Generate new identity
            use ed25519_dalek::SigningKey;
            use rand::rngs::OsRng as EdOsRng;
            let signing_key = SigningKey::generate(&mut EdOsRng);
            
            // Save with or without passphrase
            if let Err(e) = save_device_identity(&device_id, &signing_key, passphrase.as_deref()) {
                println!("{} {}", "Failed to save device identity:".red(), e);
                return Ok(());
            }
            
            signing_key
        }
    };
    
    // Generate new ephemeral key for this session (for PFS)
    let ephemeral_secret = StaticSecret::random_from_rng(&mut OsRng);
    let crypto = CryptoContext::from_keys(identity_key, ephemeral_secret);
    
    let message_handler = MessageHandler::new(crypto, device_id.clone());
    
    // Connect to bridge
    let endpoint = QuicTransport::create_client_endpoint()?;
    let connection = endpoint.connect(addr, "localhost")
        .map_err(|e| anyhow::anyhow!("Failed to connect: {}", e))?
        .await?;
    
    println!("{}", "Connected to bridge!".green());
    
    // Perform handshake
    let bridge_key = match perform_handshake(&connection, &message_handler).await {
        Ok(key) => key,
        Err(e) => {
            if matches!(e, KaijuError::Timeout) {
                println!("{}", "Connection rejected by bridge (device not trusted)".red());
            } else {
                error!("Handshake failed: {}", e);
            }
            return Ok(());
        }
    };
    
    println!("{}", "Secure session established".green().bold());
    println!("\n{}", "Type messages to send to the bridge (or 'quit'/'exit' to disconnect):".white());
    
    // Spawn message receiver
    let connection_clone = connection.clone();
    let message_handler_clone = message_handler.clone();
    tokio::spawn(async move {
        loop {
            match connection_clone.accept_bi().await {
                Ok((_, recv)) => {
                    if let Err(e) = handle_incoming_message(recv, &message_handler_clone, &bridge_key).await {
                        error!("Failed to handle message: {}", e);
                    }
                }
                Err(e) => {
                    info!("Connection closed: {}", e);
                    break;
                }
            }
        }
    });
    
    // Handle user input
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();
    
    loop {
        print!("{} ", ">".blue().bold());
        io::stdout().flush()?;
        
        if let Ok(Some(line)) = lines.next_line().await {
            let trimmed = line.trim();
            
            if trimmed == "quit" || trimmed == "exit" {
                println!("{}", "Disconnecting...".yellow());
                let _ = message_handler.send_message(&connection, MessageType::Disconnect).await;
                break;
            }
            
            if !trimmed.is_empty() {
                match send_encrypted_message(&message_handler, &connection, trimmed.to_string()).await {
                    Ok(_) => {},
                    Err(e) => println!("{} {}", "Failed to send message:".red(), e),
                }
            }
        }
    }
    
    Ok(())
}

async fn perform_handshake(
    connection: &quinn::Connection,
    message_handler: &MessageHandler,
) -> Result<[u8; 32]> {
    use tokio::time::{timeout, Duration};
    
    // Send Hello
    let device_info = message_handler.get_device_info();
    message_handler.send_message(connection, MessageType::Hello(device_info)).await?;
    
    // Wait for response with timeout (30 seconds for approval)
    let response_future = async {
        let (_, recv) = connection.accept_bi().await
            .map_err(|e| KaijuError::Transport(format!("Failed to accept stream: {}", e)))?;
        message_handler.receive_message(recv).await
    };
    
    let message = match timeout(Duration::from_secs(30), response_future).await {
        Ok(Ok(msg)) => msg,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(KaijuError::Timeout),
    };
    
    if let MessageType::HelloResponse { bridge_info, session_established } = message {
        if session_established {
            // Establish session with bridge's ephemeral key
            message_handler.establish_session(&bridge_info.ephemeral_key)?;
            Ok(bridge_info.identity_key)
        } else {
            Err(KaijuError::AuthenticationFailed)
        }
    } else {
        Err(KaijuError::InvalidMessage)
    }
}

async fn handle_incoming_message(
    recv: quinn::RecvStream,
    message_handler: &MessageHandler,
    bridge_key: &[u8; 32],
) -> Result<()> {
    let message = message_handler.receive_message(recv).await?;
    
    match message {
        MessageType::EncryptedMessage(envelope) => {
            let plaintext = message_handler
                .decrypt_and_verify_message(&envelope, bridge_key)?;
            
            println!("\n{}: {}", "[Bridge]".cyan(), plaintext.content.white());
            print!("{} ", ">".blue().bold());
            io::stdout().flush().unwrap();
        }
        MessageType::Ping => {
            // Auto-respond with Pong (handled internally)
        }
        _ => {}
    }
    
    Ok(())
}

async fn send_encrypted_message(
    handler: &MessageHandler,
    connection: &quinn::Connection,
    content: String,
) -> Result<()> {
    let envelope = handler.create_encrypted_message(content, Some("bridge".to_string()))?;
    handler.send_message(connection, MessageType::EncryptedMessage(envelope)).await
}