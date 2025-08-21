use kaiju_secure_messaging::*;
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::io::AsyncBufReadExt;
use tracing::{error, info, warn};
use chrono::Utc;
use x25519_dalek::StaticSecret;
use rand::rngs::OsRng;
use colored::Colorize;
use if_addrs::get_if_addrs;

struct ConnectedRemote {
    connection: quinn::Connection,
    message_handler: MessageHandler,
}

struct BridgeState {
    remotes: Arc<RwLock<HashMap<String, ConnectedRemote>>>,
    bridge_id: String,
    pending_approval: Arc<RwLock<Option<PendingApproval>>>,
}

struct PendingApproval {
    response_tx: tokio::sync::oneshot::Sender<bool>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();
    
    println!("{}", "=== Kaiju Secure Messaging Bridge ===".cyan().bold());
    
    // Get and display network interfaces
    let interfaces = get_network_interfaces()?;
    
    if interfaces.is_empty() {
        println!("{}", "No network interfaces found!".red());
        return Ok(());
    }
    
    println!("\n{}", "Available network interfaces:".white().bold());
    for (i, (name, ip)) in interfaces.iter().enumerate() {
        println!("  {}. {} - {}", 
            (i + 1).to_string().cyan(),
            name.yellow(),
            ip.to_string().green()
        );
    }
    
    // Let user select interface
    print!("\n{} ", "Select interface number (or press Enter for localhost):".white());
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    
    let selected_ip = if input.is_empty() {
        IpAddr::from([127, 0, 0, 1])
    } else {
        match input.parse::<usize>() {
            Ok(n) if n > 0 && n <= interfaces.len() => {
                interfaces[n - 1].1
            }
            _ => {
                println!("{}", "Invalid selection, using localhost".yellow());
                IpAddr::from([127, 0, 0, 1])
            }
        }
    };
    
    // Ask for port
    print!("{} ", "Enter port (default: 5555):".white());
    io::stdout().flush()?;
    
    let mut port_input = String::new();
    io::stdin().read_line(&mut port_input)?;
    let port: u16 = port_input.trim().parse().unwrap_or(5555);
    
    let addr = SocketAddr::new(selected_ip, port);
    
    println!("\n{} {}...", "Starting bridge on".white(), addr.to_string().yellow());
    
    let bridge_id = "bridge".to_string();
    
    let state = Arc::new(BridgeState {
        remotes: Arc::new(RwLock::new(HashMap::new())),
        bridge_id,
        pending_approval: Arc::new(RwLock::new(None)),
    });
    
    // Start QUIC server
    let endpoint = QuicTransport::create_server_endpoint(addr).await?;
    
    println!("{} {}", "Bridge listening on".green(), addr.to_string().yellow());
    println!("\n{}", "Commands:".white().bold());
    println!("  {} - Show connected devices", "list".cyan());
    println!("  {} - Send message to device", "send <device_id> <msg>".cyan());
    println!("  {} - Send to all devices", "broadcast <msg>".cyan());
    println!("  {} - Exit bridge", "quit/exit".cyan());
    println!("");
    
    // Spawn connection handler
    let state_clone = state.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let state = state_clone.clone();
            tokio::spawn(handle_connection(incoming, state));
        }
    });
    
    // Handle CLI input
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();
    
    loop {
        {
            let pending = state.pending_approval.read().await;
            if pending.is_some() {
                drop(pending);
            } else {
                print!("{} ", ">".blue().bold());
                io::stdout().flush()?;
            }
        }
        
        if let Ok(Some(line)) = lines.next_line().await {
            let trimmed = line.trim();
            
            // Check if this is an approval response
            {
                let mut pending = state.pending_approval.write().await;
                if let Some(approval) = pending.take() {
                    let approved = trimmed == "yes" || trimmed == "y";
                    let _ = approval.response_tx.send(approved);
                    continue;
                }
            }
            
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            
            match parts[0] {
                "quit" | "exit" => {
                    println!("{}", "Shutting down bridge...".yellow());
                    break;
                }
                "list" => {
                    let remotes = state.remotes.read().await;
                    if remotes.is_empty() {
                        println!("{}", "No connected devices".white().dimmed());
                    } else {
                        println!("{}", "Connected devices:".white().bold());
                        for (id, _) in remotes.iter() {
                            println!("  - {}", id.green());
                        }
                    }
                }
                "send" => {
                    if parts.len() < 3 {
                        println!("Usage: send <device_id> <message>");
                        continue;
                    }
                    let device_id = parts[1];
                    let message = parts[2..].join(" ");
                    
                    let remotes = state.remotes.read().await;
                    if let Some(remote) = remotes.get(device_id) {
                        match send_encrypted_message(
                            &remote.message_handler,
                            &remote.connection,
                            message,
                            Some(device_id.to_string()),
                        ).await {
                            Ok(_) => println!("{} {}", "Message sent to".green(), device_id.yellow()),
                            Err(e) => println!("{} {}", "Failed to send message:".red(), e),
                        }
                    } else {
                        println!("{} {}", "Device not found:".red(), device_id);
                    }
                }
                "broadcast" => {
                    if parts.len() < 2 {
                        println!("Usage: broadcast <message>");
                        continue;
                    }
                    let message = parts[1..].join(" ");
                    
                    let remotes = state.remotes.read().await;
                    for (id, remote) in remotes.iter() {
                        match send_encrypted_message(
                            &remote.message_handler,
                            &remote.connection,
                            message.clone(),
                            None,
                        ).await {
                            Ok(_) => println!("{} {}", "Broadcast sent to".green(), id.yellow()),
                            Err(e) => println!("{} {} {}", "Failed to broadcast to".red(), id, e),
                        }
                    }
                }
                _ => {
                    println!("{} {}", "Unknown command:".red(), parts[0]);
                }
            }
        }
    }
    
    Ok(())
}

async fn handle_connection(
    incoming: quinn::Incoming,
    state: Arc<BridgeState>,
) {
    let connection = match incoming.await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Failed to accept connection: {}", e);
            return;
        }
    };
    
    let remote_addr = connection.remote_address();
    info!("New connection from {}", remote_addr);
    
    // Load bridge's persistent identity (same for all connections)
    // Bridge doesn't use passphrase for simplicity (runs as a service)
    let identity_key = match load_device_identity(&state.bridge_id, None) {
        Ok(key) => key,
        Err(_) => {
            // Generate new bridge identity
            use ed25519_dalek::SigningKey;
            use rand::rngs::OsRng as EdOsRng;
            let key = SigningKey::generate(&mut EdOsRng);
            
            if let Err(e) = save_device_identity(&state.bridge_id, &key, None) {
                error!("Failed to save bridge identity: {}", e);
                return;
            }
            info!("Generated new bridge identity");
            key
        }
    };
    
    // Generate new ephemeral key for this connection (for PFS)
    let ephemeral_secret = StaticSecret::random_from_rng(&mut OsRng);
    let crypto = CryptoContext::from_keys(identity_key, ephemeral_secret);
    let message_handler = MessageHandler::new(crypto, state.bridge_id.clone());
    
    // Handle initial handshake WITHOUT establishing session yet
    let (device_info, identity_key) = match receive_hello(&connection, &message_handler).await {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to receive hello from {}: {}", remote_addr, e);
            return;
        }
    };
    
    // Check trust and prompt for approval BEFORE establishing session
    if !is_device_trusted(&device_info.device_id, &identity_key) {
        println!("\n{}", "New device connection request:".yellow().bold());
        println!("  {}: {}", "Device ID".white(), device_info.device_id.cyan());
        println!("  {}: {:02x?}...", "Identity key fingerprint".white(), &identity_key[..8]);
        print!("\n{} ", "Accept this device? (yes/no):".yellow());
        io::stdout().flush().unwrap();
        
        // Create approval channel
        let (tx, rx) = tokio::sync::oneshot::channel();
        
        // Set pending approval
        {
            let mut pending = state.pending_approval.write().await;
            *pending = Some(PendingApproval {
                response_tx: tx,
            });
        }
        
        // Wait for approval response
        let approved = match rx.await {
            Ok(approved) => approved,
            Err(_) => {
                println!("{}", "Failed to get approval response".red());
                connection.close(0u32.into(), b"Approval failed");
                return;
            }
        };
        
        if !approved {
            println!("{}", "Device rejected".red());
            connection.close(0u32.into(), b"Device not trusted");
            return;
        }
        
        let trusted = TrustedDevice {
            device_id: device_info.device_id.clone(),
            identity_key,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };
        if let Err(e) = add_trusted_device(trusted) {
            warn!("Failed to save trusted device: {}", e);
        }
        println!("{} {}", "Device trusted and saved:".green(), device_info.device_id.yellow());
    } else {
        println!("\n{} {}", "Known device reconnected:".green(), device_info.device_id.yellow());
    }
    
    // NOW establish the session after trust is confirmed
    message_handler.establish_session(&device_info.ephemeral_key).unwrap();
    
    // Send HelloResponse to confirm session
    let bridge_info = message_handler.get_device_info();
    let response = MessageType::HelloResponse {
        bridge_info,
        session_established: true,
    };
    
    if let Err(e) = message_handler.send_message(&connection, response).await {
        error!("Failed to send hello response: {}", e);
        return;
    }
    
    // Add to connected remotes
    {
        let mut remotes = state.remotes.write().await;
        remotes.insert(
            device_info.device_id.clone(),
            ConnectedRemote {
                connection: connection.clone(),
                message_handler: message_handler.clone(),
            },
        );
    }
    
    println!("\n{} {}", "Device connected:".green().bold(), device_info.device_id.yellow());
    print!("{} ", ">".blue().bold());
    io::stdout().flush().unwrap();
    
    // Handle messages
    loop {
        match connection.accept_bi().await {
            Ok((_, recv)) => {
                let device_id = device_info.device_id.clone();
                let identity_key = identity_key.clone();
                
                let message_handler = message_handler.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_message(recv, &message_handler, &device_id, &identity_key).await {
                        error!("Failed to handle message from {}: {}", device_id, e);
                    }
                });
            }
            Err(e) => {
                info!("Connection closed with {}: {}", device_info.device_id, e);
                break;
            }
        }
    }
    
    // Remove from connected remotes
    {
        let mut remotes = state.remotes.write().await;
        remotes.remove(&device_info.device_id);
    }
    
    println!("\n{} {}", "Device disconnected:".yellow(), device_info.device_id.yellow());
    print!("{} ", ">".blue().bold());
    io::stdout().flush().unwrap();
}

async fn receive_hello(
    connection: &quinn::Connection,
    message_handler: &MessageHandler,
) -> Result<(DeviceInfo, [u8; 32])> {
    let (_, recv) = connection.accept_bi().await
        .map_err(|e| KaijuError::Transport(format!("Failed to accept stream: {}", e)))?;
    
    let message = message_handler.receive_message(recv).await?;
    
    if let MessageType::Hello(device_info) = message {
        // Don't establish session yet - just return the device info
        Ok((device_info.clone(), device_info.identity_key))
    } else {
        Err(KaijuError::InvalidMessage)
    }
}

async fn handle_message(
    recv: quinn::RecvStream,
    message_handler: &MessageHandler,
    sender_id: &str,
    sender_key: &[u8; 32],
) -> Result<()> {
    let message = message_handler.receive_message(recv).await?;
    
    match message {
        MessageType::EncryptedMessage(envelope) => {
            let plaintext = message_handler.decrypt_and_verify_message(&envelope, sender_key)?;
            println!("\n{}: {}", format!("[{}]", sender_id).cyan(), plaintext.content.white());
            print!("{} ", ">".blue().bold());
            io::stdout().flush().unwrap();
        }
        MessageType::Ping => {
            // Respond with Pong - but we don't have access to state here anymore
            // Just log it for now
            info!("Received Ping from {}", sender_id);
        }
        MessageType::Disconnect => {
            info!("Device {} requested disconnect", sender_id);
        }
        _ => {}
    }
    
    Ok(())
}

async fn send_encrypted_message(
    handler: &MessageHandler,
    connection: &quinn::Connection,
    content: String,
    recipient_id: Option<String>,
) -> Result<()> {
    let envelope = handler.create_encrypted_message(content, recipient_id)?;
    handler.send_message(connection, MessageType::EncryptedMessage(envelope)).await
}

fn get_network_interfaces() -> anyhow::Result<Vec<(String, IpAddr)>> {
    let mut interfaces = Vec::new();
    
    for iface in get_if_addrs()? {
        // Skip loopback interfaces when collecting, we'll add localhost separately
        if iface.is_loopback() {
            continue;
        }
        
        // Only include IPv4 addresses for simplicity
        if iface.addr.ip().is_ipv4() {
            interfaces.push((iface.name.clone(), iface.addr.ip()));
        }
    }
    
    // Sort interfaces by name for consistent ordering
    interfaces.sort_by(|a, b| a.0.cmp(&b.0));
    
    // Always add localhost as an option at the beginning
    interfaces.insert(0, ("localhost".to_string(), IpAddr::from([127, 0, 0, 1])));
    
    Ok(interfaces)
}