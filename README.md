# Kaiju Secure Messaging

A high-performance QUIC-based secure messaging system with military-grade encryption and perfect forward secrecy.

## Features

### Security
- **Level 2 Security**: AES-256-GCM encryption + Ed25519 signatures + HMAC-SHA256
- **Perfect Forward Secrecy**: X25519 ephemeral keys for each session
- **Passphrase Protection**: Optional Argon2-based key encryption
- **Trust-On-First-Use (TOFU)**: Device fingerprint verification
- **Replay Protection**: LRU cache prevents message replay attacks
- **Message Expiration**: 5-minute validity window

### Performance
- **QUIC Protocol**: Low-latency, multiplexed connections
- **Efficient Cryptography**: Hardware-accelerated via ring
- **Concurrent Connections**: Bridge supports multiple remotes
- **2.5MB Message Size**: Can be changed

### User Experience
- **Colored CLI**: Professional interface with status indicators
- **Network Interface Selection**: Bridge can bind to any available network interface
- **Persistent Identity**: Reconnect without re-approval
- **Simple Commands**: Intuitive bridge and remote interfaces
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Installation

### Prerequisites
- Rust 1.70 or higher

### Build from Source
```bash
git clone https://github.com/stan-smith/kaiju-secure-messaging
cd kaiju-secure-messaging
cargo build --release
```

The binaries will be in `target/release/`:
- `bridge` - The bridge server
- `remote` - The remote client

### Install to System
```bash
cargo install --path .
```

## Quick Start

### 1. Start the Bridge
```bash
./target/release/bridge
```

You'll be prompted to:
1. **Select Network Interface**: Choose from available interfaces (or press Enter for localhost)
2. **Choose Port**: Specify port number (default: 5555)

Example:
```
Available network interfaces:
  1. localhost - 127.0.0.1
  2. eth0 - 192.168.1.100
  3. wlan0 - 192.168.1.101

Select interface number (or press Enter for localhost): 2
Enter port (default: 5555): 5555
Starting bridge on 192.168.1.100:5555...
```

### 2. Connect a Remote Device
```bash
./target/release/remote
```

You'll be prompted for:
1. **Device ID**: Choose a unique name (e.g., "laptop", "phone")
2. **Passphrase Protection** (first time only): Optionally protect your identity
3. **Bridge Address**: Enter the bridge's IP:port (e.g., "192.168.1.100:5555")

### 3. Device Approval
On first connection, the bridge shows:
```
New device connection request:
  Device ID: laptop
  Identity key fingerprint: [a5, 2f, 8c, ...]
  
Accept this device? (yes/no): yes
```

### 4. Send Messages
**From Remote:**
```
> Hello bridge!
```

**From Bridge:**
```
> send laptop Hello from bridge!
> broadcast Hello everyone!
> list
```

## Usage Guide

### Bridge Commands
| Command | Description |
|---------|-------------|
| `list` | Show all connected devices |
| `send <device_id> <message>` | Send to specific device |
| `broadcast <message>` | Send to all devices |
| `quit` or `exit` | Shutdown bridge |

### Remote Commands
- Type any message to send to bridge
- `quit` or `exit` to disconnect

### Security Features

#### Identity Management
- First-time setup creates a persistent identity key
- Optional passphrase encryption (recommended)
- Keys stored in `~/.local/share/kaiju-secure-messaging/device_keys/`

#### Trust Model
- Bridge must approve new devices
- Approved devices stored in trust database
- Reconnections auto-approved for known devices
- Different identity = new approval required

#### Cryptographic Flow
1. **Connection**: Remote sends Hello with public keys
2. **Approval**: Bridge operator verifies fingerprint
3. **Key Exchange**: X25519 Diffie-Hellman establishes session
4. **Encryption**: AES-256-GCM with unique nonce per message
5. **Authentication**: Ed25519 signatures + HMAC-SHA256

## Architecture

```
┌─────────────┐         QUIC/TLS 1.3         ┌─────────────┐
│   Remote    │◄────────────────────────────►│   Bridge    │
│  (Client)   │                              │  (Server)   │
└─────────────┘                              └─────────────┘
     │                                              │
     ├─ Identity Key (Ed25519)                     ├─ Trust Store
     ├─ Ephemeral Key (X25519)                     ├─ Multi-Device Router
     └─ Session Keys (AES+HMAC)                    └─ Session Manager
```

### Message Flow
1. Remote → Bridge: Direct encrypted messages
2. Bridge → Remote: Routed by device ID
3. Bridge → All: Broadcast capability
4. Security: All messages encrypted, signed, and HMAC'd

## Development

### Project Structure
```
kaiju-secure-messaging/
├── src/
│   ├── lib.rs           # Public API and trust management
│   ├── error.rs         # Error types
│   ├── protocol.rs      # Message types and wire format
│   ├── crypto.rs        # Cryptographic operations
│   ├── message.rs       # Message handling
│   ├── transport.rs     # QUIC transport layer
│   └── bin/
│       ├── bridge.rs    # Bridge server binary
│       └── remote.rs    # Remote client binary
└── tests/
    └── integration_test.rs  # Security test suite
```

### Running Tests
```bash
cargo test --release
```

Test coverage includes:
- Full handshake and message exchange
- Replay protection
- HMAC tampering detection
- Signature verification
- Message expiration
- Trusted device persistence
- Perfect forward secrecy

### Building Documentation
```bash
cargo doc --open
```

## Configuration

### Environment Variables
- `RUST_LOG`: Set logging level (e.g., `info`, `debug`)

### File Locations
- **Identity Keys**: `~/.local/share/kaiju-secure-messaging/device_keys/`
- **Trust Database**: `~/.local/share/kaiju-secure-messaging/trusted_devices.json`

## Security Considerations

### Best Practices
1. **Always use passphrase protection** for identity keys
2. **Verify fingerprints** when approving new devices
3. **Run bridge on trusted network** or use VPN
4. **Regular key rotation** - Delete old identity keys periodically

### Threat Model
- **Protects Against**:
  - Eavesdropping (AES-256-GCM)
  - Man-in-the-middle (Ed25519 signatures)
  - Replay attacks (Message ID cache)
  - Identity spoofing (Persistent keys + TOFU)
  - Session hijacking (PFS with ephemeral keys)

- **Does Not Protect Against**:
  - Compromised endpoints
  - Physical access to device
  - Traffic analysis (use Tor for anonymity)
  - Denial of service

## Contributing

Contributions are welcome! Please ensure:
1. All tests pass
2. Security features maintained
3. No emojis in code
4. Clean, commented code
5. Update documentation

## License

Unlicense, do what you want with it. No warranty at all, or promises made, verify all information yourself.

## Acknowledgments

Built with:
- [Quinn](https://github.com/quinn-rs/quinn) - QUIC implementation
- [Ring](https://github.com/briansmith/ring) - Cryptographic operations
- [Tokio](https://tokio.rs) - Async runtime
- [Ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) - Digital signatures

## Support

For issues, questions, or suggestions, please open an issue on GitHub.
