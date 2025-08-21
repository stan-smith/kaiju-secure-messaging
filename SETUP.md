# Setup Guide for Kaiju Secure Messaging

## Prerequisites

### System Requirements
- **OS**: Linux, macOS, or Windows
- **RAM**: 512MB minimum
- **Network**: TCP/UDP port 5555 (configurable)
- **Storage**: ~10MB for binaries + key storage

### Software Requirements
- **Rust**: Version 1.70 or higher
- **Git**: For cloning repository

## Installation Steps

### 1. Install Rust
If you don't have Rust installed:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Verify installation:
```bash
rustc --version
cargo --version
```

### 2. Clone Repository
```bash
git clone https://github.com/yourusername/kaiju-secure-messaging.git
cd kaiju-secure-messaging
```

### 3. Build the Project
```bash
cargo build --release
```

This creates two binaries in `target/release/`:
- `bridge` - The server component
- `remote` - The client component

### 4. Optional: Install System-Wide
```bash
sudo cp target/release/bridge /usr/local/bin/
sudo cp target/release/remote /usr/local/bin/
```

## First-Time Setup

### Setting Up the Bridge

1. **Start the bridge**:
```bash
./target/release/bridge
```

2. **Select network interface**:
```
=== Kaiju Secure Messaging Bridge ===

Available network interfaces:
  1. localhost - 127.0.0.1
  2. docker0 - 172.17.0.1
  3. eth0 - 192.168.1.100
  4. wlan0 - 192.168.1.101

Select interface number (or press Enter for localhost): 
```

Choose an interface based on your needs:
- **localhost (1)**: For local testing only
- **eth0/wlan0**: For network access from other devices
- **docker0**: For Docker container communication

3. **Choose port**:
```
Enter port (default: 5555): 
```
Press Enter for default or specify a custom port.

4. **Bridge starts**:
```
Starting bridge on 192.168.1.100:5555...
Bridge listening on 192.168.1.100:5555

Commands:
  list - Show connected devices
  send <device_id> <msg> - Send message to device
  broadcast <msg> - Send to all devices
  quit/exit - Exit bridge
```

5. **Keep the bridge running** in this terminal

### Setting Up Remote Devices

1. **Open a new terminal** for each remote device

2. **Start the remote**:
```bash
./target/release/remote
```

3. **Initial Configuration**:
```
=== Kaiju Secure Messaging Remote ===
Enter your device ID: laptop
```
Choose a unique, memorable name for this device.

4. **Identity Key Creation** (first time only):
```
Creating new identity for device laptop
Protect this identity with a passphrase? (yes/no): yes
Enter passphrase: ********
Confirm passphrase: ********
Saved passphrase-protected identity for device laptop
```

5. **Connect to Bridge**:
```
Enter bridge address (default: 127.0.0.1:5555): 
```
- For local testing: Press Enter to use default
- For network bridge: Enter the bridge's IP:port (e.g., "192.168.1.100:5555")

```
Connecting to bridge at 192.168.1.100:5555...
Connected to bridge!
```

6. **Device Approval** (on bridge terminal):
```
New device connection request:
  Device ID: laptop
  Identity key fingerprint: [a5, 2f, 8c, d1, 7e, 93, 4b, 21]...

Accept this device? (yes/no): yes
Device trusted and saved: laptop
```

7. **Success**:
```
Secure session established

Type messages to send to the bridge (or 'quit'/'exit' to disconnect):
>
```

## Usage Examples

### Basic Messaging

**From Remote to Bridge**:
```
> Hello, this is laptop calling!
```

**From Bridge to Remote**:
```
> send laptop Welcome to the secure network!
```

### Multiple Devices

1. Start additional remotes with different device IDs
2. Bridge approves each new device
3. Use `list` on bridge to see connected devices
4. Use `broadcast` to message all devices

### Remote Network Connections

When connecting from another device on the network:

1. **Find Bridge IP**: Note the IP address shown when starting the bridge
2. **Ensure Connectivity**: Ping the bridge IP from the remote device
3. **Connect Remote**: Enter the bridge's IP:port when prompted (e.g., "192.168.1.100:5555")
4. **Firewall**: Ensure UDP port 5555 is open on the bridge machine

### Reconnection

When a device reconnects:
- If using same identity: Auto-approved
- If passphrase protected: Enter passphrase
- If new identity: Requires new approval

## Network Configuration

### Default Settings
- **Bridge Address**: Selected at startup (default: 127.0.0.1:5555)
- **Protocol**: QUIC over UDP
- **TLS**: Version 1.3

### Network Interface Selection
The bridge now supports binding to any available network interface:

1. **Local Only** (127.0.0.1): For testing and local development
2. **LAN Access** (192.168.x.x): For devices on your local network
3. **All Interfaces** (0.0.0.0): Accept connections from any interface

The bridge automatically detects and lists all available interfaces at startup.

### Firewall Rules
For remote connections, open UDP port 5555:

**Linux (iptables)**:
```bash
sudo iptables -A INPUT -p udp --dport 5555 -j ACCEPT
```

**macOS**:
```bash
sudo pfctl -e
echo "pass in proto udp from any to any port 5555" | sudo tee -a /etc/pf.conf
sudo pfctl -f /etc/pf.conf
```

**Windows (PowerShell as Admin)**:
```powershell
New-NetFirewallRule -DisplayName "Kaiju Bridge" -Direction Inbound -Protocol UDP -LocalPort 5555 -Action Allow
```

## Troubleshooting

### Common Issues

**1. Connection Timeout**
- Check firewall settings
- Verify bridge is running
- Confirm correct IP address

**2. "Device not trusted" Error**
- Bridge rejected the connection
- Try reconnecting and accept when prompted

**3. "Invalid passphrase" Error**
- Passphrase is case-sensitive
- Check for extra spaces
- If forgotten, delete key file and recreate

**4. "Address already in use"**
- Another process using port 5555
- Kill existing bridge process
- Or change port in source code

### File Locations

**Identity Keys**:
```bash
ls ~/.local/share/kaiju-secure-messaging/device_keys/
```

**Trust Database**:
```bash
cat ~/.local/share/kaiju-secure-messaging/trusted_devices.json
```

### Reset Device Identity

To create new identity for a device:
```bash
rm ~/.local/share/kaiju-secure-messaging/device_keys/<device_id>.key
```

### Reset Trust Database

To clear all trusted devices on bridge:
```bash
rm ~/.local/share/kaiju-secure-messaging/trusted_devices.json
```

## Security Checklist

- [ ] Use strong passphrases for identity keys
- [ ] Verify device fingerprints when approving
- [ ] Run bridge on secure, trusted network
- [ ] Keep software updated
- [ ] Monitor bridge for unauthorized connections
- [ ] Regularly review trusted devices list
- [ ] Use VPN for internet connections

## Advanced Configuration

### Running as Service

**Linux (systemd)**:

Create `/etc/systemd/system/kaiju-bridge.service`:
```ini
[Unit]
Description=Kaiju Secure Messaging Bridge
After=network.target

[Service]
Type=simple
User=youruser
ExecStart=/usr/local/bin/bridge
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable kaiju-bridge
sudo systemctl start kaiju-bridge
```

### Docker Deployment

Create `Dockerfile`:
```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/bridge /usr/local/bin/
EXPOSE 5555/udp
CMD ["bridge"]
```

Build and run:
```bash
docker build -t kaiju-bridge .
docker run -p 5555:5555/udp kaiju-bridge
```

## Getting Help

- **Documentation**: See README.md for detailed information
- **Issues**: Report bugs on GitHub Issues
- **Security**: For security issues, please email directly

## Next Steps

1. Test with local connections
2. Set up bridge on dedicated server
3. Configure firewall rules
4. Create device identities for all users
5. Document fingerprints for verification
6. Implement monitoring and logging