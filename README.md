# TCP Port Forwarder

A lightweight TCP port forwarder written in Go for forwarding traffic from a Linux server to an Exchange server over Tailscale.

## Features

- **JSON Configuration**: Easy configuration through JSON files with init command support
- **DNS Caching**: Automatic hostname resolution with hourly refresh and fallback handling
- **High Performance**: Concurrent handling of multiple connections using goroutines
- **Bidirectional**: Full duplex data copying between client and target connections
- **Graceful Shutdown**: Proper signal handling (SIGINT/SIGTERM) with connection cleanup
- **Robust Error Handling**: Comprehensive logging and connection state management
- **Exchange Ready**: Default configuration for common Exchange ports (HTTP, HTTPS, SMTP, IMAPS)
- **IPv6 Compatible**: Proper address handling for both IPv4 and IPv6
- **Mixed Configuration**: Support for both hostnames and IP addresses in the same config
- **Single Binary**: Compiles to a standalone executable for easy deployment

## Quick Start

### 1. Build the binary
```bash
go build -o tcp-forwarder tcp-forwarder.go
```

### 2. Create default configuration
```bash
./tcp-forwarder -init
```

### 3. Edit configuration
Edit the generated `config.json` file and replace `mail.example.com` with your Exchange server hostname or IP:

```json
{
  "rules": [
    {
      "name": "HTTP",
      "listen_port": 80,
      "target_host": "exchange.your-tailnet.ts.net",
      "target_port": 80
    },
    {
      "name": "HTTPS",
      "listen_port": 443,
      "target_host": "100.64.0.2",
      "target_port": 443
    },
    {
      "name": "SMTP",
      "listen_port": 587,
      "target_host": "exchange-server",
      "target_port": 587
    },
    {
      "name": "IMAPS",
      "listen_port": 993,
      "target_host": "192.168.1.100",
      "target_port": 993
    }
  ]
}
```

**Note**: The forwarder automatically detects whether you're using hostnames or IP addresses:
- **Hostnames** (like `exchange.company.com`) are resolved via DNS and cached with hourly refresh
- **IP addresses** (like `192.168.1.100`) are used directly with no DNS overhead

### 4. Run the forwarder
```bash
./tcp-forwarder
```

## Usage

### Command Line Options

- `-init`: Create a default `config.json` file with Exchange server ports
- `-config <file>`: Specify a custom configuration file (default: `config.json`)

### Examples

```bash
# Create default configuration
./tcp-forwarder -init

# Run with default config.json
./tcp-forwarder

# Run with custom configuration file
./tcp-forwarder -config /etc/tcp-forwarder/custom.json
```

## Configuration

The configuration file uses JSON format with the following structure:

```json
{
  "rules": [
    {
      "name": "Rule Name",
      "listen_port": 80,
      "target_host": "target.example.com",
      "target_port": 8080
    }
  ]
}
```

### Configuration Fields

- **name**: Human-readable name for the forwarding rule (used in logs)
- **listen_port**: Local port to listen on for incoming connections
- **target_host**: Target server hostname or IP address (supports both formats automatically)
- **target_port**: Port on the target server to forward connections to

### Hostname vs IP Configuration

**Hostnames** (DNS-based):
- Automatically resolved and cached on startup
- Refreshed every hour to handle IP changes
- Fallback to stale cache if DNS resolution fails
- Examples: `exchange.company.com`, `mail.tailnet.ts.net`, `exchange-server`

**IP Addresses** (Direct):
- Used directly with no DNS lookup overhead
- Best for static configurations or performance-critical scenarios
- Examples: `192.168.1.100`, `100.64.0.2`, `10.0.1.50`

### Default Exchange Ports

The init command creates configuration for these common Exchange ports:

| Port | Service | Description |
|------|---------|-------------|
| 80   | HTTP    | Web services, Autodiscover |
| 443  | HTTPS   | Outlook Web Access, Exchange Admin Center |
| 587  | SMTP    | Mail submission (authenticated) |
| 993  | IMAPS   | IMAP over SSL/TLS |

## Deployment

### Linux Service (systemd)

Create a systemd service file at `/etc/systemd/system/tcp-forwarder.service`:

```ini
[Unit]
Description=TCP Port Forwarder
After=network.target

[Service]
Type=simple
User=tcp-forwarder
WorkingDirectory=/opt/tcp-forwarder
ExecStart=/opt/tcp-forwarder/tcp-forwarder -config /opt/tcp-forwarder/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl enable tcp-forwarder
sudo systemctl start tcp-forwarder
sudo systemctl status tcp-forwarder
```

### Docker

Create a `Dockerfile`:

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY tcp-forwarder.go .
RUN go build -o tcp-forwarder tcp-forwarder.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/tcp-forwarder .
COPY config.json .
CMD ["./tcp-forwarder"]
```

Build and run:
```bash
docker build -t tcp-forwarder .
docker run -d -p 80:80 -p 443:443 -p 587:587 -p 993:993 tcp-forwarder
```

## Logging

The forwarder provides detailed logging for:

- Service startup and configuration loading
- DNS resolution events and IP address changes
- Listener creation for each forwarding rule
- New client connections with source addresses
- Target connection establishment
- Connection closures and data transfer completion
- Error conditions and connection failures

Example log output:
```
2024/01/15 10:30:40 DNS: Resolving exchange.company.com on startup...
2024/01/15 10:30:40 DNS: Resolved exchange.company.com -> 100.64.0.2
2024/01/15 10:30:40 DNS: Started periodic refresh (every 1 hour)
2024/01/15 10:30:45 Started listener for HTTP on port 80 -> exchange.company.com:80
2024/01/15 10:30:45 Started listener for HTTPS on port 443 -> 192.168.1.100:443
2024/01/15 10:30:45 TCP forwarder started successfully
2024/01/15 10:31:20 New connection from 192.168.1.100:54321 for HTTP
2024/01/15 10:31:20 Established connection: 192.168.1.100:54321 -> 100.64.0.2:80 (HTTP)
2024/01/15 11:30:45 DNS: Refreshing 1 hostnames...
2024/01/15 11:30:45 DNS: IP changed for exchange.company.com: 100.64.0.2 -> 100.64.0.3
```

## Performance Considerations

- Each connection is handled in a separate goroutine for maximum concurrency
- 32KB buffer size for optimal throughput
- 30-second read/write timeouts prevent hanging connections
- Graceful shutdown ensures all connections are properly closed

## Security Notes

- The forwarder runs as a transparent TCP proxy
- No authentication or encryption is performed by the forwarder itself
- Secure the configuration file as it contains target server information
- Run with minimal privileges (non-root user recommended)
- Use Tailscale's built-in security features for network access control

## Troubleshooting

### Common Issues

**Port already in use**:
```
Failed to listen on port 80: bind: address already in use
```
Solution: Stop other services using the port or change the listen_port in configuration.

**Cannot connect to target**:
```
Failed to connect to target 100.64.0.2:80: connection refused
```
Solution: Verify the target host is accessible and the service is running.

**DNS resolution failures**:
```
DNS: Failed to resolve exchange.company.com: no such host
```
Solution: Check hostname spelling, DNS configuration, or use IP address instead.

**Stale DNS cache warnings**:
```
DNS: Fresh resolution failed for exchange.company.com, using stale cache entry: 100.64.0.2
```
This is informational - the forwarder is using a cached IP when DNS is temporarily unavailable.

**Permission denied on low ports**:
```
Failed to listen on port 80: bind: permission denied
```
Solution: Run as root or use capabilities: `sudo setcap 'cap_net_bind_service=+ep' tcp-forwarder`

### Debug Mode

For verbose logging, you can modify the log level or add debug output as needed.

## Requirements

- Go 1.19+ for building
- Linux system for deployment
- Network access to target Exchange server (via Tailscale)
- Appropriate firewall rules for listening ports

## License

This project is provided as-is for educational and operational use.