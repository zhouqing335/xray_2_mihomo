# xray2clash

A simple tool to convert Xray configuration files to Clash YAML format.

## Description

`xray2clash` parses Xray inbound configurations and generates corresponding Clash proxy configurations. It supports various protocols like VMess, VLESS, Trojan, Shadowsocks, Socks, HTTP, and WireGuard, along with transport layers such as TCP, WebSocket, gRPC, HTTP/2, and KCP.

## Features

- **Protocol Support**: VMess, VLESS, Trojan, Shadowsocks, Socks, HTTP, WireGuard
- **Transport Layers**: TCP, WS, gRPC, H2, KCP, TLS/XTLS
- **Automatic Proxy Groups**: Generates a URL-test proxy group for load balancing
- **Routing Rules**: Includes basic rules for Google domains and China traffic
- **Certificate Handling**: Skips certificate verification for IPs, localhost, or empty server addresses

## Usage

### Build

```bash
./build.sh
```

Or manually:

```bash
gcc main.c cJSON.c -o xray2clash
```

### Run

```bash
./xray2clash [server] [config_file] [output_file]
```

- `server`: Domain or IP for proxies (default: localhost). If IP or localhost, skips cert verification.
- `config_file`: Path to Xray config.json (default: config.json)
- `output_file`: Path to output Clash YAML (default: clash.yaml)

### Examples

1. Default usage (localhost, config.json -> clash.yaml):
   ```bash
   ./xray2clash
   ```

2. Specify server IP:
   ```bash
   ./xray2clash 192.168.1.1
   ```

3. Custom config and output:
   ```bash
   ./xray2clash example.com myconfig.json output.yaml
   ```

## Dependencies

- cJSON library (included in the repository)
- Standard C libraries

## Supported Xray Protocols

- **VMess**: AEAD encryption
- **VLESS**: With XTLS Vision flow
- **Trojan**: Trojan-GFW compatible
- **Shadowsocks**: SS/SS2022
- **Socks**: SOCKS5 (with optional auth)
- **HTTP**: HTTP proxy
- **WireGuard**: VPN protocol

## Output Format

Generates a complete Clash YAML config with:
- Mixed port 7890
- Proxies from Xray inbounds
- Proxy group for auto-selection
- Basic routing rules

## License

MIT License

## Contributing

Feel free to submit issues or pull requests for additional protocol support.