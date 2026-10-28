# Configuration & Schema Reference

Detailed technical reference for ConnScope's parameter schemas, profile configuration objects, and validation rules.

---

## 1. Parameter Validation Engine

Before an engine adapter receives a parameter dictionary, ConnScope's configuration builder (`connscope.adapters.builders`) validates and normalizes all values.

### Safety Invariants
1. **Forbidden Key Rejection**: Any parameter key containing execution directives (e.g. `exec`, `command`, `shell`, `spawn`) is rejected with a validation error to prevent configuration injection vulnerabilities.
2. **Type Enforcement**: Parameter values must match the declared types (`string`, `integer`, `boolean`, `list`).
3. **Bound Checking**: Numeric values (e.g. ports, MTU, packet counts) must fall within allowed protocol bounds.
4. **Secret Masking**: Parameters designated as sensitive (`uuid`, `password`, `private_key`, `secret_key`, `psk`) are marked for automatic log redaction (`[REDACTED]`).

---

## 2. Profile Parameter Schemas

### 1. `vless_tcp_none` (VLESS Plaintext)
- `uuid` (`string`, required): Client UUID (e.g. `8f8e02d4-1a2b-4c3d-8e5f-0123456789ab`). Marked sensitive.
- `flow` (`string`, optional): Flow control mode (`null` or `xtls-rprx-vision`).
- `packet_encoding` (`string`, optional): Packet encoding mode (`null` or `xudp`).

### 2. `vless_tcp_reality` (VLESS with REALITY)
- `uuid` (`string`, required): Client UUID. Marked sensitive.
- `flow` (`string`, optional): Flow control mode (`null` or `xtls-rprx-vision`).
- `server_name` (`string`, required): Destination SNI hostname (e.g. `gateway.example.com`).
- `public_key` (`string`, required): Server REALITY curve25519 public key (Base64). Marked sensitive.
- `short_id` (`string`, required): Server short ID (hexadecimal). Marked sensitive.
- `fingerprint` (`string`, optional): Client TLS fingerprint (e.g. `chrome`, `firefox`, `randomized`). Default: `chrome`.
- `spider_x` (`string`, optional): REALITY spider crawl path. Default: `/`.

### 3. `vmess_ws_tls` (VMess over WebSocket with TLS)
- `uuid` (`string`, required): Client UUID. Marked sensitive.
- `alter_id` (`integer`, optional): Legacy VMess alterId ($\ge 0$). Default: `0` (AEAD enforced).
- `security` (`string`, optional): Encryption method (`auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`). Default: `auto`.
- `path` (`string`, optional): WebSocket URI path (e.g. `/api/v1/ws`). Default: `/`.
- `host` (`string`, optional): WebSocket HTTP Host header.
- `server_name` (`string`, optional): TLS SNI hostname.
- `allow_insecure` (`boolean`, optional): Permit invalid TLS certificates. Default: `false`.

### 4. `trojan_tcp_tls` (Trojan over TCP with TLS)
- `password` (`string`, required): Trojan authentication password. Marked sensitive.
- `server_name` (`string`, required): TLS SNI hostname.
- `allow_insecure` (`boolean`, optional): Permit invalid TLS certificates. Default: `false`.
- `alpn` (`list[string]`, optional): Negotiated ALPN protocols (e.g. `["h2", "http/1.1"]`).

### 5. `shadowsocks_tcp_none` (Shadowsocks AEAD)
- `method` (`string`, required): Cipher method (`2022-blake3-aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`).
- `password` (`string`, required): Pre-shared password or Base64 key. Marked sensitive.
- `plugin` (`string`, optional): Optional transport plugin binary name.
- `plugin_opts` (`string`, optional): Options string passed to the plugin.

### 6. `wireguard_udp_none` (Standard WireGuard)
- `private_key` (`string`, required): 32-byte Base64 private identity key. Marked sensitive.
- `public_key` (`string`, required): 32-byte Base64 peer public key.
- `local_address` (`string`, required): Assigned tunnel IP/CIDR (e.g. `10.0.0.2/32`).
- `endpoint` (`string`, required): Peer UDP endpoint `host:port`.
- `mtu` (`integer`, optional): MTU size ($1280 \le \text{MTU} \le 1500$). Default: `1420`.
- `psk` (`string`, optional): Optional pre-shared key. Marked sensitive.

### 7. `openvpn_tcp_none` (OpenVPN over TCP)
- `username` (`string`, optional): Client username. Marked sensitive.
- `password` (`string`, optional): Client password. Marked sensitive.
- `ca_cert` (`string`, optional): Certificate authority certificate contents or path.
- `client_cert` (`string`, optional): Client certificate contents or path.
- `client_key` (`string`, optional): Client private key contents or path. Marked sensitive.
- `cipher` (`string`, optional): Cipher algorithm (e.g. `AES-256-GCM`). Default: `AES-256-GCM`.

### 8. `amneziawg_udp_none` (AmneziaWG Obfuscated WireGuard)
- Inherits all standard WireGuard parameters (`private_key`, `public_key`, `local_address`, `endpoint`, `mtu`).
- `jc` (`integer`, required): Junk packet count ($1 \le jc \le 128$).
- `jmin` (`integer`, required): Minimum junk packet length in bytes ($1 \le jmin \le 1280$).
- `jmax` (`integer`, required): Maximum junk packet length in bytes ($jmin \le jmax \le 1280$).
- `s1` (`integer`, required): Header padding size 1 ($0 \le s1 \le 1280$).
- `s2` (`integer`, required): Header padding size 2 ($0 \le s2 \le 1280$).
- `h1` (`integer`, required): Handshake packet type marker 1.
- `h2` (`integer`, required): Handshake packet type marker 2.

---

## 3. Configuration Overrides via CLI

When running scenarios via `connscope matrix run` or `connscope matrix preview`, parameters can be supplied using the `--config` option either as an inline JSON string:

```bash
connscope matrix run --engine xray --profile vless_tcp_reality \
  --config '{"uuid": "99999999-9999-9999-9999-999999999999", "server_name": "cdn.example.com"}'
```

Or as a path to a configuration file:

```bash
connscope matrix run --engine xray --profile vless_tcp_reality \
  --config /path/to/scenario-config.json
```
