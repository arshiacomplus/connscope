# Layer 3 Interface Adapters Guide

Comprehensive operational guide for ConnScope's Layer 3 network tunnel adapters covering WireGuard, AmneziaWG, and OpenVPN.

---

## 1. Overview & Purpose

Unlike application-layer SOCKS5 proxies that operate over loopback user-space ports, Layer 3 VPN protocols (WireGuard, AmneziaWG, and OpenVPN) operate by creating network virtual interfaces (`tun0`, `wg0`) and modifying kernel routing tables.

ConnScope includes declarative models and adapter abstractions for these Layer 3 protocols, while enforcing strict security safeguards:
- **Zero Root Privilege Requirement by Default**: ConnScope runs unprivileged; it never mutates host routing tables or binds raw kernel interfaces during standard test runs.
- **Config & Adapter Validation**: Synthesizes and validates native client configuration files (`wg0.conf`, `client.ovpn`) against engine schemas.
- **Mock Unit Verification**: All lifecycle operations (interface creation, MTU setting, handshake checking) are fully tested in hermetic mock test suites.

---

## 2. Prerequisites & Dependencies

- Python 3.11+ standard library.
- For theoretical live tunnel execution (future phases):
  - Linux kernel WireGuard module or userspace `wireguard-go`.
  - `amnezia-wg` userspace daemon for AmneziaWG.
  - `openvpn` client binary for OpenVPN.
  - Linux capabilities: `CAP_NET_ADMIN` or `sudo` access to execute `ip link` / `wg-quick`.

---

## 3. Conceptual Model & Terminology

- **Layer 3 Interface**: A virtual kernel network device (`TUN` or `WireGuard` interface) exchanging raw IP packets.
- **AmneziaWG**: An advanced WireGuard fork that introduces randomized header padding, junk packet counts (`jc`, `jmin`, `jmax`), and handshake obfuscation (`s1`, `s2`, `h1`, `h2`) to defeat Deep Packet Inspection (DPI).
- **Safe Boundary Policy**: ConnScope's architectural rule that prevents test runners from modifying the host system's primary network routing or altering default gateways.

---

## 4. Supported vs. Unsupported Matrix

| Protocol | Configuration Synthesis | Syntax / Schema Validation | Mock Adapter Lifecycle | Live Host Interface Creation |
|---|---|---|---|---|
| **WireGuard** | Supported (`wg.conf`) | Supported | Supported | Disabled by Safety Policy |
| **AmneziaWG** | Supported (`awg.conf`) | Supported | Supported | Disabled by Safety Policy |
| **OpenVPN** | Supported (`client.ovpn`) | Supported | Supported | Disabled by Safety Policy |

---

## 5. Step-by-Step Usage & Commands

### Inspecting Layer 3 Capabilities in Catalog

```bash
# View WireGuard capability details
connscope catalog show wireguard_udp_none

# View AmneziaWG obfuscation parameters
connscope catalog show amneziawg_udp_none
```

### Previewing Planned WireGuard Scenario

```bash
connscope matrix preview \
  --engine xray \
  --profile wireguard_udp_none \
  --mode explicit
```

### Validating Configuration Schemas

Validate that WireGuard keypairs, addresses, and MTUs conform to strict schema requirements:

```bash
connscope catalog parameter-coverage --profile wireguard_udp_none
```

---

## 6. Real-World Examples & Output Interpretation

### Example: AmneziaWG Parameter Configuration Schema

When previewed or generated, the AmneziaWG parameter block ensures all obfuscation parameters are properly typed and bounded:

```json
{
  "profile": "amneziawg_udp_none",
  "parameters": {
    "private_key": "[REDACTED]",
    "public_key": "9yG7h...=",
    "endpoint": "vpn.example.com:51820",
    "local_address": "10.0.0.2/32",
    "jc": 5,
    "jmin": 40,
    "jmax": 70,
    "s1": 56,
    "s2": 112,
    "h1": 1,
    "h2": 2
  }
}
```

Interpretation:
- `private_key`: Redacted for security.
- `jc`, `jmin`, `jmax`: Junk packet count and size ranges to randomize initial packet entropy.
- `s1`, `s2`: Obfuscated packet size prefixes.

---

## 7. Configuration & Parameter Reference

| Parameter Key | Protocol | Valid Range / Format | Description |
|---|---|---|---|
| `private_key` | WG / AWG | 32-byte Base64 string | Client private identity key (Redacted). |
| `public_key` | WG / AWG | 32-byte Base64 string | Server peer public key. |
| `local_address` | WG / AWG | IPv4 or IPv6 CIDR | Assigned interface IP (e.g. `10.8.0.2/24`). |
| `mtu` | WG / AWG | `1280`–`1500` | Interface Maximum Transmission Unit. |
| `jc` | AWG | `1`–`128` | Junk packet count for handshake obfuscation. |
| `jmin`, `jmax` | AWG | `1`–`1280` | Min/max byte length of junk packets. |
| `username`, `password` | OpenVPN | String | Authentication credentials (Redacted). |

---

## 8. Error Handling & Common Failure Modes

| Condition | Cause | Policy Response |
|---|---|---|
| Attempted Host TUN Creation | Unprivileged process attempted to open `/dev/net/tun` | Blocked by adapter safety policy; returns `PermissionDenied` error |
| Invalid WireGuard Key | String is not valid 32-byte Base64 | Caught during parameter validation before adapter execution |
| MTU Below Minimum | MTU $< 1280$ for IPv6 | Rejected by schema constraint validator |

---

## 9. Verification & Evidence Semantics

In v0.1.0, Layer 3 adapters operate at **Level 1 (`config_validation_implemented`)** and **Level 2 (`real_binary_config_validated`)**. Live interface creation is explicitly marked as requiring elevated network privileges and will be integrated into dedicated isolated network namespace runners in future releases.

---

## 10. Related Guides & Next Steps

- [Declarative Capability Catalog](capability-catalog.md) — Protocol capability modeling.
- [Security, Isolation & Redaction](../security.md) — Why ConnScope isolates host interfaces.
- [Feature Support Matrix](../feature-matrix.md) — Engine support status for tunnel protocols.
