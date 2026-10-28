# Getting Started with ConnScope

This guide covers system prerequisites, runtime dependencies, installation options, and environment verification for ConnScope v0.1.0.

---

## 1. System Requirements & Compatibility

ConnScope is designed with zero mandatory third-party runtime dependencies. All core measurement routines, protocol matrix generation, proxy verification, and catalog operations run directly on standard Python libraries.

| Component | Minimum Requirement | Tested Reference | Notes |
|---|---|---|---|
| **Python** | `>= 3.11` | 3.11, 3.12, 3.13, 3.14 | Pure Python wheel package (`py3-none-any`) |
| **Operating System** | POSIX-compliant | Linux x86_64 (Debian/Ubuntu/Arch) | Fully supported and locally verified |
| **Xray-core** | Optional (v1.8.0+) | v26.3.27 (`/usr/local/bin/xray`) | Required only for real binary validation and live execution |
| **sing-box** | Optional (v1.8.0+) | v1.12.12 | Required only for real binary validation and live execution |
| **System Privileges** | Unprivileged user | Standard user | Non-root execution. Host TUN interfaces are disabled by default. |

---

## 2. Installation Options

### Option A: Install from Built Wheel (Recommended for End Users)

When downloading a release wheel artifact (`connscope-0.1.0-py3-none-any.whl`):

```bash
# Create an isolated virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the wheel
pip install connscope-0.1.0-py3-none-any.whl
```

### Option B: Install from Source Distribution

```bash
# Install from source distribution tarball
pip install connscope-0.1.0.tar.gz
```

### Option C: Development Installation (For Contributors)

To install ConnScope in editable development mode with development and testing dependencies (`pytest`, `pytest-asyncio`):

```bash
git clone https://github.com/ArshiaComPlus/connscope.git
cd connscope

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip setuptools wheel
pip install -e .[dev]
```

---

## 3. Verifying Installation

Verify that the `connscope` command-line executable is available in your PATH:

```bash
connscope --version
# Output: connscope 0.1.0
```

Verify that the CLI can parse builtin commands and inspect available probes:

```bash
connscope probe list
```

Expected output:
```text
Available Builtin Probes:
  tcp    - TCP connection latency & socket state probe (aliases: tcp_connect)
  dns    - DNS resolution probe (aliases: dns_resolve)
  tls    - TLS handshake probe (aliases: tls_handshake)
  http   - HTTP request probe (aliases: http_request)
```

Verify local engine readiness:

```bash
connscope catalog check
```

This command inspects the system PATH for `xray` and `sing-box` binaries, checks version compatibility against catalog definitions, and outputs readiness for the 8 standard profile families.

---

## 4. Environment Variables

ConnScope recognizes the following optional environment variables:

| Variable | Description | Default |
|---|---|---|
| `CONNSCOPE_AGENT_URL` | Default remote Agent base URL when `--node` is not specified on CLI. | `None` (local execution) |
| `CONNSCOPE_AGENT_TOKEN` | Bearer token for authenticating to remote Agent nodes. Recommended over `--token` to prevent token leakage in OS process listings (`ps`). | `None` |

---

## 5. Next Steps

- Proceed to the [Quickstart Guide](quickstart.md) for a 30-second walkthrough running local diagnostic tests.
- Learn about the [System Architecture](architecture.md).
- Explore the [CLI Reference](reference/cli.md) for all command options.
