# Declarative Capability Catalog Guide

Comprehensive operational guide for ConnScope's declarative protocol, engine, and parameter capability catalog.

---

## 1. Overview & Purpose

ConnScope grounds its test planning in an explicit, source-verified declarative catalog (`ProtocolCatalog`). Rather than hardcoding protocol features into ad-hoc test scripts, the catalog separates:
- **Canonical Capabilities**: Protocol-level features defined by standards or official specifications (e.g. VLESS flow types, VMess AEAD, Shadowsocks ciphers).
- **Engine Capabilities**: Engine-specific implementations (e.g. Xray-core vs sing-box support matrices).
- **Parameter Schemas**: Typed definitions for all tunable parameters, including data types, allowed values, bounds, and security sensitivity flags.
- **Source References**: Traceable provenance linking each capability claim to official documentation, Git commits, or published RFCs.

---

## 2. Prerequisites & Dependencies

- Python 3.11+ standard library.
- Catalog data is bundled with ConnScope; no database or external network access is required to query, validate, or inspect catalog schemas.

---

## 3. Conceptual Model & Terminology

- **Canonical Capability**: A protocol feature considered independently of any specific engine implementation.
- **Engine Capability**: The concrete realization of a capability in an engine version (e.g. `xray:vless_reality`).
- **Profile Family**: An executable client template pairing a protocol, transport, and security mode (e.g. `vless_tcp_reality`).
- **Parameter Constraint**: Rules enforcing validity (e.g. `uuid` must match standard UUID hex format; `alter_id` must be an integer $\ge 0$).
- **Taxonomy Category**: Logical grouping of capabilities (`proxy_protocols`, `transport_layers`, `security_layers`, `obfuscation`, `tunnel_interfaces`).

---

## 4. Supported vs. Unsupported Matrix

| Catalog Capability | Status in v0.1.0 | Notes |
|---|---|---|
| In-Memory Catalog Validation | Fully Supported | Validates schema integrity and constraint bounds |
| Custom Catalog Loading | Supported via `--catalog PATH` | Load alternative catalog JSON files |
| Coverage Reporting | Supported via `catalog coverage` | Displays tabular or JSON capability coverage |
| Parameter Coverage Auditing | Supported via `catalog parameter-coverage` | Evaluates parameter test space coverage |
| Upstream Provenance Links | Supported | RFCs, Xray/sing-box source docs, Exclave commit hashes |
| Dynamic Runtime Schema Mutation | Unsupported | Schemas are immutable at runtime to guarantee reproducibility |

---

## 5. Step-by-Step Usage & Commands

### Validating Catalog Schemas

Validate the integrity of the built-in catalog:

```bash
connscope catalog validate
```

To validate an external catalog file:

```bash
connscope catalog validate /path/to/custom-catalog.json
```

### Listing Registered Engines and Profiles

```bash
connscope catalog list
```

### Inspecting Specific Capabilities or Profiles

```bash
# Inspect an engine
connscope catalog show xray

# Inspect a protocol profile
connscope catalog show vless_tcp_reality
```

### Generating Capability Coverage Reports

```bash
# Global coverage across all engines and protocols
connscope catalog coverage

# Filter coverage to sing-box
connscope catalog coverage --engine sing_box

# Export coverage report as JSON
connscope catalog coverage --json
```

### Generating Parameter Coverage Reports

```bash
# Per-profile parameter coverage table
connscope catalog parameter-coverage

# Filter to Xray REALITY profile
connscope catalog parameter-coverage --engine xray --profile vless_tcp_reality
```

---

## 6. Real-World Examples & Output Interpretation

### Example: Catalog Coverage Output

Command:
```bash
connscope catalog coverage --protocol vless
```

Terminal output:
```text
Protocol Capability Coverage: VLESS
Category            Capability               Xray Support    sing-box Support    Evidence Status
------------------  -----------------------  --------------  ------------------  -------------------
proxy_protocols     vless_base               SUPPORTED       SUPPORTED           real_binary_config_validated
security_layers     vless_reality            SUPPORTED       SUPPORTED           real_binary_config_validated
security_layers     vless_tls                SUPPORTED       SUPPORTED           real_binary_config_validated
transport_layers    vless_tcp                SUPPORTED       SUPPORTED           local_diagnostic_verified
transport_layers    vless_ws                 SUPPORTED       SUPPORTED           config_validation_implemented
transport_layers    vless_grpc               SUPPORTED       SUPPORTED           config_validation_implemented
```

Interpretation:
- `SUPPORTED`: Both engines provide native implementation for the capability.
- `Evidence Status`: The highest verified evidence level attained for this capability.

---

## 7. Configuration & Parameter Reference

Catalog inspection commands support standard arguments:

| Flag | Argument | Description |
|---|---|---|
| `--catalog` | Path to JSON file | Load a user-supplied catalog definition. |
| `--engine` | Engine identifier (`xray`, `sing_box`) | Filter coverage or profile list. |
| `--protocol` | Protocol name (`vless`, `vmess`, etc.) | Filter coverage to specific protocol families. |
| `--category` | Taxonomy category | Filter coverage by functional area. |
| `--validate-binary`| Flag | Execute native binary syntax check against parameter variations. |
| `--json` | Flag | Output structured JSON instead of formatted text tables. |

---

## 8. Error Handling & Common Failure Modes

| Failure Symptom | Root Cause | Remediation |
|---|---|---|
| `UnknownProfileError` | Profile ID not in catalog | Check spelling with `connscope catalog list` |
| `UnknownEngineError` | Engine ID not recognized | Valid built-in engines are `xray` and `sing_box` |
| `SchemaValidationError` | Custom catalog JSON violated schema | Run `connscope catalog validate <path>` to see field errors |
| `BinaryValidationMismatch` | Engine rejected parameter value | Run with `--validate-binary` to see parser error output |

---

## 9. Verification & Evidence Semantics

The catalog enforces explicit evidence status tracking:
- `catalogued` (Level 0): Present in schema declarations.
- `config_validation_implemented` (Level 1): Verified by internal parameter validator.
- `real_binary_config_validated` (Level 2): Native engine binary parsed the configuration successfully.
- `local_diagnostic_verified` (Level 3): Full loopback proxy handshake and HTTP transfer completed.

---

## 10. Related Guides & Next Steps

- [Parameter Scenarios & Combinatorics](parameter-scenarios.md) — How catalog parameters are combined into test matrices.
- [Evidence Hierarchy & Verification Semantics](../reference/evidence-levels.md) — Formal taxonomy of verification states.
- [Configuration Reference](../reference/configuration.md) — Detailed listing of all catalog parameters.
