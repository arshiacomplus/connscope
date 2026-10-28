# Development & Contribution Guide

Developer reference for ConnScope: environment setup, project layout, test suite execution, and architecture conventions.

---

## 1. Development Environment Setup

### Prerequisites
- Python 3.11, 3.12, 3.13, or 3.14.
- Git.
- Optional: `xray` and `sing-box` installed on `$PATH` for local binary verification.

### Installation
Clone the repository and install with development dependencies:

```bash
git clone https://github.com/ArshiaComPlus/connscope.git
cd connscope

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip setuptools wheel
pip install -e .[dev]
```

---

## 2. Source Code Layout

```text
connscope/
├── pyproject.toml              # Build backend configuration & entry points
├── src/
│   └── connscope/
│       ├── __init__.py
│       ├── __main__.py         # Package executable runner (python -m connscope)
│       ├── core/               # Engine contracts, base probe, registry, data models
│       ├── probes/             # TCP, DNS, TLS, HTTP measurement probes
│       ├── adapters/           # Engine adapters (Xray, sing-box) & configuration builders
│       ├── scenarios/          # Protocol catalog, matrix generator, coordinator, harness
│       ├── agent/              # Remote agent client, server protocol, authentication
│       ├── storage/            # In-memory history and result repository contracts
│       ├── events/             # Publisher-subscriber event bus
│       ├── api/                # Observatory REST API endpoints
│       └── cli/                # CLI argument parser, presentation tables, JSON formatters
├── tests/                      # Comprehensive test suite
│   ├── core/
│   ├── probes/
│   ├── adapters/
│   ├── scenarios/
│   ├── agent/
│   └── cli/
└── docs/                       # Complete project documentation
```

---

## 3. Running the Test Suite

ConnScope uses `pytest` for all unit, integration, and mock verification tests:

```bash
# Run the entire test suite
pytest -q

# Run specific subsystem tests
pytest -q tests/scenarios
pytest -q tests/adapters
pytest -q tests/cli
pytest -q tests/agent
pytest -q tests/probes

# Run with verbose output
pytest -v
```

---

## 4. Architectural Rules for Extending ConnScope

### Adding a New Protocol Profile
1. **Catalog Definition**: Register the canonical capability and profile family in `src/connscope/scenarios/catalog.py` with source documentation links.
2. **Parameter Schema**: Define all configurable parameters with strict types, default values, bounds, and security flags (`is_secret=True` for credentials).
3. **Configuration Synthesis**: Add builder logic in `src/connscope/adapters/builders.py` mapping profile parameters to engine-native JSON format.
4. **Adapter Reuse**: Reuse existing `XrayAdapter` or `SingBoxAdapter` lifecycle management. Avoid duplicating subprocess launch or port polling logic.
5. **Unit Tests**: Implement tests covering:
   - Schema validation and constraint bounds.
   - OFAT and Pairwise scenario generation.
   - Native binary syntax validation (`-test` / `check`) where applicable.

---

## 5. Coding & Repository Invariants

- **Standard Library First**: Core measurement and execution routines must avoid unnecessary third-party dependencies.
- **Port Invariant**: Test suites and adapters must **never** hardcode or bind host ports (e.g. `127.0.0.1:10808`). Always bind to ephemeral port `0`.
- **Secret Redaction**: Always ensure new sensitive parameters are marked for automatic masking.
- **Zero Comments / Docstrings Rule**: Per project convention, Python source files must not contain explanatory comments or docstrings. Preserve only compiler directives (`# noqa`, `# type: ignore`, `# pragma: no cover`, shebangs).
