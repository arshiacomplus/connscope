# ConnScope

Network Measurement & Connectivity Monitoring Framework.

ConnScope is designed around a reusable core with pluggable probes,
transport layers, agents, APIs, and multiple frontends.

## Project Structure

```text
src/connscope/
├── core/
├── probes/
├── transports/
├── agent/
├── api/
├── cli/
├── storage/
├── analysis/
└── events/

tests/
docs/
examples/
scripts/
```

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Run:

```bash
connscope
```

## Status

Early project foundation. Core architecture and probe interfaces are
being developed incrementally.
