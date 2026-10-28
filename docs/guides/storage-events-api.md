# Storage, Event Stream & Observatory API Guide

Comprehensive operational guide for ConnScope's in-memory storage, pub/sub event bus, and Observatory REST API interfaces.

---

## 1. Overview & Purpose

ConnScope provides a unified telemetry subsystem designed to store measurement histories, broadcast real-time events to listeners, and serve data via HTTP endpoints.

This subsystem comprises:
- **`connscope.storage`**: In-memory repository contracts for storing, querying, and filtering historical probe results and scenario measurement records.
- **`connscope.events`**: Decoupled publisher-subscriber event bus for broadcasting lifecycle changes, probe completions, and error notifications.
- **`connscope.api`**: Lightweight HTTP API providing read-only REST endpoints for observability dashboards and external health checks.

---

## 2. Prerequisites & Dependencies

- Python 3.11+ standard library (`asyncio`, `dataclasses`).
- No external databases (PostgreSQL, SQLite, Redis) are required for baseline in-memory storage.

---

## 3. Conceptual Model & Terminology

- **ResultStore**: Abstract storage repository interface defining query, add, and filter primitives for probe results.
- **EventBus**: Asynchronous event dispatcher facilitating publish-subscribe patterns between measurement producers and consumers.
- **Event Topic**: Categorized event channel (e.g. `probe.started`, `probe.completed`, `scenario.failed`).
- **Observatory API**: Programmatic HTTP interface exposing stored telemetry and engine state to web dashboards.

---

## 4. Supported vs. Unsupported Matrix

| Capability | In-Memory Engine | External SQL Database |
|---|---|---|
| Probe Result Retention | Supported (configurable capacity) | Architectural stub in v0.1.0 |
| Scenario Record Retention | Supported | Architectural stub in v0.1.0 |
| Event Topic Filtering | Supported | Supported |
| REST Query Endpoints | Supported | Supported |
| Long-term Persistent Disk Storage | Via JSON Lines files (`.jsonl`) | Dedicated DB integration in future phases |

---

## 5. Step-by-Step Usage & Commands

### Using the In-Memory ResultStore (Python API)

```python
from connscope.storage import InMemoryResultStore
from connscope.core.models import Target, ProbeStatus

# Initialize store with max capacity
store = InMemoryResultStore(max_results=1000)

# Query recent successful results
results = store.query(status=ProbeStatus.SUCCESS, limit=10)
```

### Subscribing to Event Topics

```python
from connscope.events import EventBus

bus = EventBus()

async def on_probe_done(event):
    print(f"Probe completed: {event.probe_name} against {event.target}")

bus.subscribe("probe.completed", on_probe_done)
```

### Starting the Observatory API Server

The API server can be instantiated programmatically:

```python
from connscope.api import create_app
import asyncio

app = create_app(store=store, bus=bus)
# Runs ASGI / HTTP listener
```

---

## 6. Real-World Examples & Output Interpretation

### Example: REST API Response (`GET /api/v1/results`)

```json
{
  "total": 142,
  "limit": 2,
  "offset": 0,
  "results": [
    {
      "id": "res_8f93a1c",
      "probe": "http_request",
      "target": "example.com:443",
      "status": "SUCCESS",
      "duration_ms": 18.4,
      "timestamp": "2026-10-28T12:00:00Z"
    },
    {
      "id": "res_7e82b0b",
      "probe": "tcp_connect",
      "target": "1.1.1.1:53",
      "status": "SUCCESS",
      "duration_ms": 8.1,
      "timestamp": "2026-10-28T11:59:50Z"
    }
  ]
}
```

Interpretation:
- `results`: Chronologically ordered list of recent measurement records.
- Standardized pagination headers support infinite scrolling in observatory dashboards.

---

## 7. Configuration & Parameter Reference

| Class / Component | Configuration Parameter | Default | Description |
|---|---|---|---|
| `InMemoryResultStore` | `max_results` | `10000` | Maximum number of records retained in ring buffer. |
| `EventBus` | `max_queue_size` | `1000` | Asynchronous queue buffer per subscriber. |
| `ObservatoryApp` | `host` | `"127.0.0.1"` | Bind host for API listener. |
| `ObservatoryApp` | `port` | `8080` | Bind port for API listener. |

---

## 8. Error Handling & Common Failure Modes

| Condition | Cause | System Handling |
|---|---|---|
| Ring Buffer Saturation | More results added than `max_results` | Oldest records evicted via FIFO order |
| Slow Event Consumer | Subscriber async task lagging behind producer | Event queue drops or raises `QueueFull` warning |
| API Query Parameter Invalid | Negative limit or malformed status string | HTTP API returns `400 Bad Request` |

---

## 9. Verification & Evidence Semantics

The storage and event pipeline does not alter evidence semantics. Records stored in `ResultStore` retain their original `evidence_status` (`local_diagnostic_verified`, `real_data_transfer_tested`, etc.) to guarantee auditing integrity across API queries.

---

## 10. Related Guides & Next Steps

- [Measurement Reporting & Formats](measurement-reporting.md) — Schemas of records saved to storage.
- [Architecture & Design](../architecture.md) — How the storage and event bus fit into the overall system.
- [CLI Reference Manual](../reference/cli.md) — CLI commands for generating measurement data.
