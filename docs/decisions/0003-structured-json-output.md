# 0003. Structured JSON Output

## Context

ConnScope performs network measurements via `ProbeEngine` and previously exposed them exclusively through human-readable CLI output (Phase 3). To enable automation, scripting, and future API/agent integrations, measurement results must be reliably machine-readable without coupling serialization logic to Core domain models or Probe implementations.

## Decision

We establish the following structured JSON output contract and architecture:

1. **Presentation-Layer Serialization**:
   Serialization logic lives in `src/connscope/cli/output.py` (`result_to_dict` and `render_result_json`).
   The Core layer (`models.py`, `engine.py`, `registry.py`) and Probe implementations remain completely decoupled from JSON rendering. No serialization methods are added to `ProbeResult`.

2. **JSON Field Contract**:
   The output JSON object contains exactly these top-level fields:
   - `probe`: string canonical probe name.
   - `target`: object containing `host` (string) and `port` (integer or `null`).
   - `status`: string representation of `ProbeStatus` (`"success"`, `"failed"`, `"timeout"`).
   - `started_at`: ISO 8601 string with an explicit timezone offset (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`).
   - `duration_ms`: finite float measurement duration in milliseconds.
   - `metrics`: dictionary of numeric measurements (empty object `{}` if no metrics).
   - `details`: dictionary of probe-specific details (empty object `{}` if no details).
   - `error`: error string if status is failed/timeout, otherwise `null`.

3. **Schema Versioning**:
   No `schema_version` field is added at this stage. The JSON shape directly mirrors the Core `ProbeResult` value object. Adding versioning machinery now would be premature abstraction.

4. **Supported Values and Strict Rejection**:
   - Supported values in metrics and details: strings, integers, finite floats, booleans, `null`, lists, and dictionaries with string keys.
   - Non-finite numbers (`NaN`, `Infinity`, `-Infinity`) are strictly rejected with an explicit error to prevent emitting non-standard JSON tokens.
   - Timezone-naive timestamps are strictly rejected to prevent emitting ambiguous timestamps.
   - Arbitrary unsupported objects are rejected with clear type errors without generic string fallbacks.

5. **Deterministic Serialization**:
   JSON is emitted using standard-library `json.dumps` with `indent=2`, `ensure_ascii=False`, `allow_nan=False`, and `sort_keys=True`.
   Serialization never mutates original `ProbeResult`, `metrics`, or `details` instances.

6. **Output Streams and Exit Codes**:
   - `stdout` receives pure, valid JSON on completed measurements (success, failure, timeout).
   - `stderr` receives operational diagnostic messages for usage errors (exit code 3) and internal/serialization errors (exit code 4), leaving `stdout` completely empty.
   - Exit codes remain identical between text and JSON modes:
     - `0`: Successful measurement (`ProbeStatus.SUCCESS`)
     - `1`: Failed measurement (`ProbeStatus.FAILED`)
     - `2`: Timed-out measurement (`ProbeStatus.TIMEOUT`)
     - `3`: Usage error (syntax error, missing port, unknown probe)
     - `4`: Unexpected internal or serialization error

## Consequences

- Programs can pipe `connscope run ... --json` directly into `jq`, Python `json.loads()`, or other JSON processors.
- Measurement failures (`FAILED`) and timeouts (`TIMEOUT`) remain fully structured results on `stdout`, paired with exit codes 1 and 2.
- Future frontends (Remote Agent in Phase 5, Storage in Phase 7, API in Phase 8) have an unambiguous schema contract while Core contracts remain clean and unencumbered.
