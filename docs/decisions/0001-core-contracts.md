# 0001. Core Contracts

## Context

ConnScope needs a stable foundational layer (Core) that defines what a network measurement is, how it executes, and what it returns. This layer must remain independent of specific network protocols, configuration formats, and user interfaces (CLI, GUI, Agent). 

We need to establish the basic abstractions for Phase 1 before building actual probes.

## Decision

We establish the following Core abstractions:

1. **Target**: A frozen value object representing the destination being tested (`host`, optional `port`). Validates that `host` is not empty and `port` is within valid bounds.
2. **ProbeResult**: A frozen value object representing the normalized output of a measurement. Contains the target, status (success, failed, timeout), duration, and isolated mutable dictionaries for metrics and details.
3. **Probe**: An abstract base class (`ABC`) that specific network measurements will implement. Defines a single `async def run(target, config)` method, reflecting that network I/O is inherently asynchronous.
4. **ProbeRegistry**: A central directory that maps string names to `Probe` implementations. Ensures uniqueness and explicit registration.
5. **ProbeEngine**: The orchestrator that resolves a probe name via the registry and executes it against a target, forwarding any provided configuration. It is deliberately minimal and does not currently manage concurrency.

## Consequences

- All future probes (Phase 2+) must conform to the `Probe` ABC and return `ProbeResult`.
- Frontends (CLI, APIs) will interact exclusively with the `ProbeEngine`, shielding them from probe implementation details.
- The use of `async` for `run` dictates that the runtime environment must provide an asyncio event loop.
- The flexible `config: dict[str, Any]` parameter defers the need for a rigid configuration schema until patterns emerge from concrete probe implementations.
