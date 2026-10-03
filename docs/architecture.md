# ConnScope Architecture

```text
Frontends
    |
    v
Core
    |
    +--> Probe Engine
    +--> Registry
    +--> Configuration
    +--> Result Processing
    +--> Scheduler
    |
    v
Probes
    |
    v
Transports
    |
    v
Targets / Remote Nodes
```

The core must remain independent from any specific frontend.
