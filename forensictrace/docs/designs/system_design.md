# ForensicTrace — system design (prototype)

## High-level architecture

```mermaid
flowchart TB
    subgraph CLI
        M[main.c]
    end
    subgraph Pipeline
        COL[collector.c\nptrace syscall capture]
        NORM[normaliser.c\nMVP pass-through]
        COR[correlator.c\nPID lookback]
        REC[reconstructor.c\nstdout timeline]
        JSON[json_writer.c]
        INT[integrity.c\nSHA-256 sidecar]
    end
    subgraph Target
        T[User command\nexec via fork]
    end
    M --> COL
    COL --> NORM --> COR --> REC
    COR --> JSON --> INT
    COL -.->|PTRACE_SYSCALL| T
    JSON --> F[(experiment.json)]
    INT --> H[(experiment.json.sha256)]
```

## Module interaction

| From | To | Data |
|------|-----|------|
| `main.c` | `collector.c` | argv, `FTContext` |
| `collector.c` | memory | `Event[]`, timestamps, syscall metadata |
| `correlator.c` | memory | `parent_event[]` indices |
| `reconstructor.c` | stdout | formatted timeline |
| `json_writer.c` | disk | JSON experiment file |
| `integrity.c` | disk | hash sidecar |

## Evidence configuration flow

```mermaid
flowchart LR
    SC[Syscall stop] --> CL[classify type]
    CL --> CF{config A/B/C/D}
    CF -->|accept| EV[append Event]
    CF -->|reject| SK[skip]
    EV --> OUT[correlate + export]
```

## CLI data flow

```
forensictrace --config B --output run.json -- <command>
        │
        ├─► stderr: run metadata
        ├─► stdout: reconstructed timeline
        └─► files: run.json, run.json.sha256
```

Figures in the capstone report (Figures 3–8) match this structure; use terminal
screenshots of the running CLI as **interface evidence** for submission.
