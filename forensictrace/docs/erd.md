# ForensicTrace — experimental data model (ERD summary)

Logical entities for stored experiments (JSON + manifest), aligned with capstone Figure 4.

```mermaid
erDiagram
    SCENARIO ||--o{ EXPERIMENT : generates
    CONFIGURATION ||--o{ EXPERIMENT : uses
    EXPERIMENT ||--|{ EVENT : contains
    EXPERIMENT ||--|| RECONSTRUCTION : yields
    EXPERIMENT ||--|| RESOURCE_METRIC : measures
    EXPERIMENT ||--|| INTEGRITY : has
    EVENT }o--o| PROCESS : references
    EVENT }o--o| FILE : references
    EVENT }o--o| NETWORK : references

    SCENARIO {
        string id
        string script_path
    }
    CONFIGURATION {
        string code
        string description
    }
    EXPERIMENT {
        string output_path
        int event_count
        int64 duration_ns
    }
    EVENT {
        int id
        int64 ts_ns
        string type
        string syscall
        int pid
        int ppid
        int parent_event
    }
    INTEGRITY {
        string sha256_hex
        string sidecar_path
    }
```

**MVP implementation:** One JSON file embeds `config`, `event_count`, `duration_ns`, and
`events[]`. `parent_event` is filled by the correlator. `INTEGRITY` is stored as a separate
`.sha256` file, not inside JSON.
