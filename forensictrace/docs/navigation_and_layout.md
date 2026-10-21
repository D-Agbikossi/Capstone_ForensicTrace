# Navigation and layout (CLI product)

Marking criterion *Navigation & layout* is written for graphical apps. For ForensicTrace, **navigation** means how a user (researcher/supervisor) finds their way through the product; **layout** means how information is structured and displayed.

## 1. Repository navigation (logical structure)

```
forensictrace/
├── README.md              Start here (features, usage)
├── Makefile               Build entry point
├── forensictrace          Runnable binary (after make)
├── src/                   Implementation by module
├── tests/run_tests.sh     Quality gate / smoke test
├── scenarios/             Incident demos (01–04)
├── scripts/               setup, demo, viewers
└── docs/                  Architecture, deployment, designs, examples
```

**Recommended path for a first-time user:**

1. Root [README.md](../../README.md) (submission overview)  
2. `scripts/setup.sh` (environment + tests)  
3. `./forensictrace --help`  
4. One trace command → `view_timeline.py` on JSON  

## 2. CLI command layout (consistent grammar)

All runs follow the same pattern:

```text
forensictrace --config <A|B|C|D> --output <file.json> [--verbose] -- <command> [args...]
```

| Flag | Purpose |
|------|---------|
| `--config` | Evidence profile (required) |
| `--output` | JSON path (required) |
| `--verbose` | Per-event log on stderr |
| `--` | Separates tool options from target command |
| `--help` | Usage on stderr, exit 0 |

Invalid input → usage message and exit code 1 (predictable errors).

## 3. Output layout (three channels)

| Channel | Content | User purpose |
|---------|---------|--------------|
| **stderr** | Run banner: config, output path, command; final byte count | Operational metadata |
| **stdout** | Reconstructed timeline table (fixed columns) | Primary “screen” for investigation |
| **Files** | `*.json` + `*.json.sha256` | Archival evidence and verification |

Timeline columns (stable layout):

```text
#     Delta(ms)  Type      PID      PPID     Syscall      Target
```

Empty capture → explicit `(no events captured)` (no blank confusion).

## 4. Secondary interfaces (analysis navigation)

| Tool | Input | Output layout |
|------|-------|----------------|
| `scripts/view_timeline.py` | JSON file | Condensed timeline text |
| `scripts/visualize_events.py` | JSON file | Counts by type (+ optional PNG) |

## 5. Evidence configurations (mental model)

Progressive disclosure of detail:

- **A** — process only (simplest view)  
- **B** — + files  
- **C** — + network  
- **D** — all syscalls (busiest view)  

Same command line; only `--config` changes — easy comparison during demos.

## 6. What to show markers in the video

- `./forensictrace --help`  
- One full trace showing **stderr banner + stdout table + sha256sum -c**  
- `view_timeline.py` reading the same JSON (consistent story)  

This demonstrates **clear, logical navigation** without a web UI.
