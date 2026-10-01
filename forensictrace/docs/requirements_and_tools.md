# Project requirements and development tools

This document maps **prototype assignment requirements** to **what was built** and **which tools were chosen**, for marking criterion *Review requirements & tools*.

## Functional requirements (MVP) — implemented

| ID | Requirement | Implementation |
|----|-------------|----------------|
| R1 | Trace target via `ptrace` | `collector.c` — `PTRACE_SYSCALL`, fork follow |
| R2 | Configurable evidence sets A–D | `ft_config_accepts()` in `collector.c` |
| R3 | Normalize events | Structured in collector; `normaliser.c` (MVP pass-through) |
| R4 | Correlate by PID | `correlator.c` — 200-event lookback |
| R5 | Reconstruct timeline | `reconstructor.c` → stdout table |
| R6 | Persist JSON experiment | `json_writer.c` |
| R7 | Integrity hash | `integrity.c` — SHA-256 sidecar |
| R8 | CLI | `main.c` — `--config`, `--output`, `--verbose`, `--` |
| R9 | Controlled scenarios | `scenarios/scenario01–04*.sh` |
| R10 | Automated verification | `tests/run_tests.sh` (13 checks) |

Full MVP specification is reflected in code comments, tests, and `tests/run_tests.sh` pass criteria.

## Non-functional requirements — addressed

| NFR | Approach |
|-----|----------|
| Modular C | Separate compilation units per pipeline stage |
| Reproducible builds | `Makefile`, `-Wall -Wextra` |
| Linux 5.x+ | Standard ptrace API, x86_64 syscalls |
| Local-only evidence | JSON on disk, no network export in MVP |

## Development tools (selection rationale)

| Tool | Role | Why this choice |
|------|------|-----------------|
| **C11 + GCC** | Core product | Low-level access to `ptrace`, fits Linux DFIR research scope |
| **GNU Make** | Build | Simple, universal in academic/lab Linux environments |
| **Linux ptrace** | Collection | MVP scope: no kernel module/eBPF complexity |
| **OpenSSL (libcrypto)** | SHA-256 | Standard, fast, compatible with `sha256sum` |
| **Python 3** | Analysis helpers | JSON viewing and charts without bloating the C core |
| **Git / GitHub** | Version control | Submission zip from repo; supervisor can clone |
| **curl** | Scenarios/tests | HTTP steps in download/network scenarios |
| **Valgrind** (optional) | Quality | Memory leak checks documented in README |
| **Lucidchart / Mermaid** | Design docs | Architecture in `docs/designs/` |

## Out of scope (explicit)

Kernel modules, eBPF, GUI, database, cloud deployment, enterprise SIEM features — documented in README limitations so scope matches requirements.
