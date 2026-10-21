# ForensicTrace architecture (MVP)

## Overview

ForensicTrace is a single-host research prototype. The researcher runs the
`forensictrace` CLI against a target command; the tool attaches with `ptrace`,
collects syscalls according to evidence configuration A–D, correlates events,
prints a timeline, and writes JSON plus a SHA-256 sidecar.

```
CLI (main.c)
  → collector (ptrace loop)
  → normaliser (MVP no-op)
  → correlator (PID lookback)
  → reconstructor (stdout timeline)
  → json_writer + integrity (disk)
```

## Components

| Module | Role |
|--------|------|
| `main.c` | Argument parsing, `FTContext` lifecycle, pipeline orchestration |
| `collector.c` | Fork/exec tracee, syscall stops, classification, config filter |
| `normaliser.c` | Placeholder for future path canonicalisation |
| `correlator.c` | Same-PID chain + cross-process link to parent fork/clone/execve |
| `reconstructor.c` | Human-readable table on stdout |
| `json_writer.c` | Experiment JSON schema |
| `integrity.c` | OpenSSL SHA-256 sidecar in `sha256sum` format |

## Data model

In-memory `Event` records (see `forensictrace.h`) are appended during collection,
then enriched with `parent_event` indices before export. JSON includes `truncated`
when the 20,000-event cap drops further syscalls. Output paths get parent
directories created automatically; failed writes exit non-zero.

## Trust boundary

Evidence is produced and stored locally. Integrity checking is file-level (whole
JSON hash), not a per-event chain (future work).

See also the capstone ERD in [erd.md](erd.md).
