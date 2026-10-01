# ForensicTrace (application)

> **Submission overview, GitHub link, demo script, and zip instructions:** see the [repository root README](../README.md).

C/Linux research prototype for controlled cyber incident reconstruction using
`ptrace`-based system call collection. ForensicTrace is the experimental
instrument for studying **evidence sufficiency** and **resource trade-offs** in
Linux incident reconstruction (BSc capstone, Software Engineering).

## Features (MVP)

- Attach to a target command via `ptrace(PTRACE_SYSCALL)`
- Follow `fork` / `vfork` / `clone` children
- Four evidence configurations (A–D): process-only through full syscall capture
- Normalize, correlate (PID lookback), reconstruct timeline to stdout
- Persist each run as JSON plus SHA-256 sidecar (`.sha256`)
- Four controlled scenario scripts and batch experiment runner

## Requirements

- Linux kernel 5.x+ (tested on Ubuntu 22.04 / Debian 12, x86_64)
- GCC, GNU Make, OpenSSL development libraries (`libssl-dev`)
- Python 3 (tests, `view_timeline.py`, scenarios)
- `curl` (network tests and scenarios)
- Permission to trace processes (`ptrace`); on some systems set
  `kernel.yama.ptrace_scope=0` or trace only child processes (default here)

## Build

```bash
cd forensictrace
make
```

## Usage

```bash
./forensictrace --config B --output /tmp/run.json --verbose -- /bin/ls /tmp
sha256sum -c /tmp/run.json.sha256
python3 scripts/view_timeline.py /tmp/run.json
```

Evidence configurations:

| Config | Scope |
|--------|--------|
| A | Process events (`execve`, `fork`, `exit`, …) |
| B | A + file syscalls (`open`, `read`, `write`, `unlink`, …) |
| C | B + network syscalls (`connect`, `sendto`, …) |
| D | All syscalls (including `syscall_N` for others) |

## Scenarios

```bash
chmod +x scenarios/*.sh scripts/*.sh
./forensictrace --config C --output /tmp/s1.json -- bash scenarios/scenario01_download_execute.sh
```

Run the full 4×4×4 experiment matrix (64 JSON files + manifest):

```bash
./scripts/run_all_experiments.sh
```

## Tests

```bash
chmod +x tests/run_tests.sh
./tests/run_tests.sh
```

Optional memory check:

```bash
valgrind --leak-check=full ./forensictrace --config A --output /tmp/vg.json -- /bin/true
```

## Limitations (MVP)

- Syscall exit return values are not recorded
- IPv6 endpoints may appear as `sockfd=N`
- Correlation uses a 200-event PID lookback window
- `normaliser.c` is a no-op; paths are not canonicalized
- High `ptrace` overhead (measured in later work, not hidden)

## Documentation

- [docs/architecture.md](docs/architecture.md)
- [docs/designs/system_design.md](docs/designs/system_design.md)
- [docs/deployment.md](docs/deployment.md)
- [docs/security.md](docs/security.md)
- [docs/erd.md](docs/erd.md)
- [docs/examples/](docs/examples/) — sample JSON and timeline output

## License / ethics

Use only on authorised systems and controlled lab scenarios. Do not deploy for
covert monitoring of real users without approval.
