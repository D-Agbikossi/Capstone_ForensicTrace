# ForensicTrace (application)

> Submission overview and demo script: [../README.md](../README.md) and [../VIDEO_DEMO_SCRIPT.md](../VIDEO_DEMO_SCRIPT.md)

C/Linux prototype: `ptrace` syscall collection → correlation → timeline → JSON + SHA-256 sidecar.

## Quick start

```bash
make clean && make
chmod +x tests/run_tests.sh scenarios/*.sh scripts/*.sh
./tests/run_tests.sh
```

Record the demo:

```bash
bash scripts/demo.sh
```

## Usage

```bash
./forensictrace --config B --output /tmp/run.json -- /bin/ls /tmp
sha256sum -c /tmp/run.json.sha256
python3 scripts/view_timeline.py /tmp/run.json
```

## Evidence configurations

| Config | Records |
|--------|---------|
| A | Process syscalls only |
| B | A + file syscalls |
| C | B + network syscalls |
| D | All syscalls |

## Build

Use **`Makefile`** in this directory (`make`). There is only one build file — do not use a duplicate `MakeFIle`.

## Project layout

```
src/          C source (collector, correlator, reconstructor, …)
tests/        run_tests.sh — 16 acceptance checks
scenarios/    Four controlled incident scripts
scripts/      setup.sh, demo.sh, viewers
docs/         Architecture, deployment, designs
```

## Documentation

- [docs/deployment.md](docs/deployment.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/requirements_and_tools.md](docs/requirements_and_tools.md)
- [docs/navigation_and_layout.md](docs/navigation_and_layout.md)
- [docs/security.md](docs/security.md)

## Ethics

Lab use only — controlled scenarios on authorised systems.
