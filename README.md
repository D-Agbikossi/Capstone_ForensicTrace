# ForensicTrace — Capstone Prototype (MVP)

**Author:** Denaton Agbikossi · BSc Software Engineering · September 2026  
**Supervisor:** Junior Turatsinze

## Description

ForensicTrace is a **C/Linux executable prototype** that monitors a target program with
`ptrace`, records selected system calls (process, file, network), correlates events,
reconstructs a **human-readable incident timeline**, and saves each run as **JSON** with a
**SHA-256 integrity sidecar**. It supports four evidence configurations (A–D) and four
controlled security scenarios for repeatable experiments.

This repository is the **initial product version (MVP)** for supervisor review—not a
production SIEM or enterprise DFIR platform.

**GitHub repository:** https://github.com/D-Agbikossi/Capstone_ForensicTrace

All application source, build files, tests, and scenarios live in the [`forensictrace/`](forensictrace/) directory.

**Marking criteria (15 pts):** see [MARKING_RUBRIC.md](MARKING_RUBRIC.md) — maps rubric → repo evidence and demo.

## Environment setup and project build

### Quick setup (recommended for markers)

```bash
cd forensictrace
bash scripts/setup.sh
```

This installs dependencies, builds, and runs all 13 acceptance tests.

### Prerequisites (Ubuntu 22.04 / Debian 12, x86_64)

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev python3 curl
# Optional: valgrind (memory checks), matplotlib (PNG charts)
sudo apt install -y valgrind python3-matplotlib
```

### Build and verify

```bash
cd forensictrace
make clean && make
chmod +x tests/run_tests.sh scenarios/*.sh scripts/*.sh
./tests/run_tests.sh
```

Expected: **13 tests passed**.

### Run one trace

```bash
./forensictrace --config B --output /tmp/run.json -- /bin/ls /tmp
sha256sum -c /tmp/run.json.sha256
python3 scripts/view_timeline.py /tmp/run.json
```

See [forensictrace/README.md](forensictrace/README.md) for configuration details and CLI options.

**Requirements & tools (rubric):** [forensictrace/docs/requirements_and_tools.md](forensictrace/docs/requirements_and_tools.md)  
**Navigation & layout (CLI rubric):** [forensictrace/docs/navigation_and_layout.md](forensictrace/docs/navigation_and_layout.md)

## Designs (architecture, data model, sample outputs)

| Artifact | Location |
|----------|----------|
| Architecture overview | [forensictrace/docs/architecture.md](forensictrace/docs/architecture.md) |
| Component & data-flow diagrams | [forensictrace/docs/designs/system_design.md](forensictrace/docs/designs/system_design.md) |
| Entity-relationship (experiment data) | [forensictrace/docs/erd.md](forensictrace/docs/erd.md) |
| Sample JSON experiment | [forensictrace/docs/examples/demo_scenario04.json](forensictrace/docs/examples/demo_scenario04.json) |
| Sample timeline output | [forensictrace/docs/examples/demo_timeline.txt](forensictrace/docs/examples/demo_timeline.txt) |

**Screenshots for submission:** Capture terminal output while running the commands in
[VIDEO_DEMO_SCRIPT.md](VIDEO_DEMO_SCRIPT.md) (timeline table, test suite, integrity check,
optional chart from `visualize_events.py`). Place PNGs in `forensictrace/docs/designs/screenshots/` before zipping.

## Deployment plan

Lab deployment steps (single Linux host, local JSON storage, no cloud):

1. **Prepare host** — Ubuntu 22.04 VM or physical machine; install dependencies (above).
2. **Build** — `make` in `forensictrace/`; confirm `./tests/run_tests.sh` passes.
3. **Operate** — Run `./forensictrace --config <A|B|C|D> --output <path> -- <command>` for each experiment.
4. **Batch runs** — `./scripts/run_all_experiments.sh` writes 64 JSON files + `experiments/manifest.csv`.
5. **Verify evidence** — `sha256sum -c <file>.json.sha256` after each run or before analysis.
6. **Analyze** — `view_timeline.py` and `visualize_events.py` on exported JSON.

Full operational notes: [forensictrace/docs/deployment.md](forensictrace/docs/deployment.md).

## Security measures (prototype)

Summary: [forensictrace/docs/security.md](forensictrace/docs/security.md)

- **Evidence integrity:** SHA-256 hash sidecar per JSON file (`sha256sum -c` compatible).
- **Controlled collection:** Traces only a **child process** started by the tool; no remote exfiltration in MVP.
- **Authorised use:** Intended for **controlled lab scenarios** only (see scenario scripts).
- **Process isolation:** `PTRACE_O_EXITKILL` so tracees terminate if the tracer exits unexpectedly.

## Video demo (5–10 minutes)

Record a screen capture following **[VIDEO_DEMO_SCRIPT.md](VIDEO_DEMO_SCRIPT.md)**. Focus on **live functionality** (build, trace, configs A vs B, scenario, integrity, tests)—not the research literature.

## Repository layout

```
Capstone_ForensicTrace/
├── README.md                 ← this file (submission overview)
├── VIDEO_DEMO_SCRIPT.md      ← demo recording guide
├── forensictrace/
│   ├── forensictrace         ← binary (after make)
│   ├── src/                  ← C source
│   ├── scenarios/            ← four incident scripts
│   ├── scripts/              ← batch runner, visualization
│   ├── tests/run_tests.sh    ← automated acceptance tests
│   └── docs/                 ← architecture, deployment, designs, examples
```

## Code files

Primary implementation: `forensictrace/src/*.c`, header `forensictrace/src/forensictrace.h`, build via `forensictrace/Makefile`.

## Packaging for submission

From the repository root:

```bash
git archive -o ForensicTrace-prototype.zip HEAD
# Or zip manually, excluding .git and build artifacts:
# cd forensictrace && make clean && cd ..
# zip -r ForensicTrace-prototype.zip . -x '*.git*' 'forensictrace/.test_out/*'
```

Include your **recorded demo video** separately if the LMS does not accept it inside the zip.
