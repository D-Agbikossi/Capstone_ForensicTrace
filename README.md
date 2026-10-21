# ForensicTrace — Capstone Prototype (MVP)

**Author:** Denaton Agbikossi · **Supervisor:** Junior Turatsinze  
**GitHub:** https://github.com/D-Agbikossi/Capstone_ForensicTrace

ForensicTrace is a **Linux CLI** that traces a command with `ptrace`, records selected system calls, prints an incident timeline, and saves **JSON + SHA-256 sidecar**. Four evidence configs (A–D) and four lab scenarios support controlled experiments.

All code is in [`forensictrace/`](forensictrace/).

## Setup (markers / supervisor)

```bash
cd forensictrace
sudo apt install -y build-essential libssl-dev python3 curl   # once
make clean && make
chmod +x tests/run_tests.sh scenarios/*.sh scripts/*.sh
./tests/run_tests.sh          # expect: 16 passed
```

Or: `bash scripts/setup.sh`

## Try one trace

```bash
./forensictrace --config B --output /tmp/run.json -- /bin/ls /tmp
sha256sum -c /tmp/run.json.sha256
```

No sudo needed for normal use (child process tracing).

## Video demo

Follow **[VIDEO_DEMO_SCRIPT.md](VIDEO_DEMO_SCRIPT.md)** or run:

```bash
cd forensictrace && bash scripts/demo.sh
```

## What to push (Git)

| Include | Exclude (gitignored / generated) |
|---------|----------------------------------|
| `forensictrace/Makefile` | `forensictrace/forensictrace` (binary) |
| `forensictrace/src/*.c`, `*.h` | `*.o`, `.test_out/` |
| `tests/`, `scenarios/`, `scripts/` | binary, `*.o`, `.test_out/` |
| `docs/`, this README | Duplicate **`MakeFIle`** (removed — use **`Makefile` only**) |

## Designs and docs

| Doc | Path |
|-----|------|
| Deployment | [forensictrace/docs/deployment.md](forensictrace/docs/deployment.md) |
| Architecture | [forensictrace/docs/architecture.md](forensictrace/docs/architecture.md) |
| Marking rubric map | [MARKING_RUBRIC.md](MARKING_RUBRIC.md) |
| Sample output | [forensictrace/docs/examples/](forensictrace/docs/examples/) |

## Repository layout

```
Capstone_ForensicTrace/
├── README.md
├── VIDEO_DEMO_SCRIPT.md
└── forensictrace/
    ├── Makefile          ← only build file
    ├── src/
    ├── tests/
    ├── scenarios/
    └── scripts/
```
