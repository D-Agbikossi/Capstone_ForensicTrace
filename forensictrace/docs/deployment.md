# ForensicTrace — deployment guide

Follow these steps in order on **Ubuntu 22.04** or **Debian 12** (x86_64).

---

## Step 1 — Get the code

```bash
git clone https://github.com/D-Agbikossi/Capstone_ForensicTrace.git
cd Capstone_ForensicTrace/forensictrace
```

---

## Step 2 — Install tools (one time)

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev python3 curl
```

| Package | Why |
|---------|-----|
| `build-essential` | `gcc`, `make` |
| `libssl-dev` | SHA-256 sidecar |
| `python3` | Tests and `view_timeline.py` |
| `curl` | Scenario scripts |

---

## Step 3 — Build and test

**Option A — automatic (recommended)**

```bash
bash scripts/setup.sh
```

You should see `Setup complete` and **16 tests passed**.

**Option B — manual**

```bash
make clean && make
chmod +x tests/run_tests.sh scenarios/*.sh scripts/*.sh
./tests/run_tests.sh
```

Build uses **`Makefile`** in this folder (`make`). There is no `make install`.

---

## Step 4 — Run your first trace

```bash
./forensictrace --config B --output /tmp/run.json -- /bin/ls /tmp
```

| Part | Meaning |
|------|---------|
| `--config B` | Process + **file** syscalls (use `A`, `C`, or `D` to change scope) |
| `--output /tmp/run.json` | Where to save the experiment |
| `--` | End of ForensicTrace options |
| `/bin/ls /tmp` | Command to trace |

You do **not** need `sudo` for normal runs.

**Output**

- **Terminal:** timeline table  
- **Files:** `/tmp/run.json` and `/tmp/run.json.sha256`

---

## Step 5 — Check integrity and read the timeline

```bash
sha256sum -c /tmp/run.json.sha256
python3 scripts/view_timeline.py /tmp/run.json
```

If verification prints `FAILED`, the JSON was changed after the run — capture again.

Each JSON file includes `"truncated": true` if the run hit the 20,000-event cap (extra events were dropped).
Parent directories for `--output` are created automatically (e.g. `/tmp/my_run/out.json`).

---

## Step 6 — Run a lab scenario (optional)

```bash
./forensictrace --config B --output /tmp/scenario4.json -- bash scenarios/scenario04_file_corruption.sh
python3 scripts/view_timeline.py /tmp/scenario4.json
```

Other scripts: `scenarios/scenario01_download_execute.sh` (needs port **8765**), `scenario02_*`, `scenario03_*` (port **8766**).

---

## Step 7 — Record a demo (optional)

```bash
bash scripts/demo.sh
```

See [VIDEO_DEMO_SCRIPT.md](../../VIDEO_DEMO_SCRIPT.md) at the repo root.

---

## Config quick reference

| Config | What is recorded |
|--------|------------------|
| **A** | Process only (`execve`, `fork`, `exit`, …) |
| **B** | A + files (`open`, `read`, `write`, `unlink`, …) |
| **C** | B + network (`connect`, …) |
| **D** | All syscalls |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `make` fails | Install `build-essential` and `libssl-dev` |
| **0 events** | Do not run under `strace`, `gdb`, or the IDE debugger |
| Tests fail on scenario 1 | Install `curl`; free port **8765** |
| `PTRACE_TRACEME: Operation not permitted` | Close other tracers; trace only via `./forensictrace -- …` |

---

## Where files live

| Item | Location |
|------|----------|
| Binary (after build) | `./forensictrace` (not committed to Git) |
| Your traces | Any path you pass to `--output` (e.g. `/tmp/…`) |
| Helper scripts | `scripts/setup.sh`, `scripts/demo.sh`, `scripts/view_timeline.py` |
