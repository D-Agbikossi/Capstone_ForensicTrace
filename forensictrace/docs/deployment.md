# ForensicTrace — deployment and operation

## Environment

- **OS:** Ubuntu 22.04 LTS or Debian 12 (x86_64)
- **Packages:** `build-essential`, `libssl-dev`, `python3`, `curl`
- **User:** Same UID as traced processes (child tracing via `fork` + `exec`)

Install dependencies (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev python3 curl
```

## Build

```bash
git clone <repo>
cd forensictrace
make clean && make
```

Verify no compiler warnings:

```bash
make clean && make 2>&1 | grep -i warning && exit 1 || echo OK
```

## Run a single experiment

```bash
./forensictrace --config B --output experiments/sample.json -- /bin/ls
```

Outputs:

1. Timeline on **stdout**
2. Metadata on **stderr**
3. JSON at `--output`
4. Sidecar at `<output>.sha256`

Verify integrity:

```bash
sha256sum -c experiments/sample.json.sha256
```

## Batch experiments

```bash
chmod +x scripts/run_all_experiments.sh scenarios/*.sh
./scripts/run_all_experiments.sh
```

Results land in `experiments/` with `manifest.csv`.

## ptrace permissions

If collection records zero events and `PTRACE_TRACEME` fails with `EPERM`:

- Do not run under another tracer (`strace`, `gdb`) on the same process tree
- Check YAMA: `cat /proc/sys/kernel/yama/ptrace_scope` (0 = permissive, 1 = restricted)
- For lab VMs only, an admin may temporarily set `ptrace_scope=0`

ForensicTrace traces a **child** it creates; this works with `ptrace_scope=1` when
the tracer is the parent.

## Operational notes

- One monitored host, one target command line per run
- JSON files are the unit of analysis; copy with sidecars for archival
- Re-run `sha256sum -c` after any file transfer to detect tampering
- Scenario scripts use local HTTP ports **8765** and **8766**; ensure they are free

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| 0 events, exit 0 | Wrong `PTRACE_GETREGS` request or trace blocked |
| Immediate exit 127 under `strace` | Nested tracer; test binary directly |
| Scenario curl fails | Port in use or slow start; increase sleep in script |
| `sha256sum` FAILED | JSON edited after run; re-run experiment |
