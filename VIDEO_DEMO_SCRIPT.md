# ForensicTrace — video demo script (5–10 minutes)

**Goal:** Show the prototype working. Minimal research background; maximum live commands and output.

**Suggested length:** 6–8 minutes.

---

## Before recording

```bash
cd forensictrace
make clean && make
chmod +x tests/run_tests.sh scenarios/*.sh scripts/*.sh
```

Terminal: large font, clear prompt. Close unrelated notifications.

---

## 1. What it is (30 seconds)

Say briefly:

> “ForensicTrace is a Linux tool I run from the command line. It attaches to a program, records selected system calls, prints a forensic timeline, and saves JSON plus a SHA-256 hash file.”

Show: `ls src/` or project tree—do not read the thesis problem statement.

---

## 2. Environment setup and tests (1 minute)

```bash
bash scripts/setup.sh
```

Or manually: `make && ./tests/run_tests.sh`

Highlight: **13 passed** — satisfies *development environment setup* and *requirements* rubric lines.

---

## 3. CLI navigation — help and layout (30 seconds)

```bash
./forensictrace --help
```

Point out: fixed command pattern, config A–D, where timeline (stdout) vs metadata (stderr) appear.

## 4. Single command trace — Config B (1.5 minutes)

```bash
./forensictrace --config B --output /tmp/demo_ls.json --verbose -- /bin/ls /tmp
```

Point out on screen:

- stderr: config, output path, command
- stdout: **Reconstructed Timeline** table (process + file events)
- stderr: event count and bytes written

```bash
sha256sum -c /tmp/demo_ls.json.sha256
python3 scripts/view_timeline.py /tmp/demo_ls.json
```

Say: “The sidecar detects tampering if the JSON is edited.”

(Optional: `echo x >> /tmp/demo_ls.json` then show `sha256sum -c` **FAILED**.)

---

## 5. Evidence configurations A vs B (1 minute)

```bash
./forensictrace --config A --output /tmp/demo_a.json -- /bin/ls /tmp >/dev/null
./forensictrace --config B --output /tmp/demo_b.json -- /bin/ls /tmp >/dev/null
python3 -c "import json;a=json.load(open('/tmp/demo_a.json'));b=json.load(open('/tmp/demo_b.json'));print('A events',a['event_count'],'file',sum(1 for e in a['events'] if e['type']=='file'));print('B events',b['event_count'],'file',sum(1 for e in b['events'] if e['type']=='file'))"
```

Explain: **A** = process only; **B** adds file activity—same command, different evidence set.

---

## 6. Controlled scenario — file corruption (1.5 minutes)

```bash
./forensictrace --config B --output /tmp/demo_s4.json -- bash scenarios/scenario04_file_corruption.sh
```

Scroll timeline: **open**, **write**, **unlink** pattern.

Or use scenario 1 for network + exec (needs `curl`):

```bash
./forensictrace --config C --output /tmp/demo_s1.json -- bash scenarios/scenario01_download_execute.sh
```

Mention: multiple **execve** (download, chmod, run payload).

---

## 7. Visualization (1 minute)

If matplotlib installed:

```bash
python3 scripts/visualize_events.py /tmp/demo_b.json -o /tmp/events_by_type.png
```

Show the PNG (event counts by type). If not installed, skip and use `view_timeline.py` only.

---

## 8. Batch experiments (45 seconds)

```bash
./scripts/run_all_experiments.sh
head experiments/manifest.csv
ls experiments/*.json | wc -l
```

Say: “The runner supports the full experiment matrix for later evaluation.”

---

## 9. Close (20 seconds)

> “This MVP delivers collect → correlate → reconstruct → persist → verify. Next steps in the project are resource metrics and scoring against ground truth—not shown here.”

---

## Checklist before upload

- [ ] Video length 5–10 minutes  
- [ ] Shows real terminal output, not slides only  
- [ ] Shows timeline + JSON integrity  
- [ ] Shows at least one scenario script  
- [ ] Repo link in submission README matches GitHub  
