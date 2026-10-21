# How this repository meets the prototype marking criteria (15 pts)

ForensicTrace is a **CLI software prototype** (not a website). The table below maps each rubric line to **evidence in this repo** and **what to show in the demo video**.

| Criterion (15 pts) | Target band | Where the evidence lives | What to demonstrate (video / zip) |
|--------------------|-------------|---------------------------|-----------------------------------|
| **Review requirements & tools** (5) | Excellent | [forensictrace/docs/requirements_and_tools.md](forensictrace/docs/requirements_and_tools.md) — FR/NFR ↔ modules; tools table with rationale | Briefly show `src/` modules matching pipeline; run `tests/run_tests.sh` (requirements verified automatically) |
| **Development environment setup** (5) | Excellent | Root [README.md](README.md) § setup; [forensictrace/docs/deployment.md](forensictrace/docs/deployment.md); **`forensictrace/scripts/setup.sh`** | Run `bash forensictrace/scripts/setup.sh` on Ubuntu: install deps → build → 16 tests pass |
| **Navigation & layout** (5) | Excellent | [forensictrace/docs/navigation_and_layout.md](forensictrace/docs/navigation_and_layout.md); CLI `--help`; fixed timeline columns | Show `--help`, one trace (stderr + stdout table), `view_timeline.py` on same JSON |

## Checklist before submission

- [ ] GitHub link in README works and matches zip contents  
- [ ] `setup.sh` or README steps work on a **clean** Ubuntu VM  
- [ ] Screenshots in `forensictrace/docs/designs/screenshots/` (timeline, tests, integrity)  
- [ ] Video 5–10 min: **functionality first** ([VIDEO_DEMO_SCRIPT.md](VIDEO_DEMO_SCRIPT.md))  
- [ ] Optional: mention this file in cover email so markers know where to look  

## Expected self-assessment

If setup and tests pass on marker’s machine and the video follows the script, all three criteria align with **Excellent (5 / 5 / 5)** for a command-line prototype.
