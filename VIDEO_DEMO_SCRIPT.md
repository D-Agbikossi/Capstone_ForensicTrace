# ForensicTrace video demo — read-aloud script (5–8 minutes)

This script is written to be read while recording. Text under **Say** is the
narration; text under **On screen** is what to do in the terminal. Pause after
each command so the output is visible before continuing.

## Before recording

Open a terminal with a large font and go to the application directory:

```bash
cd ~/Documents/Capstone/Capstone_ForensicTrace/forensictrace
```

Do not run the demo under `strace` or a debugger; ForensicTrace needs to use
`ptrace` itself. The demo traces commands you start locally.

## 1. Introduction

**On screen:** Show the terminal in the `forensictrace` directory.

**Say:**

> “Hello. In this video, I’m demonstrating ForensicTrace, a Linux command-line
> prototype for collecting and reviewing system activity. I’ll build and test
> it, trace a command, verify the saved evidence, compare two capture
> configurations, and finish with a controlled file-tampering scenario.”

## 2. Build and run the tests

**On screen:** Run:

```bash
make clean && make
./tests/run_tests.sh
```

Wait for the test results to finish.

**Say:**

> “First, I’m building the program with Make. The build uses the Makefile in
> this directory. Next, I’m running the acceptance tests to check that the
> program’s main features work. The test results are shown here.”

**On screen:** Pause with the final test summary visible.

**Say:**

> “The tests have completed. This gives us a basic check of the build and the
> behavior we’re about to demonstrate.”

## 3. Show the command-line options

**On screen:** Run:

```bash
./forensictrace --help
```

**Say:**

> “Here is the command-line interface. Each capture specifies a configuration
> and an output file. The double dash separates ForensicTrace’s options from
> the command I want it to trace. The configurations are cumulative: A captures
> process activity, B adds file activity, C adds network activity, and D
> captures all syscalls.”

## 4. Capture and view a trace

**On screen:** Run:

```bash
mkdir -p /tmp/forensictrace_demo
./forensictrace --config B --output /tmp/forensictrace_demo/ls.json -- /bin/ls /tmp
```

Pause to show the output. Then run:

```bash
sha256sum -c /tmp/forensictrace_demo/ls.json.sha256
python3 scripts/view_timeline.py /tmp/forensictrace_demo/ls.json | head -15
```

**Say:**

> “I’m now tracing the `ls` command with configuration B, which includes file
> activity. The results are saved as JSON, and the program also creates a
> SHA-256 checksum sidecar. I’m checking the checksum first; a successful
> result confirms that this JSON file matches its recorded checksum.”
>
> “Next, I’m opening the same trace with the timeline viewer. The events are
> presented in a compact, readable form so I can inspect what happened during
> the command.”

## 5. Compare configurations A and B

**On screen:** Run:

```bash
./forensictrace --config A --output /tmp/forensictrace_demo/a.json -- /bin/ls /tmp >/dev/null
./forensictrace --config B --output /tmp/forensictrace_demo/b.json -- /bin/ls /tmp >/dev/null
python3 -c "
import json
for k in 'AB':
    with open(f'/tmp/forensictrace_demo/{k.lower()}.json') as f:
        data = json.load(f)
    files = sum(1 for event in data['events'] if event['type'] == 'file')
    print(f\"Config {k}: events={data['event_count']} file={files}\")
"
```

**Say:**

> “For this comparison, I’m tracing the same command twice. The only thing I’m
> changing is the configuration. The summary shows the total events and file
> events recorded by each run. Configuration A focuses on process activity;
> configuration B also includes file activity. This makes it possible to
> compare how much evidence each configuration captures.”

**On screen:** Pause with the two summary lines visible.

## 6. Run a controlled scenario

**On screen:** Run:

```bash
./forensictrace --config B --output /tmp/forensictrace_demo/scenario4.json -- bash scenarios/scenario04_file_corruption.sh
python3 scripts/view_timeline.py /tmp/forensictrace_demo/scenario4.json | grep -E 'write|unlink|open' | head -10
```

**Say:**

> “Finally, I’m running scenario four, a controlled demonstration of file
> corruption. The scenario performs file operations, and I’m filtering the
> timeline to highlight events such as opening, writing, and deleting files.
> This is a lab scenario for demonstrating how activity can be recorded and
> reviewed.”

## 7. Closing

**On screen:** Show the final timeline output, then the output directory:

```bash
ls -1 /tmp/forensictrace_demo
```

**Say:**

> “That concludes the demonstration. ForensicTrace collects system activity,
> reconstructs it into a timeline, saves the results as JSON, and provides a
> checksum for verification. We’ve also compared evidence configurations and
> reviewed a controlled scenario. Thank you for watching.”

## Recording checklist

- [ ] Keep the terminal text readable and pause so important output can be seen.
- [ ] Show the build, test summary, trace, checksum verification, and scenario.
- [ ] Run the demo directly in the terminal, not under another tracer.
- [ ] Confirm the repository link in the README before recording.
- [ ] If packaging the project, include `forensictrace/Makefile`, not `MakeFIle`.
