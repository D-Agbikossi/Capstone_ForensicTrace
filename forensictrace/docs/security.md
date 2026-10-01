# ForensicTrace — security measures (MVP)

This prototype is a **research instrument**, not a certified forensic product.
The measures below support **integrity**, **controlled operation**, and **safe lab use**.

## Evidence integrity

- Each experiment JSON is hashed with **SHA-256** (OpenSSL) after write.
- Sidecar format matches GNU `sha256sum` so reviewers can run:
  `sha256sum -c experiment.json.sha256`
- Any post-collection edit to the JSON causes verification to **fail** (tamper detection).

## Collection boundary

- ForensicTrace only traces a process tree it **starts** via `fork` + `exec` in the child
  after `PTRACE_TRACEME`.
- There is **no network upload** of evidence in the MVP; storage is **local JSON** only.
- Configurations **A–D** deliberately limit which syscalls are stored (data minimisation for experiments).

## Runtime safety

- **`PTRACE_O_EXITKILL`:** If the tracer crashes or is killed, traced processes are killed
  rather than left suspended indefinitely.
- Tracee table is bounded (`FT_MAX_TRACEES`, `FT_MAX_EVENTS`) to avoid unbounded memory use
  during buggy or noisy workloads.

## Authorisation and ethics

- Scenario scripts simulate incidents in **temporary directories**; they must be run only on
  systems you are authorised to use.
- Reading `/etc/shadow` in scenario 02 is an **attempt** that may fail; it is included to
  model privilege-related activity in a lab, not to exfiltrate credentials.

## Threats not covered in MVP

- No encryption at rest for JSON files (filesystem protection is assumed).
- No per-event hash chain (whole-file hash only).
- No protection against a **root attacker** altering files and sidecars together.
- `ptrace` is not stealthy and is not intended for covert monitoring.

Future work may add per-event chaining and resource accounting; see thesis scope.
