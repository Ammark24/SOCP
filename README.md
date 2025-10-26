# Secure Chat (SOCP) — Group Cache Money
**Last updated:** 2025-10-26

This is our implementation of the class-standard SOCP overlay chat protocol.  
The **single supported entry point** is `run.py`. Older direct-entry scripts
(e.g., `server_single.py`, ad-hoc client launchers) are **deprecated** and kept only
for comparison in the appendix/vulnerable area.

---

## Quick Start

### 1) Requirements
- Python 3.10+
- pip, venv

### 2) Setup
```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

> If `requirements.txt` is missing, install:
```bash
pip install websockets cryptography pytest hypothesis jsonschema
```

### 3) Generate keys on first run
Keys are created automatically for each user on first launch in the `.keys/` folder
(never committed to git).

### 4) Start two local nodes and chat
**Terminal A (Node A):**
```bash
python run.py server --port 9000 --bootstrap bootstrap.json
```

**Terminal B (Node B):**
```bash
python run.py client --connect ws://localhost:9000 --name Alice
```

**Terminal C (Optional, Node C):**
```bash
python run.py client --connect ws://localhost:9000 --name Bob
```

Now type in Alice’s terminal to DM Bob or broadcast:
```
/dm Bob hello
/broadcast hi everyone
```

### 5) File Transfer (point-to-point)
In Alice:
```
/send Bob ./path/to/file.bin
```

---

## Commands (from client prompt)
- `/who` — list visible peers
- `/dm <User> <message>` — send a private message
- `/broadcast <message>` — group message
- `/send <User> <filepath>` — point-to-point file transfer
- `/quit` — exit client

---

## Configuration

`bootstrap.json` controls initial peers and trust anchors.

Minimal example:
```json
{
  "peers": ["ws://localhost:9000"],
  "trusted_servers": [],
  "options": {
    "require_signature": true,
    "reject_replay": true
  }
}
```

**Important:** The clean build **does not** accept static tokens or debug signatures.
All envelopes must be signed with RSA-PSS; payloads are encrypted with AES-GCM.

---

## Security Model (Clean Build)
- RSA-OAEP + RSA-PSS for key exchange and signatures
- AES-GCM for payload confidentiality/integrity
- Strict order: **verify → freshness → decrypt → authorise → deliver**
- Nonce cache per peer; replayed messages are rejected
- Path sanitisation on file uploads; temp files auto-clean on timeout
- Server-to-server connections require explicit key pinning / allowlist

---

## Interoperability Test (How To)
Local 2-node test:
```bash
# Terminal A
python run.py server --port 9000 --bootstrap bootstrap.json

# Terminal B
python run.py client --connect ws://localhost:9000 --name Alice
```

Workshop interop:
- Share your public key and canonical JSON ordering rules with the partner group
- Run `tests/test_interop.py` (if provided) or follow `TESTING.md`

---

## Troubleshooting
- **“Verify failed”**: Ensure both sides use RSA-PSS and identical canonical JSON ordering.
- **“Connection refused”**: Port in use — pass `--port <new>` when starting server.
- **“File send stuck”**: Check quota/timeouts and that `FILE_END` is received; see logs.
- **Windows path issues**: Quote paths with spaces; prefer WSL or use forward slashes.

---

## Dev Notes
- Linting: `ruff` / Formatting: `black` (optional)
- Tests: `pytest -q` (see `TESTING.md` for suite)
- Legacy files (`server_single.py`) are preserved for reference only.

---

## Vulnerable Version (Quarantined)
Intentional backdoors for the assessment are stored under `vulnerable/` with usage notes.
**Run only in a VM**. See `QUARANTINE_README.txt` for safe reproduction steps.

---

## License
For academic use in the Secure Programming course.
