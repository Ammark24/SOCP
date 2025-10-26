# Code Quality & Operational Readiness

This checklist describes how the codebase meets the rubric for **Outstanding (4 pts)**: runs out-of-the-box, has good error handling, and behaves well under failures.

---

## 1) Run-Ready Defaults
- `README.md` includes: prerequisites, install commands, run examples, and port defaults.
- Sample commands:
  - `python3 server_mesh.py --port 9000 --bootstrap bootstrap.json`
  - `python3 client.py --connect ws://localhost:9000 --name Alice`
- First run generates keys locally; no secrets in repo.

## 2) Error Handling
- **Network:** Timeouts, retries with backoff, and graceful socket close on exceptions.
- **Crypto:** Clear messages when verification/decryption fails; no stack traces leaked to clients.
- **Files:** Quotas and timeouts on uploads; temp dir auto-clean on failure; canonical path enforcement (no `../`).

## 3) Defensive Defaults
- Signature verification is **mandatory** (RSA-PSS). No debug bypass in clean build.
- Nonce/replay cache per peer; rejects duplicates.
- Server-to-server connections require explicit trust (key pinning or allowlist).
- WebSocket masking uses compliant randomness; never a constant mask.

## 4) Resource Safety
- Rate limiting on message/file endpoints.
- Bounded queues for incoming frames.
- Size limits for messages and files.
- DoS guards on long-running handlers.

## 5) Shutdown & Recovery
- Ctrl-C leads to orderly shutdown: stop acceptors, drain queues, close sockets.
- Idempotent stop signals; repeated calls are safe.
- Crash-only design elements: on restart, system rebuilds in-memory state from known-good sources.

## 6) Logging & Observability
- Structured logs (JSON) with event IDs for: verify_fail, replay_detected, path_traversal_blocked, quota_hit.
- Log levels: INFO for lifecycle, WARN for recoverable issues, ERROR for security or data loss risks.
- Redaction policy: never log keys, nonces, or plaintext payloads.

## 7) Testing Hooks (Non-Production)
- Feature flags for test visibility only (e.g., force nonce collision in test); disabled in production build.
- Integration with `pytest` fixtures for ephemeral temp dirs and sockets.

## 8) Repository Hygiene
- `vulnerable/` folder clearly marked with `QUARANTINE_README.txt` and PoC instructions only.
- CI (optional): run lint + tests on push; reject if adversarial tests fail.
- Consistent style (ruff/black).

## 9) Known Issues & Remediations
- Legacy `server_single.py` retained for comparison; **do not use in production**.
- Updated file handler now normalises paths and enforces quotas/timeouts.
- README updated to reflect accurate file names and run commands.
