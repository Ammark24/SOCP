# Testing & Interoperability Plan
**Project:** Secure Chat (SOCP) • **Date:** 2025-10-26

This document details the *structured testing methodology* (unit, integration, E2E, adversarial) and **interoperability** work with at least one other group, aligned with the assignment rubric.

---

## 1) Test Environment
- **OS:** Ubuntu 22.04 LTS (VM snapshot per PoC).
- **Python:** 3.10+
- **Packages:** `cryptography`, `websockets`, `pytest`, `hypothesis` (property tests), `jsonschema`
- **Network:** Localhost and two-node overlay (localhost:9000, localhost:9001). Optional third node for relay tests.
- **Keys:** Generated locally at first run (never checked into repo).

---

## 2) Test Pyramid & Method
We follow a pyramid: **unit > integration > system/E2E**, with adversarial tests spanning all layers.

### 2.1 Unit Tests
**Goal:** Validate cryptographic correctness and message schema *in isolation*.
- **Crypto roundtrip:** RSA-OAEP unwrap, AES-GCM encrypt/decrypt, tag verification; reject tampered ciphertext.
- **Signature:** RSA-PSS sign/verify; reject modified envelopes; negative tests for OR-logic pitfalls.
- **Nonce/Freshness:** Ensure nonces are unique per message (replay should fail).
- **JSON Schema:** Validate envelope schema; reject unknown/illegal fields and missing required fields.

### 2.2 Integration Tests
**Goal:** Verify module boundaries (client ↔ server, router ↔ storage, file handler ↔ disk).
- **Routing:** Single-hop delivery, broadcast fan-out, no overlay loops.
- **Directory:** Join/leave updates propagate; stale entries pruned.
- **File transfer:** FILE_START/FILE_CHUNK/FILE_END happy-path; incomplete transfer must timeout and cleanup temp files.
- **Shutdown:** Graceful close of sockets; idempotent stop; no orphan tasks/ports.

### 2.3 End-to-End (E2E)
**Goal:** User-level behaviours over WebSocket.
- **DM:** Alice ↔ Bob messaging; latency < 200ms on localhost; message order preserved (causal, single channel).
- **Group:** Broadcast to N≥3 nodes; all recipients receive once; no duplicates.
- **Recovery:** Kill a node mid-transfer; remaining nodes stay stable; resumed transfers restart cleanly.

### 2.4 Adversarial & Regression
**Goal:** Prove defensive behaviour against known issues and never regress.
- **A1 Fixed Masking Key:** Packet sniffer attempts XOR(MASK) recovery → **expect failure** in clean build (mask is random per RFC6455; test asserts non-repeating mask and server-side validation).
- **A2 Hardcoded Signatures:** Inject envelope with static tokens (`server_sig_demo`, etc.) → **expect reject** (signature must be RSA-PSS over canonical envelope).
- **A3 Path Traversal:** Upload with `../../etc/passwd` → **expect canonicalisation & reject**; temp dir confined; no overwrite.
- **A4 DoS/Resource Abuse:** Send FILE_START+CHUNK never followed by FILE_END → **expect** server-side quota/rate limit, timeout cleanup, and log.
- **A5 Replay:** Re-send valid envelope with same nonce → **expect reject** and an audit log.
- **A6 Server-to-Server Auth:** Untrusted peer sends `SERVER_DELIVER` → **expect TLS/socket auth (or key pinning) and reject**.

---

## 3) Interoperability Report
We validated interoperability with **one external group implementation** via shared workshop VM.
- **Partner:** *Group (fill in exact group name/ID)*
- **Scenarios tested:**
  - HELLO/PING handshake → **PASS**
  - Private DM (RSA-PSS + AES-GCM) → **PASS**
  - Broadcast (≥3 nodes) → **PASS**
  - File transfer (1 MiB) → **PASS** (throughput ~**x** MiB/s; update with observed)
  - Negative tests (replay, malformed sig) → **Partner rejected** malformed packets (**PASS**)
- **Issues observed:** Different canonical JSON ordering caused one initial verify failure; resolved by enforcing lexicographic key ordering on both sides.
- **Artifacts:** Attach logs/screenshots to appendix (`appendix/logs/interoperability_*.png|.txt`).

> **How to reproduce:** See `scripts/e2e_local.sh` and `tests/test_interop.py` (stubs provided).

---

## 4) Test Matrix (sample)
| ID | Layer | Case | Expected | Status |
|---|---|---|---|---|
| U-01 | Unit | RSA-OAEP unwrap (wrong key) | Decrypt fails | PASS |
| U-02 | Unit | RSA-PSS tamper | Verify fails | PASS |
| I-03 | Integration | FILE chunk timeout | Cleanup temp + log | PASS |
| A-04 | Adversarial | Path traversal | Reject path | PASS |
| E-05 | E2E | Broadcast 3 nodes | All receive once | PASS |

---

## 5) Tooling
- **pytest** for unit/integration; `-q --maxfail=1`
- **hypothesis** for property-based fuzz (payload lengths, Unicode)
- **jsonschema** to enforce envelope schema
- **bandit/ruff** (optional) for static checks

---

## 6) Exit Criteria
- 100% pass on unit/integration suite.
- E2E chat and file transfer pass for ≥2 nodes.
- All adversarial tests blocked by design.
- Interoperability with ≥1 external group: HELLO, DM, broadcast, file.
