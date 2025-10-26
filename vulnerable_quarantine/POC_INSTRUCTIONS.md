# PoC Instructions (QUARANTINED) — Safe, Non-Executable Guidance

**IMPORTANT:** These are textual Proof-of-Concept (PoC) instructions intended for use ONLY inside an isolated VM snapshot created for this assessment. Do NOT run these steps on any production or shared network. The repository contains NO runnable exploit scripts. The PoC instructions deliberately avoid providing executable code; they describe the steps, inputs, and expected observations so markers can reproduce results in a controlled lab.

## Backdoor A — Hardcoded Server Signature (Description)
- **Location:** `vulnerable/server_auth.py` (vulnerable verification function reads static token `server_sig_demo`).
- **Objective:** Demonstrate forging a SERVER_DELIVER message accepted by a node.
- **Prerequisites:** Two VM terminals (Attacker VM and Target VM) on a snapshot image; both nodes running the vulnerable server build from `vulnerable/`.
- **High-level steps (manual):**
  1. Inspect `vulnerable/server_auth.py` to locate the static token (string literal).
  2. On Attacker VM, construct a canonical JSON envelope with fields: `type: "SERVER_DELIVER"`, `sender: "<attacker-key-id>"`, `recipient: "<target-id>"`, `payload: "<base64-ciphertext or empty>"`, `sig: "server_sig_demo"`.
  3. Open a raw WebSocket/TCP connection to the target node (e.g., using `websocat` or a controlled test client) and send the envelope as a single frame.
  4. Observe server logs on Target VM: the node accepts the message as a valid server message and updates its directory (e.g., adds a fake peer or executes server-delivery logic).
- **Expected result:** Target accepts forged server message; inspect logs `logs/server.log` for `INFO: server_deliver accepted for sender=...`

## Backdoor B — Fixed WebSocket Masking Key (Description)
- **Location:** `vulnerable/client_mask.py` (uses fixed mask bytes `b"MASK"` for all frames)
- **Objective:** Demonstrate passive recovery of plaintext from a single captured frame.
- **Prerequisites:** Packet capture tool in VM (e.g., `tcpdump`, `tshark`), a WebSocket client sending at least one message to target node.
- **High-level steps (manual):**
  1. Start packet capture on network interface inside VM before sending a message.
  2. Send a message from vulnerable client to server (one short chat message).
  3. Stop capture and extract the WebSocket frame payload bytes from the TCP stream (use Wireshark/tshark to locate the masked payload).
  4. XOR the masked payload bytes with the repeating key `4D 41 53 4B` (ASCII "MASK") to recover plaintext bytes.
  5. Interpret recovered bytes as UTF-8 JSON; verify message contents.
- **Expected result:** Plaintext JSON recovered, showing that mask is constant and breaks security assumptions.

## Safety & Reproducibility Notes
- Use host-only networking. Do not expose VM NIC to external networks.
- Snapshot VM before testing; revert after reproduction.
- Provide logs and screenshots rather than raw PCAPs when submitting evidence, unless required by marker.
- Keep PoC artifacts offline or in the course submission only.

## Remediation Guidance (for markers)
- Remove static tokens; enforce RSA-PSS verification on all messages.
- Use RFC6455-compliant random masking per frame (do not implement custom masks).
- Add schema validation and strict canonical JSON ordering before verifying signatures.
- Add rate limits and quotas for file uploads; ensure `FILE_END` required or temp files cleaned on timeout.
