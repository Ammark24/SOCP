QUARANTINE — Vulnerable Build (Intentional Backdoors)

This directory contains the intentionally backdoored version required by the
assignment. Run only in an *isolated VM snapshot*. Never connect these binaries
to untrusted networks.

Includes (high level):
- Backdoor A: static server signature acceptance (educational)
- Backdoor B: fixed WebSocket masking key in client (educational)

POC steps are described textually in the appendix and TESTING.md (Adversarial
section). No exploit scripts are provided here.

Safety checklist:
- VM snapshot before running
- Host-only networking
- Destroy VM after demo
