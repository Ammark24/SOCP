# README — Vulnerable Quarantine Bundle

**Purpose:** This directory contains the intentionally vulnerable version of the Secure Chat project required by the Advanced Secure Protocol assignment. It includes textual PoC instructions, pseudocode, and metadata. **NO runnable exploit scripts** are included. All files are for controlled-lab reproduction only.

**Files included:**
- `POC_INSTRUCTIONS.md` — step-by-step reproduction guidance (textual) for each backdoor.
- `POC_PSEUDOCODE.txt` — high-level pseudocode illustrating exploit logic (non-executable).
- `metadata.json` — creation metadata + SHA256 fingerprint of `POC_INSTRUCTIONS.md`.
- `QUARANTINE_README.txt` — short safety checklist (also present in repo root).

## SAFETY WARNING (READ BEFORE USE)
These materials are intentionally vulnerable and must be handled only in an **isolated VM snapshot**. Follow these safety rules:
1. Create a fresh VM snapshot (recommended: Ubuntu 22.04 LTS) and disable external networking or use host-only networking. Do not run on production or multi-user systems.
2. Install required tooling in the VM only (python 3.10+, web tools), and isolate the VM from the internet unless explicitly required for the exercise.
3. Do **NOT** transfer PoC artefacts or PCAPs to public systems. Use screenshots/logs for reporting where possible.
4. Revert or destroy the VM snapshot immediately after demonstration. Do not retain the VM connected to other networks.
5. The repository intentionally omits runnable exploit scripts. If you choose to produce scripts for lab reproduction, keep them inside the VM and mark them as local-only.

## HOW TO REPRODUCE (OVERVIEW)
1. Boot the VM and create a snapshot.
2. Inside VM, extract the vulnerable bundle and inspect `vulnerable/server_auth.py` and `vulnerable/client_mask.py` to understand the injected logic.
3. Follow `POC_INSTRUCTIONS.md` step-by-step to reproduce the effects in a controlled environment.
4. Capture logs and screenshots; do not publish raw PCAPs outside the VM.

## AUTHOR & INTEGRITY
- Created by: Muhammad Khan
- Created on: 2025-10-26
- Integrity SHA256 (POC_INSTRUCTIONS.md): ee4b5fb6d7167e2e0f1e26b468edc1ae598ccfa6b94f893aa44c8f9dc1c23bc6

If you need assistance preparing a VM snapshot or additional safety checks, request help from your course tutor or IT lab staff.
