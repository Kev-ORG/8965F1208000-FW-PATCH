# Probe Diagnostic Failure Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Preserve one complete non-sector diagnostic summary when the read-only comprehensive probe receives a valid non-PASS outcome.

**Architecture:** The reviewed ECU probe payload stays unchanged. Host code validates a complete stream, atomically replaces one untrusted diagnostic JSON outside trusted evidence, then raises the normal fail-closed error with a concise DCRA/path summary.

**Tech Stack:** Python 3.12, pytest, standard-library JSON/hashlib/binascii/os/tempfile.

## Global Constraints

- Do not modify payload/probe_pe_cycle.c, any payload binary, the manifest, or reviewed envelope pins.
- Do not add ECU operations, erase/program commands, or another probe execution.
- Store one diagnostic only at /data/eps-patch/artifacts/failures/last-probe-failure.json.
- Store metadata and digests only; never sector bytes, backups, candidates, or a trusted PASS report.
- Only a structurally valid OP_FACI_PE_CYCLE stream with nonzero primary or cleanup writes this diagnostic.
- A diagnostic remains untrusted and cannot enable patch or restore.

---

### Task 1: Atomic overwrite primitive and fixed failure path

**Files:**
- Modify: eps_patch/paths.py
- Modify: eps_patch/artifacts.py
- Test: tests/test_artifacts.py

**Interfaces:**
- Produces ArtifactLayout.probe_failure_report returning root / failures / last-probe-failure.json.
- Produces _atomic_replace(path: Path, content: bytes) -> None, fsyncing the file and parent around replacing an existing final file.

- [ ] **Step 1: Write the failing tests**

    def test_probe_failure_report_uses_one_fixed_nontrusted_path(tmp_path):
      layout = ArtifactLayout(tmp_path)
      assert layout.probe_failure_report == tmp_path / "failures" / "last-probe-failure.json"
      assert layout.probe_failure_report.parent != layout.probe_directory

    def test_atomic_replace_replaces_an_existing_complete_file(tmp_path):
      path = tmp_path / "failures" / "last-probe-failure.json"
      _atomic_replace(path, b"first")
      _atomic_replace(path, b"second")
      assert path.read_bytes() == b"second"

- [ ] **Step 2: Verify RED**

Run:

    /Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_artifacts.py -v

Expected: fail because the path property and overwrite primitive do not exist.

- [ ] **Step 3: Write minimal implementation**

Add the fixed path property. Add _atomic_replace beside _atomic_create: create the parent, write/flush/fsync a sibling temporary file, os.replace it onto the final path, fsync the parent, and unlink an unconsumed temporary file in finally.

- [ ] **Step 4: Verify GREEN**

Run the Task 1 command. Expected: pass.

- [ ] **Step 5: Commit**

    git add eps_patch/paths.py eps_patch/artifacts.py tests/test_artifacts.py
    git commit -m "feat: add atomic probe failure artifact"

### Task 2: Complete non-PASS probe diagnostic and console summary

**Files:**
- Modify: eps_patch/probe.py
- Test: tests/test_probe.py

**Interfaces:**
- Consumes ArtifactLayout.probe_failure_report, _atomic_replace, EcuIdentity, PayloadImage, and one complete StreamResult.
- Produces untrusted JSON containing UTC time, workflow/schema, identity, payload, outcome, magic words, all DCRA fields, five named FACI snapshots, and target/CRC address/length/SHA-256/CRC32 descriptors.
- Produces a ProbeError with entry_ctl, entry_cout, exit_ctl, exit_cout, and the fixed report path.

- [ ] **Step 1: Write failing behavior tests**

Mutate the valid fixture to statuses=((1, 3),) and make the DCRA exit differ. Assert that run_probe raises an error matching entry_ctl=0x10203040 and last-probe-failure.json. Load the JSON and assert outcome is primary 3/cleanup 0; DCRA includes all fields; snapshots names are PRE, UNLOCKED, WINDOWS, CONFIGURED, RESTORED; region descriptors contain expected SHA-256 values; serialized JSON contains no sector data field; and probe_directory does not exist. Add a PASS case that leaves no failure file and a malformed-result case that writes none.

- [ ] **Step 2: Verify RED**

Run:

    /Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_probe.py -v

Expected: fail because a non-PASS result currently raises before writing a report.

- [ ] **Step 3: Write minimal implementation**

Split outcome decoding from PASS acceptance. After strict structural validation of the complete result, on a nonzero outcome build a diagnostic with explicit unsigned-32-bit checks, named 5-by-8 FACI snapshots, and digest-only region descriptors. Atomically overwrite the failure path, then raise the original non-PASS error augmented with four hex DCRA values and that path. Do not call install_probe_pass, persist region bytes, or weaken existing PASS validation. If report writing fails, retain the non-PASS error and append the write error.

- [ ] **Step 4: Verify GREEN**

Run the Task 2 command. Expected: all probe tests pass.

- [ ] **Step 5: Commit**

    git add eps_patch/probe.py tests/test_probe.py
    git commit -m "feat: record complete probe failure diagnostics"

### Task 3: Operator documentation and full regression

**Files:**
- Modify: README.md
- Modify: tests/test_documentation.py

**Interfaces:**
- Documents the fixed diagnostic path, its untrusted status, the absence of full sector data, and that one failed read-only probe captures all returned scalar diagnostics.

- [ ] **Step 1: Write a failing documentation assertion**

Require the README to contain /data/eps-patch/artifacts/failures/last-probe-failure.json, untrusted diagnostic, and does not create probe evidence.

- [ ] **Step 2: Verify RED**

Run:

    /Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_documentation.py -v

Expected: fail because failure diagnostics are undocumented.

- [ ] **Step 3: Update bilingual documentation**

Add short Chinese and English Probe troubleshooting text. Explain that the JSON is diagnostic-only, records no sector data, never makes patch/restore eligible, and should be retained with the displayed DCRA values before deciding whether DCRA restoration needs adaptation.

- [ ] **Step 4: Verify focused and full suites**

Run:

    /Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_artifacts.py tests/test_probe.py tests/test_documentation.py -v
    /Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest -q
    git diff --check

Expected: all tests pass and whitespace is clean.

- [ ] **Step 5: Commit**

    git add README.md tests/test_documentation.py
    git commit -m "docs: describe probe failure diagnostics"

## Plan self-review

- Task 1 provides the separate atomic location.
- Task 2 collects all scalar evidence returned by one valid failed probe, while leaving payload and trusted evidence unchanged.
- Task 3 documents the operator workflow and runs focused/full verification.
- No task modifies a payload, manifest, envelope pin, public command, or hardware behavior.

