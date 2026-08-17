# Single Payload Per Invocation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Guarantee that every probe, patch, and restore process invocation triggers at most one ECU RAM payload, with a complete persisted power-cycle boundary between each read-only precheck and writer.

**Architecture:** Split the two combined patch branches into separate precheck and writer branches keyed by persisted schema-2 states. Extend the canonical resume map in both patch execution and shared state validation. Preserve all V850 binaries and the already-correct restore workflow, and enforce the cross-workflow invariant with lifecycle tests.

**Tech Stack:** Python 3.12, pytest, immutable JSON state files, existing `PowerCycleCheckpoint` and `ArtifactLayout` APIs.

## Global Constraints

- Run tests with `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python`.
- One command invocation may call `transport.run_payload(...)` at most once.
- Never reset, retry, or assume watchdog recovery between payloads.
- Do not modify or rebuild any V850 source or binary in this change.
- Preserve exact writer order: target `0x60000`, then CRC `0xf8000`.
- Preserve all armed/indeterminate and restore-order rules.
- Existing schema-1 states and terminal `FAILED` attempts are never resumable.

---

### Task 1: Prove the Consecutive-Payload Regression

**Files:**
- Modify: `tests/test_restart_resume.py`
- Modify: `tests/test_patch.py`

**Interfaces:**
- Consumes: `run_patch(...) -> Path`, `FakeTransport.run_payload(...)`, and persisted `state.json` schema 2.
- Produces: lifecycle tests requiring new `TARGET_PRECHECKED` and `CRC_PRECHECKED` checkpoints and one payload per invocation.

- [ ] **Step 1: Rewrite the patch lifecycle expectation as six invocations**

Update `test_patch_resumes_one_stage_per_manual_rerun_in_the_same_attempt` so the expected results are:

```text
PROBED -> TARGET_PRECHECKED -> TARGET_COMMITTED
       -> CRC_PRECHECKED -> CRC_COMMITTED -> PASS
```

Provide only one `FakeTransport` before each invocation. After the target precheck invocation assert:

```python
assert state["result"] == "TARGET_PRECHECKED"
assert checkpoint == {
  "completed_state": "TARGET_PRECHECKED",
  "next_state": "TARGET_ARMED",
}
assert "confirmation" not in events
```

After the CRC precheck invocation require the analogous `CRC_PRECHECKED -> CRC_ARMED` checkpoint and no confirmation.

- [ ] **Step 2: Add a direct one-payload-per-invocation assertion**

Track each invocation separately and assert that its events contain exactly one `("<label>", "payload", <operation>)` record whenever hardware runs. Include the already-correct one-sector restore lifecycle in the same safety assertion.

- [ ] **Step 3: Update the complete patch helper expectations**

Change `_run_patch` to allow six invocations and update `test_patch_preserves_two_sector_order_confirmations_and_reconnects` to require five planned power prompts:

```python
(
  "PROBED -> TARGET_PRECHECKED",
  "TARGET_PRECHECKED -> TARGET_ARMED",
  "TARGET_COMMITTED -> CRC_PRECHECKED",
  "CRC_PRECHECKED -> CRC_ARMED",
  "CRC_COMMITTED -> VERIFY_PENDING",
)
```

Transport and writer order remain unchanged.

- [ ] **Step 4: Run RED tests**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_restart_resume.py::test_patch_resumes_one_stage_per_manual_rerun_in_the_same_attempt tests/test_patch.py::test_patch_preserves_two_sector_order_confirmations_and_reconnects -q
```

Expected: failure because a `PROBED` invocation consumes both the precheck and writer transports and records `TARGET_COMMITTED` rather than `TARGET_PRECHECKED`.

---

### Task 2: Split Patch Prechecks From Writers

**Files:**
- Modify: `eps_patch/patch.py`
- Modify: `eps_patch/restore.py`
- Test: `tests/test_restart_resume.py`
- Test: `tests/test_patch.py`
- Test: `tests/test_restore.py`

**Interfaces:**
- Consumes: `PowerCycleCheckpoint(completed_state: str, next_state: str)`, `_StateRecorder.record(...) -> Path`, and deterministic candidate construction from probe evidence.
- Produces: resumable schema-2 states `TARGET_PRECHECKED` and `CRC_PRECHECKED` that authorize only their matching writer after a manual complete power cycle.

- [ ] **Step 1: Extend both canonical resume maps**

In `eps_patch/patch.py` and the shared patch-state validator in `eps_patch/restore.py`, use the exact map:

```python
_PATCH_RESUME_NEXT = {
  "PROBED": "TARGET_PRECHECKED",
  "TARGET_PRECHECKED": "TARGET_ARMED",
  "TARGET_COMMITTED": "CRC_PRECHECKED",
  "CRC_PRECHECKED": "CRC_ARMED",
  "CRC_COMMITTED": "VERIFY_PENDING",
}
```

- [ ] **Step 2: End the target precheck invocation**

After validating and persisting the `crc_probe` result, record `TARGET_PRECHECKED` with:

```python
checkpoint = PowerCycleCheckpoint(
  PatchState.TARGET_PRECHECKED.value,
  PatchState.TARGET_ARMED.value,
)
path = recorder.record(
  PatchState.TARGET_PRECHECKED,
  evidence=precheck_evidence,
  power_cycle=checkpoint,
)
raise _PlannedPowerCycle(path, checkpoint)
```

Move target intent construction, exact confirmation, `TARGET_ARMED`, writer execution, readback validation, and `TARGET_COMMITTED` into a separate `if entry is PatchState.TARGET_PRECHECKED:` branch. This branch must open exactly one transport.

- [ ] **Step 3: End the CRC precheck invocation**

After validating and persisting `crc_intermediate`, record `CRC_PRECHECKED` with restore order `("target",)` and checkpoint:

```python
PowerCycleCheckpoint(
  PatchState.CRC_PRECHECKED.value,
  PatchState.CRC_ARMED.value,
)
```

Move CRC intent construction, exact confirmation, `CRC_ARMED`, writer execution, validation, and `CRC_COMMITTED` into a separate `if entry is PatchState.CRC_PRECHECKED:` branch.

- [ ] **Step 4: Preserve failure classification**

Keep `_failure_for_phase` semantics exact:

- `TARGET_PRECHECKED` failure before arm -> `FAILED`, no restore order;
- `CRC_PRECHECKED` failure before arm -> `RECOVERY_REQUIRED`, restore target;
- armed transport uncertainty -> existing indeterminate state;
- no retry in every case.

- [ ] **Step 5: Run focused GREEN tests**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_patch.py tests/test_restart_resume.py tests/test_restore.py -q
```

Expected: all focused tests pass and every lifecycle invocation consumes at most one transport result.

- [ ] **Step 6: Commit the state-machine fix**

```bash
git add eps_patch/patch.py eps_patch/restore.py tests/test_patch.py tests/test_restart_resume.py tests/test_restore.py
git commit -m "fix: power cycle between prechecks and writers"
```

---

### Task 3: Operator Documentation and Release Verification

**Files:**
- Modify: `README.md`
- Modify: `tests/test_documentation.py`
- Review only: `eps_patch/probe.py`
- Review only: `eps_patch/restore.py`
- Review only: `eps_patch/transport.py`

**Interfaces:**
- Consumes: the final patch checkpoint map and existing restore live-read checkpoints.
- Produces: operator-visible instructions that exactly match runtime behavior and a verified clean main branch.

- [ ] **Step 1: Add documentation contract assertions**

Require both language sections to name the precheck boundaries and state that one command invocation triggers at most one payload. Keep `Press Enter` forbidden.

- [ ] **Step 2: Update Chinese and English patch instructions**

List the five planned checkpoints and instruct the operator to complete the vehicle/EPS/comma power cycle, reconnect over SSH, and rerun the same command after each checkpoint. State that a precheck invocation never arms a writer.

- [ ] **Step 3: Perform static workflow audit**

Verify:

- `probe.run_probe` has one `run_payload` call;
- each reachable `patch` branch has one `run_payload` call and immediately returns a report or planned checkpoint;
- each reachable `restore` branch has one `run_payload` call and immediately returns a report or planned checkpoint;
- no automatic reset/retry path is introduced.

- [ ] **Step 4: Run complete verification**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest -q
git diff --check
sh -n payload/build.sh
git status --short
```

Expected: full suite passes, diff and shell checks pass, and only planned host state-machine/test/documentation files are modified.

- [ ] **Step 5: Commit release changes**

```bash
git add README.md tests/test_documentation.py
git commit -m "docs: explain precheck power cycles"
```
