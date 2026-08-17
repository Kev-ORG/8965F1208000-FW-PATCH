# Restart-Resume Power Cycles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make each planned patch/restore power cycle a durable exit-and-rerun boundary that advances one safe stage only on a later manual rerun.

**Architecture:** Add a small power-cycle checkpoint value, store it in schema-2 workflow state, and refactor patch/restore orchestration into state-dispatched single-invocation stages. Keep fixed probe evidence as the source of candidates/backups, keep one attempt directory and continuous transition history across reruns, and refuse every state that is not an explicit planned checkpoint.

**Tech Stack:** Python 3.12, standard-library JSON/path handling, pytest 8, existing atomic artifact helpers and offline transport fakes.

## Global Constraints

- Use `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python` for every Python and pytest command.
- Perform no hardware or network operation.
- `probe` has no planned cycle.
- Patch writer-arm uncertainty is restore-only and is never forward-resumed or retried.
- Restore writer-arm uncertainty is external-recovery-only and is never resumed or retried.
- The public CLI remains exactly `probe`, `patch`, and `restore`, with optional `--serial` only.
- Schema-1 incident state remains restorable but never restart-resumable.

---

## File Structure

- `eps_patch/power.py`: immutable checkpoint schema, checkpoint validation, and nonblocking bilingual instruction output.
- `eps_patch/patch.py`: schema-2 patch recorder/loader, resumable-attempt selection, and one-stage-per-invocation patch dispatcher.
- `eps_patch/restore.py`: schema-1/2 patch incident parsing, schema-2 restore recorder/loader, resumable restore selection, and one-stage-per-invocation restore dispatcher.
- `eps_patch.py`: print planned instructions without input.
- `tests/test_power.py`: nonblocking prompt and checkpoint unit contracts.
- `tests/test_restart_resume.py`: cross-invocation patch/restore state-machine tests.
- `tests/test_patch.py`, `tests/test_restore.py`, `tests/test_cli.py`, `tests/test_end_to_end_offline.py`: adapt retained workflow/fault tests to explicit reruns while preserving their safety assertions.
- `README.md`, `tests/test_documentation.py`: operator exit/reboot/rerun instructions and removal of Enter guidance.

### Task 1: Power-cycle checkpoint primitive

**Files:**
- Modify: `eps_patch/power.py`
- Modify: `tests/test_power.py`

**Interfaces:**
- Produces: `PowerCycleCheckpoint(completed_state: str, next_state: str)` with `as_dict() -> dict[str, str]` and strict `from_dict(value) -> PowerCycleCheckpoint`.
- Produces: `request_power_cycle(current_state: str, next_state: str, output: Callable[[str], object]) -> None`, which emits once and never asks for input.

- [ ] **Step 1: Retain the failing nonblocking prompt test and add literal checkpoint validation tests**

```python
def test_power_cycle_instruction_exits_instead_of_waiting_for_enter():
  prompts = []
  request_power_cycle("PROBED", "TARGET_PRECHECKED", prompts.append)
  assert "Press Enter" not in prompts[0]
  assert "rerun the same command" in prompts[0]

def test_checkpoint_round_trips_only_an_exact_uuid_bound_mapping():
  checkpoint = PowerCycleCheckpoint("PROBED", "TARGET_PRECHECKED")
  assert PowerCycleCheckpoint.from_dict(checkpoint.as_dict()) == checkpoint
  with pytest.raises(ValueError):
    PowerCycleCheckpoint.from_dict({**checkpoint.as_dict(), "extra": True})
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_power.py -q`

Expected: FAIL because the prompt still says `Press Enter` and the checkpoint type does not exist.

- [ ] **Step 3: Implement the minimal primitive**

```python
@dataclass(frozen=True, slots=True)
class PowerCycleCheckpoint:
  completed_state: str
  next_state: str

  def __post_init__(self) -> None:
    if not self.completed_state or not self.next_state:
      raise ValueError("power-cycle states must be non-empty text")
  def as_dict(self) -> dict[str, str]:
    return {
      "completed_state": self.completed_state,
      "next_state": self.next_state,
    }
```

Change the instruction tail to `After comma restarts, rerun the same command / comma 重启后重新运行同一命令。` and do not invoke an input callback.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_power.py -q`

Expected: all power tests PASS.

### Task 2: Durable single-attempt patch resume

**Files:**
- Modify: `eps_patch/patch.py`
- Modify: `tests/test_restart_resume.py`
- Modify: `tests/test_patch.py`

**Interfaces:**
- Consumes: `PowerCycleCheckpoint`, existing trusted probe/candidate builders and writer validators.
- Produces: `run_patch(...) -> Path` returning `state.json` for a planned pause and `patch-report.json` for PASS.
- Produces internally: exact `_PATCH_RESUME_NEXT = {"PROBED": "TARGET_PRECHECKED", "TARGET_COMMITTED": "CRC_PRECHECKED", "CRC_COMMITTED": "VERIFY_PENDING"}`.

- [ ] **Step 1: Keep the RED patch tests that prove persist-before-output, one attempt, and one stage per manual rerun**

The literal expected checkpoint after the first invocation is:

```python
assert state["power_cycle"] == {
  "completed_state": "PROBED",
  "next_state": "TARGET_PRECHECKED",
}
```

- [ ] **Step 2: Run the focused patch tests and verify RED**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_restart_resume.py -k patch -q`

Expected: FAIL because `run_patch` executes all stages in one invocation and has no schema-2 checkpoint.

- [ ] **Step 3: Upgrade `_StateRecorder` to schema 2 and allow loading an existing canonical history**

Add `power_cycle: PowerCycleCheckpoint | None` to the summary. Its exact validation is:

```python
if checkpoint is not None:
  if checkpoint.completed_state != state["result"]:
    raise PatchError("patch power-cycle checkpoint contradicts result")
  if _PATCH_RESUME_NEXT.get(state["result"]) != checkpoint.next_state:
    raise PatchError("patch power-cycle successor is not allowlisted")
```

Initialize a resumed recorder from the existing attempt timestamp and copied
transition list; never create a second directory for a resumable state.
Treat `incident_timestamp` as the permanent identity of a patch incident;
retain `incident_state_sha256` only as immutable snapshot evidence. A PASS
restore for that timestamp supersedes a paused patch even if its current state
serialization has a different digest.

- [ ] **Step 4: Add fail-closed resumable-attempt selection**

Scan every timestamped patch directory. Accept at most one schema-2 state with
an exact non-null checkpoint. Reject malformed state. Exclude a paused attempt
if any canonical PASS restore records the same `incident_timestamp`. Run the
existing unresolved-incident gate against every other incident.

- [ ] **Step 5: Split the linear body into four exact entry branches**

```python
if entry is None:
  return _start_patch(...)
if entry.result == "PROBED":
  return _write_target_stage(...)
if entry.result == "TARGET_COMMITTED":
  return _write_crc_stage(...)
if entry.result == "CRC_COMMITTED":
  return _verify_stage(...)
raise PatchError("patch state is not restart-resumable")
```

Each stage repeats static/probe validation and preflight, reconstructs all
candidate bytes from trusted evidence, and records `*_ARMED` before its one
writer call. Persist the new checkpoint, return its state path, then emit the
instruction outside the writer/failure exception boundary so output failure
cannot rewrite the durable stage as an incident.

- [ ] **Step 6: Run focused patch tests and retained fault tests**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_restart_resume.py -k patch tests/test_patch.py -q`

Expected: PASS; writer-loss tests still observe exactly one writer invocation and the same restore order.

### Task 3: Durable one-hardware-stage restore resume

**Files:**
- Modify: `eps_patch/restore.py`
- Modify: `tests/test_restart_resume.py`
- Modify: `tests/test_restore.py`

**Interfaces:**
- Consumes: `PowerCycleCheckpoint`, existing `RestorePlan`, immutable backup reconstruction, live classification, and restore writer validators.
- Produces: `run_restore(...) -> Path` returning `state.json` for planned pause and `restore-report.json` for PASS.
- Preserves: schema-1 patch incident parsing for recovery only.

- [ ] **Step 1: Keep the RED target-only restore test and add a two-sector checkpoint-order case**

The target-only expected sequence across manual reruns is:

```python
TARGET_ECHO_VERIFIED -> TARGET_LIVE_PRECHECKED -> TARGET_COMMITTED -> PASS
```

The two-sector sequence adds `CRC_COMMITTED -> TARGET_ECHO_VERIFIED`, with a
a new invocation required at every arrow that crosses a planned power checkpoint.

- [ ] **Step 2: Run focused restore tests and verify RED**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_restart_resume.py -k restore -q`

Expected: FAIL because `run_restore` rejects its own nonterminal attempt on rerun and crosses planned cycles in one invocation.

- [ ] **Step 3: Add schema-2 restore checkpoint state while retaining schema-1 terminal parsing**

Reconstruct `completed` exclusively from committed transitions. Allow only:

```python
CRC_ECHO_VERIFIED -> CRC_LIVE_PRECHECKED
CRC_LIVE_PRECHECKED -> CRC_ARMED
CRC_COMMITTED -> TARGET_ECHO_VERIFIED
TARGET_ECHO_VERIFIED -> TARGET_LIVE_PRECHECKED
TARGET_LIVE_PRECHECKED -> TARGET_ARMED
```

The exact allowed subset depends on `restore_order` and completed bases.
`*_ARMED`, `FAILED`, `INDETERMINATE`, and `PASS` have `power_cycle: null`.
Live policy also accepts the exact known state at planned patch restore points:
`TARGET_COMMITTED` requires target candidate/CRC source, while `CRC_COMMITTED`
requires both candidates.

- [ ] **Step 4: Select or create exactly one restore attempt**

When a schema-2 planned checkpoint exists for the selected incident, resume it
instead of `_create_attempt`. A prior `INDETERMINATE` still raises the
external-recovery error; a prior `PASS` still
blocks; schema-1 nonterminal state never resumes.

- [ ] **Step 5: Dispatch exactly one restore hardware stage**

Use the current result and checkpoint successor to choose one of RAM echo, live
read, or exact-confirmation/writer. After a non-final commit, install the
between-sector checkpoint. After final commit, generate the unchanged PASS
report and final state. Preserve the `armed` determination from transition
history so any post-arm failure is still `INDETERMINATE`.

- [ ] **Step 6: Run focused restore, classification, and one-shot tests**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_restart_resume.py -k restore tests/test_restore.py -q`

Expected: PASS; post-arm fault cases still show one restore writer call,
`automatic_retry == false`, and `external_recovery_required == true`.

### Task 4: CLI and operator contract

**Files:**
- Modify: `eps_patch.py`
- Modify: `tests/test_cli.py`
- Modify: `README.md`
- Modify: `tests/test_documentation.py`

**Interfaces:**
- Consumes: the unchanged CLI command namespace.
- Produces: exit code 0 plus state path for planned pauses; no input call for power instructions.

- [ ] **Step 1: Add failing CLI/documentation tests**

```python
assert set(_command_action(parser).choices) == {"probe", "patch", "restore"}
assert "Press Enter" not in README
assert "rerun the same command" in README
```

Assert dispatch gives the nonblocking power-cycle output callback only to
patch/restore, not probe.

- [ ] **Step 2: Run tests and verify RED**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_cli.py tests/test_documentation.py -q`

Expected: FAIL on Enter-based documentation and the blocking input callback.

- [ ] **Step 3: Update CLI injection and README**

Pass `power_cycle_checkpoint=print` for patch/restore. Keep
`confirmation=input`. Document exit, full cycle, comma reboot, and same-command
rerun at every patch/restore planned boundary.

- [ ] **Step 4: Run CLI/documentation tests and verify GREEN**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_cli.py tests/test_documentation.py -q`

Expected: PASS with exactly three commands and no new user argument.

### Task 5: End-to-end adaptation and full verification

**Files:**
- Modify: `tests/test_end_to_end_offline.py`
- Modify: any retained test fixture whose old callback assumed all cycles occurred in one process

**Interfaces:**
- Consumes: schema-2 stage dispatch and repeated manual invocations.
- Produces: offline probe/patch/restore lifecycle reaching unchanged semantic PASS results.

- [ ] **Step 1: Change the offline harness to invoke the same command repeatedly until its final report**

Patch uses four invocations. A two-sector restore uses one invocation for every
echo/live/writer stage and the between-sector boundary. Accumulate transport
fakes across invocations and assert every list is exhausted once.

- [ ] **Step 2: Run the offline lifecycle test**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_end_to_end_offline.py -q`

Expected: PASS with final patch/restore reports and canonical writer order.

- [ ] **Step 3: Run the complete suite with fresh evidence**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest -q`

Expected: all tests PASS, no hardware/network access, and no warnings.

- [ ] **Step 4: Check repository hygiene and diff**

Run: `git diff --check`

Run: `git status --short`

Expected: no whitespace errors; only intended design, plan, Python, tests, and README changes.
