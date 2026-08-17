# CRC Trigger Route Recovery Implementation Plan

## Approved Final-Fix Routing Amendment

This amendment supersedes the direction-specific route choices in the original
plan below without rewriting that implementation history. Authentication stays
at RAM `0xFEBF0000 / 0x1000`. `EcuTransport.trigger()` must first retain every
existing operation and specialized actual-sector validation, including an
explicit `0x60000` or `0xF8000` actual base for restore, then emit the single
bench-proven `FF00` range `0xE0000 / 0x8000` for every allowed operation.

The final-fix TDD wave updates transport literals and the routed offline restore
workflow so target and CRC triggers both equal
`31 01 ff 00 45 00 00 0e 00 00 00 00 80 00`. It adds a regression proving
that actual-sector differences cannot change the trigger bytes and retains
rejections for cross-direction, missing, and arbitrary actual bases. Actual
payload/result sectors remain `0x60000` and `0xF8000`; no payload, V850, FACI,
intent, candidate, CRC, binary, manifest, pin, or writer primitive changes.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Separate the UDS `FF00` trampoline range from the payload's actual Flash sector and safely resume the supplied two-indeterminate CRC incident through one fresh read-only classification.

**Architecture:** `EcuTransport.trigger()` continues to validate the specialized payload's actual sector, then derives an allowlisted UDS trigger base: target=`0x60000`, CRC=`0xE0000`, default read-only=`0x60000`. Patch-state loading gains one exact legacy NRC-0x31 history predicate; only that predicate permits a fresh `live_read`, and a newly persisted reconciliation marker consumes the exception before any later manually confirmed writer.

**Tech Stack:** Python 3.12, pytest, JSON schema/state audit, raw ISO-TP/UDS framing, existing pinned V850 payload envelopes.

## Global Constraints

- Do not modify or rebuild any V850 source, payload binary, writer instruction, FACI register sequence, erase/program primitive, sector data, CRC adjustment word, intent layout, envelope pin, or payload result contract.
- Run tests with `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python`.
- Do not connect to panda, comma, ECU, Docker, SSH, or any network endpoint during implementation or verification.
- The first eligible ECU action after release must be the existing read-only `live_read`; error text alone never authorizes a writer.
- Target actual/trigger base remains `0x60000`; CRC actual base remains `0xF8000`; CRC trigger base is `0xE0000`; every length remains `0x8000`.
- Preserve exact uppercase `YES`, planned power-cycle checkpoints, one-shot writer behavior, complete readback validation, and atomic state persistence.
- Never edit or synthesize the operator's `state.json`; tests must create canonical fixtures through existing recorders/helpers.

---

### Task 1: Separate actual Flash direction from the UDS trigger route

**Files:**
- Modify: `tests/test_transport.py:243-271`
- Modify: `eps_patch/transport.py:263-296`

**Interfaces:**
- Consumes: `EcuTransport.trigger(*, operation: int, new_uds: bool, sector_base: int | None)` where `sector_base` identifies the specialized payload's actual sector.
- Produces: internal deterministic route selection that serializes one of `0x60000` or `0xE0000` into `31 01 ff 00 45 xx <base> 00 00 80 00`.

- [ ] **Step 1: Add failing exact-frame tests for both candidate writers**

  Extend `tests/test_transport.py` with a parameterized test that invokes the real `trigger()` and inspects `fake_bindings(...).isotp_send`:

  ```python
  @pytest.mark.parametrize(
    ("operation", "actual_base", "trigger_base"),
    (
      (OP_WRITE_TARGET_CANDIDATE, 0x60000, 0x60000),
      (OP_WRITE_CRC_CANDIDATE, 0xF8000, 0xE0000),
    ),
  )
  def test_candidate_writer_trigger_separates_actual_sector_from_uds_route(
    operation, actual_base, trigger_base,
  ):
    calls = []
    with EcuTransport(bindings=fake_bindings(calls)) as transport:
      transport.trigger(
        operation=operation, new_uds=False, sector_base=actual_base,
      )
    assert calls[0][0][1] == (
      b"\x31\x01\xff\x00\x45\x00"
      + struct.pack("!II", trigger_base, 0x8000)
    )
  ```

  Import the named protocol constants instead of using numeric operation IDs.

- [ ] **Step 2: Add failing restore-direction tests and preserve rejection tests**

  Add two `OP_RESTORE_SECTOR` cases proving actual target/CRC bases route to
  `0x60000`/`0xE0000`. Keep the existing cross-direction candidate rejection
  and read-only override rejection. Add an invalid restore base case proving
  `0xE0000` cannot be supplied by the caller as an actual sector.

- [ ] **Step 3: Run the focused tests and verify RED**

  Run:

  ```bash
  /Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_transport.py -q
  ```

  Expected: CRC candidate and CRC restore cases fail because the emitted base
  is `0xF8000`, while target/read-only and rejection cases pass.

- [ ] **Step 4: Implement the minimal allowlisted route derivation**

  In `EcuTransport.trigger()`, keep the existing operation/actual-sector
  validation and replace only `selected_base` derivation. Use an explicit
  constant and no caller-controlled trigger parameter:

  ```python
  _CRC_UDS_TRIGGER_BASE = 0xE0000

  is_crc_direction = (
    operation == OP_WRITE_CRC_CANDIDATE
    or (operation == OP_RESTORE_SECTOR and sector_base == TARGET.crc_sector_base)
  )
  trigger_base = _CRC_UDS_TRIGGER_BASE if is_crc_direction else TARGET.sector_base
  option = routine_magic + struct.pack("!II", trigger_base, TARGET.sector_length)
  ```

  Do not change `run_payload()`, specialized image validation, or payload
  metadata: `sector_base` must remain `0xF8000` for CRC direction.

- [ ] **Step 5: Run transport tests and verify GREEN**

  Run the Task 1 command again. Expected: all `tests/test_transport.py` tests
  pass, with exact raw-frame assertions for all four destructive directions.

- [ ] **Step 6: Commit Task 1**

  ```bash
  git add eps_patch/transport.py tests/test_transport.py
  git commit -m "fix: separate CRC payload and trigger addresses"
  ```

---

### Task 2: Admit only the supplied legacy NRC history to read-only reconciliation

**Files:**
- Modify: `tests/test_patch.py:480-710`
- Modify: `tests/test_restore.py` (patch-state audit regression section)
- Modify: `eps_patch/restore.py:620-714`
- Modify: `eps_patch/patch.py:217-304,791-855`

**Interfaces:**
- Produces in `eps_patch.restore`: `_legacy_crc_trigger_recovery_status(transitions: list[dict[str, object]]) -> str | None`, returning only `"pending"`, `"consumed"`, or `None`.
- Consumes in `eps_patch.patch`: the structural status above plus exact current `CrcCandidate`, `TargetManifest`, reviewed CRC template, and fixed payload records before calling `preflight()`.
- Persists on successful read-only recovery: `legacy_trigger_rejection_sequence: int` and `legacy_trigger_recovery: "nrc31-route-v1"` in the new reconciliation transition evidence.

- [ ] **Step 1: Create a canonical two-indeterminate NRC fixture through test helpers**

  In `tests/test_patch.py`, extend `_crc_indeterminate_case()` or add a sibling
  helper that first performs the existing source reconciliation, invokes the
  CRC writer with a `PostTriggerTransportError` whose cause text is exactly:

  ```text
  RoutineControl negative response NRC 0x31; raw=037f313100000000
  ```

  The helper must assert that the resulting state has exactly the sequence:

  ```python
  [
    "STARTED", "PROBED", "TARGET_PRECHECKED", "TARGET_ARMED",
    "TARGET_COMMITTED", "CRC_PRECHECKED", "CRC_ARMED",
    "CRC_INDETERMINATE", "CRC_PRECHECKED", "CRC_ARMED",
    "CRC_INDETERMINATE",
  ]
  ```

  Do not load `/Users/kevin/Desktop/state.json` in tests.

- [ ] **Step 2: Add failing pending-recovery tests**

  Add tests proving the exact fixture runs only `OP_LIVE_READ`, never calls
  confirmation, and records one of these branches:

  ```python
  # Fresh CRC source
  assert state["result"] == "CRC_PRECHECKED"
  assert state["transitions"][-1]["evidence"]["legacy_trigger_recovery"] \
    == "nrc31-route-v1"
  assert state["transitions"][-1]["evidence"][
    "legacy_trigger_rejection_sequence"
  ] == 10

  # Fresh CRC candidate
  assert state["result"] == "CRC_COMMITTED"
  assert writer_events == []
  ```

  Both branches must assert the normal exact power-cycle checkpoint and fresh
  complete sector SHA-256 evidence.

- [ ] **Step 3: Add failing near-miss and no-mutation tests**

  Parameterize one mutation at a time over:

  - NRC `0x22` instead of `0x31`;
  - raw frame not equal to `037f313100000000`;
  - missing or changed sequence-8 `classification=source`;
  - wrong `reconciled_sequence`;
  - sequence-8 target or CRC readback hash inconsistent with `PROBED`;
  - second arm operation/base/source/candidate mismatch;
  - an extra transition after the final NRC;
  - partial CRC live bytes, source target instead of candidate, identity
    mismatch, and transport failure.

  For every case assert byte-for-byte unchanged state and zero confirmation;
  structural near-misses must also assert zero preflight and zero transport.

- [ ] **Step 4: Add a failing consumed-exception test**

  After fresh source classification, run the normal next invocation with a
  corrected-route writer that becomes indeterminate. Assert the subsequent
  `patch` invocation is rejected before preflight/transport/confirmation. This
  proves `legacy_trigger_recovery="nrc31-route-v1"` cannot authorize a second
  recovery.

- [ ] **Step 5: Add failing persisted-state audit tests**

  In `tests/test_restore.py`, pass the canonical pending history and its valid
  consumed `CRC_PRECHECKED`/`CRC_COMMITTED` successor through the real
  `_load_patch_state()`. Assert both load. Then mutate every marker/error/hash
  listed above and assert `RestoreError`; retain the existing generic
  second-indeterminate retry rejection.

- [ ] **Step 6: Run focused tests and verify RED**

  Run:

  ```bash
  /Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_patch.py tests/test_restore.py -q
  ```

  Expected: the exact two-indeterminate state is not selected as resumable and
  a forged second reconciliation is rejected by the one-time retry audit.

- [ ] **Step 7: Implement a single strict structural history predicate**

  In `eps_patch/restore.py`, implement
  `_legacy_crc_trigger_recovery_status()` with exact comparisons. It must:

  - find exactly two `CRC_INDETERMINATE` transitions;
  - require the first error to equal the historical unknown-`0x03` error and
    the last pending error to equal the full observed NRC/raw error string;
  - require the subsequence between incidents to be exactly
    `CRC_PRECHECKED, CRC_ARMED`;
  - require the first reconciliation evidence to bind the first incident and
    compare its readback hashes to the original `PROBED` source/candidate
    hashes;
  - require the second arm to declare operation 14, base `0xf8000`, and hashes
    matching `PROBED`;
  - return `"pending"` only when the second incident is final;
  - return `"consumed"` only for one immediate `CRC_PRECHECKED` or
    `CRC_COMMITTED` successor containing the exact recovery marker and second
    incident sequence;
  - return `None` for every malformed or additional transition.

  Use this predicate at the one-time retry check in `_load_patch_state()` so
  only the exact consumed transition can cross the old limit.

- [ ] **Step 8: Validate semantic writer evidence before any hardware call**

  In `eps_patch.patch`, before `preflight()` in the pending recovery branch,
  reconstruct the exact `CandidateWriterIntent.for_crc(...)` and reviewed
  specialized writer from the current fixed probe candidate. Compare the
  second arm evidence to the expected operation, sector, source/candidate
  hashes, candidate CRC32, and `_writer_payload_record(expected_writer)`.
  Raise `PatchError` on any mismatch before preflight or transport.

  Update `_select_patch_resume()` so `"pending"` is eligible despite two
  indeterminate transitions, and so a planned `"consumed"` state remains
  restart-resumable. Do not relax either condition for `None`.

- [ ] **Step 9: Persist and consume the exact recovery marker**

  Reuse the existing `CRC_INDETERMINATE` live-read branch. When its entry status
  is `"pending"`, record:

  ```python
  {
    "legacy_trigger_recovery": "nrc31-route-v1",
    "legacy_trigger_rejection_sequence": state["sequence"],
    "reconciled_from": "CRC_INDETERMINATE",
    "reconciled_sequence": state["sequence"],
    "classification": classification,
    # existing identity, hashes, and live_read payload record
  }
  ```

  Keep the source/candidate state branches, power cycles, restore order, and
  failure no-mutation behavior unchanged.

- [ ] **Step 10: Run focused tests and verify GREEN**

  Run the Task 2 command again. Expected: all patch and restore tests pass,
  including generic second-indeterminate blocking and exact legacy recovery.

- [ ] **Step 11: Commit Task 2**

  ```bash
  git add eps_patch/patch.py eps_patch/restore.py tests/test_patch.py tests/test_restore.py
  git commit -m "fix: recover exact rejected CRC trigger incident"
  ```

---

### Task 3: Cross-workflow regression, operator guidance, and release verification

**Files:**
- Modify: `tests/test_end_to_end_offline.py`
- Modify: `README.md`
- Create: `.superpowers/sdd/2026-08-17-crc-trigger-route-recovery-report.md`

**Interfaces:**
- Consumes: corrected transport routes and exact legacy recovery marker from Tasks 1-2.
- Produces: offline end-to-end proof, bilingual operator steps, and a release report containing exact test outputs and commit IDs.

- [ ] **Step 1: Add an offline end-to-end regression for the supplied state shape**

  Exercise the public `run_patch()` API through pending legacy state -> fresh
  source `live_read` -> power-cycle checkpoint -> exact `YES` -> one CRC writer
  -> commit/verify. Capture transport trigger frames with the real transport
  fake where possible and assert the only CRC writer `FF00` frame contains
  `0xE0000`, while writer result/readback still identifies `0xF8000`.

- [ ] **Step 2: Add an offline restore route regression**

  Exercise CRC-before-target restore and assert each writer is preceded by its
  existing fresh two-sector `live_read`; exact confirmations remain two; CRC
  restore routes through `0xE0000` while returning sector `0xF8000`; target
  restore routes/returns `0x60000`.

- [ ] **Step 3: Run integration tests and verify RED, then GREEN without new production behavior**

  Run:

  ```bash
  /Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_end_to_end_offline.py tests/test_restart_resume.py -q
  ```

  If a test fails because a fake does not expose raw trigger frames, minimally
  extend only that test fake; do not add production APIs. Expected final result:
  all tests pass.

- [ ] **Step 4: Update bilingual operator guidance**

  State that for this exact NRC incident the first post-update `patch` command
  is read-only. Document the three exact outcomes (`CRC_PRECHECKED`,
  `CRC_COMMITTED`, partial/unknown), required power cycles, and the prohibition
  on manually editing `state.json`. Explain that displayed actual CRC sector
  `0xF8000` is expected even though the host's internal UDS trampoline route is
  `0xE0000`.

- [ ] **Step 5: Run all focused safety suites**

  ```bash
  /Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_transport.py tests/test_patch.py tests/test_restore.py tests/test_restart_resume.py tests/test_end_to_end_offline.py tests/test_candidate_writer_source_contracts.py tests/test_restore_source_contracts.py tests/test_payload_binaries.py -q
  ```

  Expected: all pass; payload source/binary pin tests prove no V850 artifact
  changed.

- [ ] **Step 6: Run the complete repository suite and static checks**

  ```bash
  /Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest -q
  git diff --check
  git status --short
  ```

  Expected: full suite passes, `git diff --check` is silent, and status lists
  only the intended README/report changes before the final commit.

- [ ] **Step 7: Request independent safety review**

  Ask the reviewer to inspect: raw UDS route bytes for target/CRC patch and
  restore; absence of V850 changes; exact legacy-history predicate; semantic
  prior-arm binding before hardware; no-mutation near misses; consumed retry
  exception; and operator steps. Resolve every Critical or Important finding
  with a fresh RED/GREEN cycle.

- [ ] **Step 8: Write report and commit Task 3**

  Record the exact commands/results, changed file list, payload artifact hashes,
  review verdict, and the statement that no hardware/network operation ran.

  ```bash
  git add README.md tests/test_end_to_end_offline.py .superpowers/sdd/2026-08-17-crc-trigger-route-recovery-report.md
  git commit -m "docs: publish CRC trigger recovery procedure"
  ```
