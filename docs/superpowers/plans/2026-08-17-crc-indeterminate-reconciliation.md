# CRC Indeterminate Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correctly demultiplex UDS Response Pending frames and safely reconcile one persisted `CRC_INDETERMINATE` attempt by exact read-only two-sector classification before any possible CRC writer retry.

**Architecture:** The host transport will classify ISO-TP RoutineControl negative-response single frames before the private payload collector. The patch state machine will reuse the already reviewed `live_read` payload to classify complete live sectors: CRC source resumes to one manually confirmed writer, CRC candidate skips the writer and resumes final verification, and any other bytes remain restore-only without mutating the incident state. No V850 source, binary, FACI sequence, writer intent, erase/program primitive, or candidate byte changes.

**Tech Stack:** Python 3.12, pytest, immutable JSON state history, existing Panda/opendbc transport adapter, existing pinned `live_read` and writer payloads.

## Global Constraints

- Run tests with `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python`.
- Work directly on the current local `main`, as previously requested; do not create a worktree.
- Never run hardware operations, Panda connections, or network operations during implementation or verification.
- Every production behavior change must begin with a failing test.
- The only allowed new forward edges are `CRC_INDETERMINATE -> CRC_PRECHECKED` and `CRC_INDETERMINATE -> CRC_COMMITTED` after one exact `live_read` classification.
- A CRC source result permits at most one new manual writer attempt; CRC candidate permits no writer; partial/other remains restore-only.
- Keep `automatic_retry` and `automatic_forward_resume` false.

---

### Task 1: Demultiplex UDS Response Pending from payload frames

**Files:**
- Modify: `tests/test_transport.py`
- Modify: `eps_patch/transport.py:298-318`

**Interfaces:**
- Consumes: `EcuTransport.collect_stream(*, operation: int, timeout: float = 60.0) -> StreamResult`.
- Produces: the same public method, with exact ISO-TP single-frame classification and raw-frame diagnostics.

- [ ] **Step 1: Add failing transport tests**

Add real collector tests that feed response-route CAN frames through `FakePanda.can_batches`:

```python
def _ram_echo_frames(sector: bytes) -> list[bytes]:
  frames = [
    bytes([FrameType.BEGIN0, PROTOCOL_VERSION, OP_RAM_ECHO, 0])
      + struct.pack("<I", 0xFEBF2000),
    bytes([FrameType.BEGIN1, PROTOCOL_VERSION, OP_RAM_ECHO, 1])
      + struct.pack("<I", len(sector)),
  ]
  frames.extend(
    bytes([FrameType.DATA]) + struct.pack("<H", index) + b"\x00"
      + sector[index * 4:index * 4 + 4]
    for index in range(0x2000)
  )
  frames.extend((
    bytes([FrameType.MAGIC, 0, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.MAGIC, 1, 0, 0]) + struct.pack("<I", 0x5AA5A55A),
    bytes([FrameType.STATUS, 1, 0, 0]) + bytes(4),
    bytes([FrameType.END, 0, 0, 0]) + struct.pack("<I", binascii.crc32(sector)),
  ))
  return frames

def test_collect_stream_ignores_routine_pending_with_arbitrary_padding():
  pending = bytes.fromhex("03 7f 31 78 aa bb cc dd")
  sector = bytes((index * 17) & 0xFF for index in range(0x8000))
  with EcuTransport(bindings=fake_bindings([])) as transport:
    FakePanda.instances[-1].can_batches = [[
      (0x7A9, pending, 0),
      *((0x7A9, frame, 0) for frame in _ram_echo_frames(sector)),
    ]]
    result = transport.collect_stream(operation=OP_RAM_ECHO, timeout=1.0)
  assert result.operation == OP_RAM_ECHO

def test_collect_stream_reports_nonpending_routine_nrc_and_raw_frame():
  frame = bytes.fromhex("03 7f 31 22 aa bb cc dd")
  with pytest.raises(TransportError, match=r"NRC 0x22.*037f3122aabbccdd"):
    transport.collect_stream(operation=OP_RAM_ECHO, timeout=0.1)

def test_collect_stream_reports_unknown_payload_frame_raw_bytes():
  frame = bytes.fromhex("03 01 02 03 04 05 06 07")
  with pytest.raises(TransportError, match="0301020304050607"):
    transport.collect_stream(operation=OP_RAM_ECHO, timeout=0.1)
```

- [ ] **Step 2: Run the three tests and verify RED**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_transport.py -k 'pending or nonpending or unknown_payload_frame' -q
```

Expected: nonzero-padding pending is rejected as frame type `0x03`; diagnostic tests lack NRC/raw bytes.

- [ ] **Step 3: Implement exact demultiplexing**

In `collect_stream`, classify only exact eight-byte ISO-TP single frames before `StreamCollector.consume`:

```python
if (
  len(frame) == 8 and frame[0] == 0x03
  and frame[1:3] == b"\x7f\x31"
):
  nrc = frame[3]
  if nrc == 0x78:
    continue
  raise TransportError(
    f"RoutineControl negative response NRC 0x{nrc:02x}; raw={frame.hex()}"
  )
```

When `StreamCollector` raises `ProtocolError`, include `frame.hex()` in the `TransportError` without changing collector ordering or validation.

- [ ] **Step 4: Run focused and complete transport tests**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_transport.py -q
```

Expected: all transport tests pass.

- [ ] **Step 5: Commit Task 1**

```bash
git add eps_patch/transport.py tests/test_transport.py
git commit -m "fix: demultiplex routine response pending frames"
```

---

### Task 2: Validate and classify the pinned live-read result in patch

**Files:**
- Modify: `tests/test_patch.py`
- Modify: `eps_patch/patch.py:24-93,621-650,861-915`

**Interfaces:**
- Consumes: the existing `PayloadImage` named `live_read`, envelope SHA-256 `4d102f0c91e7ef8807efcbe48b5bedf8a787e37ff6d3860792b82f35ed4fca2d`, `StreamResult`, and fixed `CrcCandidate`.
- Produces: `_validate_crc_reconciliation(result: object, candidate: CrcCandidate, target: TargetManifest) -> str`, returning only `"source"` or `"candidate"`; all other inputs raise `PatchError`.

- [ ] **Step 1: Add failing payload-pin and classifier tests**

Extend `tests/test_patch.py::_payloads()` to construct the existing pinned `live_read` envelope and add a real two-region fixture:

```python
def _live_read_result(target_sector: bytes, crc_sector: bytes) -> StreamResult:
  return StreamResult(
    operation=OP_LIVE_READ,
    sector=None,
    magic_words=(TARGET.magic_word, TARGET.magic_word),
    statuses=((1, 0),),
    regions=(
      RegionResult(TARGET.sector_base, target_sector),
      RegionResult(TARGET.crc_sector_base, crc_sector),
    ),
  )
```

Test exact source and candidate classifications. Parametrize partial CRC, wrong target, wrong operation, wrong magic, wrong bases/lengths, unexpected CRC/DCRA/FACI records, and malformed payload pin; each must raise before any writer authorization.

- [ ] **Step 2: Run classifier tests and verify RED**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_patch.py -k 'live_read or reconciliation_classification' -q
```

Expected: missing patch `live_read` pin/classifier failures.

- [ ] **Step 3: Add the reviewed pin and exact classifier**

Import `OP_LIVE_READ`, add the reviewed envelope digest to `_PAYLOAD_DIGESTS`, and implement structural validation equivalent to the restore live-read contract but returning only exact patch-forward states:

```python
def _validate_crc_reconciliation(result, candidate, target):
  target_live, crc_live = _regions(result, target, "CRC reconciliation")
  if (
    result.operation != OP_LIVE_READ
    or result.sector is not None
    or result.magic_words != (target.magic_word, target.magic_word)
    or result.statuses != ((1, 0),)
    or result.faci_values or result.crc_values or result.crc is not None
    or result.dcra_values or result.dcra is not None
  ):
    raise PatchError("CRC reconciliation live-read contract is not exact")
  if target_live != candidate.target_final:
    raise PatchError("CRC reconciliation target sector is not the exact candidate")
  if crc_live == candidate.crc_source:
    return "source"
  if crc_live == candidate.crc_final:
    return "candidate"
  raise PatchError("CRC reconciliation found a partial or unknown CRC sector; restore is required")
```

- [ ] **Step 4: Run focused patch validation tests**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_patch.py -k 'payload or live_read or reconciliation_classification' -q
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit Task 2**

```bash
git add eps_patch/patch.py tests/test_patch.py
git commit -m "feat: classify uncertain CRC with live read"
```

---

### Task 3: Resume exactly one CRC-indeterminate incident without mutating failures

**Files:**
- Modify: `tests/test_patch.py`
- Modify: `tests/test_restart_resume.py`
- Modify: `tests/test_restore.py`
- Modify: `eps_patch/patch.py:163-572,730-818`
- Modify: `eps_patch/restore.py:80-121,615-690`

**Interfaces:**
- Consumes: schema-2 patch states validated by `restore._load_patch_state`, `PowerCycleCheckpoint`, and Task 2 `_validate_crc_reconciliation`.
- Produces: resume selection for one current `CRC_INDETERMINATE`; exact recovery edges to `CRC_PRECHECKED` or `CRC_COMMITTED`; unchanged state bytes on reconciliation failure.

- [ ] **Step 1: Add failing source-branch workflow test**

Create a real persisted `CRC_INDETERMINATE` by running the existing workflow until the first CRC writer raises after trigger. On the next invocation, supply only one `OP_LIVE_READ` result containing target candidate + CRC source. Assert:

```python
assert operations == [OP_LIVE_READ]
assert confirmations == []
assert state["result"] == "CRC_PRECHECKED"
assert state["restore_order"] == ["target"]
assert state["power_cycle"] == {
  "completed_state": "CRC_PRECHECKED",
  "next_state": "CRC_ARMED",
}
```

Then invoke again after the checkpoint and assert exactly one `OP_WRITE_CRC_CANDIDATE`, only after exact `YES`.

- [ ] **Step 2: Run source-branch test and verify RED**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_patch.py -k 'reconciles_crc_source' -q
```

Expected: current resume selector rejects the unresolved incident before transport.

- [ ] **Step 3: Add failing candidate and partial/unknown tests**

For target candidate + CRC candidate, assert only `OP_LIVE_READ`, no confirmation/writer, `CRC_COMMITTED`, restore order `['crc', 'target']`, and checkpoint `CRC_COMMITTED -> VERIFY_PENDING`. For partial/unknown CRC, wrong target, identity mismatch, transport error, or malformed readback, save the original `state.json` bytes and assert the invocation raises while `state.json` remains byte-for-byte unchanged.

- [ ] **Step 4: Add failing retry-limit and state-audit tests**

After source reconciliation, make the single permitted writer indeterminate again. Assert the history contains two `CRC_INDETERMINATE` transitions and every later `patch` invocation rejects before `preflight`, `transport_factory`, or `confirmation`. Add loader tests proving the two new recovery edges are accepted only from `CRC_INDETERMINATE`, while missing/wrong checkpoints and invented edges remain rejected.

- [ ] **Step 5: Run all new state tests and verify RED**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_patch.py tests/test_restart_resume.py tests/test_restore.py -k 'indeterminate or reconciliation' -q
```

Expected: resume selection, recovery edges, or immutable-failure assertions fail for the missing feature.

- [ ] **Step 6: Implement selector, state edges, and isolated reconciliation**

Update both canonical state graphs so `CRC_INDETERMINATE` has only `CRC_PRECHECKED` and `CRC_COMMITTED` as normal successors. In `_select_patch_resume`, select a current schema-2 `CRC_INDETERMINATE` only when its transition history contains exactly one occurrence; two occurrences remain unresolved and unselected.

Handle reconciliation in a dedicated branch before the ordinary destructive-stage exception recorder:

```python
if entry is PatchState.CRC_INDETERMINATE:
  preflight()
  with transport_factory() as transport:
    boot_identity = transport.read_bootloader_identity()
    _require_boot_identity(boot_identity, trusted.identity)
    live = transport.run_payload(
      patch_payloads["live_read"], operation=OP_LIVE_READ, new_uds=new_uds,
    )
  classification = _validate_crc_reconciliation(live, candidate, target)
  # Persist only after full validation succeeds. Source -> CRC_PRECHECKED;
  # candidate -> CRC_COMMITTED. Then persist/emit the exact checkpoint and exit.
```

Do not route any exception from this branch through `_failure_for_phase`; propagate it as `PatchError` while leaving the original incident bytes unchanged. Preserve the original incident timestamp, probe digest, sequence ordering, and `automatic_retry=False`.

- [ ] **Step 7: Run focused patch/restore/restart suites**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_patch.py tests/test_restore.py tests/test_restart_resume.py -q
```

Expected: all selected tests pass.

- [ ] **Step 8: Commit Task 3**

```bash
git add eps_patch/patch.py eps_patch/restore.py tests/test_patch.py tests/test_restore.py tests/test_restart_resume.py
git commit -m "fix: reconcile one uncertain CRC writer outcome"
```

---

### Task 4: Full safety regression and operator documentation

**Files:**
- Modify: `README.md`
- Verify: all Python, source-contract, payload-manifest, offline end-to-end, patch, and restore tests.

**Interfaces:**
- Consumes: completed Tasks 1-3.
- Produces: human-readable recovery instructions matching the implemented state flow and a clean verified repository.

- [ ] **Step 1: Add README operator guidance**

Document the exact post-install sequence in both Chinese and English:

```text
Power-cycle vehicle/EPS and comma, reconnect SSH, run python3.12 eps_patch.py patch.
CRC_PRECHECKED => power-cycle, rerun patch, inspect WRITE-CRC, type YES.
CRC_COMMITTED => power-cycle, rerun patch for final verification; no CRC writer runs.
partial/unknown => stop patch and run restore; never retry patch.
```

State explicitly that `0x03` is an ISO-TP single-frame length byte and only exact UDS `7F 31 78` is ignored; no outcome is inferred from DTC state.

- [ ] **Step 2: Run syntax and whitespace checks**

Run:

```bash
git diff --check
sh -n payload/build.sh
```

Expected: both exit zero.

- [ ] **Step 3: Run focused safety suite**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_transport.py tests/test_protocol.py tests/test_patch.py tests/test_restore.py tests/test_restart_resume.py tests/test_candidate_writer_fault_model.py tests/test_offline_e2e.py -q
```

Expected: all selected tests pass.

- [ ] **Step 4: Run the complete repository suite freshly**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest -q
```

Expected: all tests pass with no unexpected skips, failures, or errors.

- [ ] **Step 5: Request code review and address only verified findings**

Use `superpowers:requesting-code-review` against the spec and this plan. Any review finding must be processed with `superpowers:receiving-code-review`, reproduced, fixed TDD-first, and followed by the focused and full suites again.

- [ ] **Step 6: Commit documentation/final verified changes**

```bash
git add README.md
git commit -m "docs: explain uncertain CRC reconciliation"
```

- [ ] **Step 7: Verify the final commit and clean tree**

Run:

```bash
git status --short
git log -5 --oneline
```

Expected: empty status and the transport, reconciliation, and documentation commits at `HEAD`.
