# EPS Restore Live-Read Precheck Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a build-ready, state-agnostic two-sector read-only payload and require incident-aware live classification before every restore writer arm.

**Architecture:** Operation 15 reuses the strict two-region framing shape without CRC/DCRA semantic records. The restore host derives exact source/candidate sectors from trusted backups, validates each fresh observation against the persisted incident and completed restore progress, and records a new live-prechecked state before the existing writer path.

**Tech Stack:** Python 3.12, pytest, freestanding V850 C, existing framed CAN protocol, GCC 13.2.0/binutils 2.41 remote build boundary.

## Global Constraints

- The payload reads only `[0x60000, 0x68000)` and `[0xF8000, 0x100000)`.
- It has no FACI/DCRA capability and performs no erase/program operation.
- Existing `restore_sector.c`, `restore_sector.bin`, intent layout, hash, and writer flow remain unchanged.
- A fresh live read occurs before every writer arm, including target after CRC restore.
- `other` is accepted only for the sector named by the matching persisted `*_INDETERMINATE` incident.
- No binary digest or envelope pin is invented; missing production pin fails closed.
- No hardware or network access is permitted.

---

### Task 1: Strict live-read protocol operation

**Files:**
- Modify: `eps_patch/protocol.py`
- Modify: `eps_patch/transport.py`
- Modify: `tests/test_protocol.py`
- Modify: `tests/test_transport.py`

**Interfaces:**
- Consumes: existing BEGIN/REGION/DATA/MAGIC/STATUS/END frames.
- Produces: `OP_LIVE_READ = 15` and `StreamCollector(expected_operation=OP_LIVE_READ) -> StreamResult` with exactly two `RegionResult` values.

- [ ] **Step 1: Write failing collector tests**

Add a frame builder that emits target then CRC regions with per-region and
combined CRC-32. Assert an exact stream returns operation 15, no scalar sector,
two exact regions, target magic, one zero status, and no CRC/DCRA/FACI fields.
Add parametrized failures for wrong first base, reversed/missing/truncated/extra
regions, nonzero status, and bad combined CRC.

- [ ] **Step 2: Run the collector tests and verify RED**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest tests/test_protocol.py -k live_read -v
```

Expected: collection fails because `OP_LIVE_READ` is absent.

- [ ] **Step 3: Implement the minimal strict collector**

Add operation 15, route it to the existing strict two-region collector, allow
the collector to transition directly from the second `REGION_END` to `MAGIC`,
require BEGIN0 value `TARGET.sector_base`, and return a plain `StreamResult`
without CRC semantic records.

- [ ] **Step 4: Add and run transport RED/GREEN**

Assert `trigger(operation=OP_LIVE_READ)` is accepted with no sector-base
override and still rejects any supplied override. Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest tests/test_protocol.py tests/test_transport.py -k live_read -v
```

Expected after implementation: PASS.

### Task 2: Read-only payload source and build-ready surface

**Files:**
- Create: `payload/live_read.c`
- Create: `tests/test_live_read_source_contracts.py`
- Modify: `payload/patch_protocol.h`
- Modify: `payload/build.sh`
- Modify: `payload/build/manifest.json`
- Modify: `eps_patch/payload.py`
- Modify: `tests/test_payload_binaries.py`

**Interfaces:**
- Consumes: `patch_common.h` runtime/CAN primitives and fixed target constants.
- Produces: build target `live_read`, reviewed source hash, and `BUILD_READY_PAYLOADS = ("live_read",)` without a binary pin.

- [ ] **Step 1: Write failing source-contract/build-surface tests**

Require `live_read.c`, `LIVE_READ_PAYLOAD`, `PROTO_OP_LIVE_READ`, two fixed
region calls in target-then-CRC order, exact magic/status/end frames, and no
FACI/DCRA include or erase/program/PE symbols. Require `build.sh` to compile and
retain `live_read.bin`, the source manifest to bind `live_read.c`, and the
production runtime pin table not to claim the missing binary.

- [ ] **Step 2: Run source/build tests and verify RED**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest tests/test_live_read_source_contracts.py tests/test_payload_binaries.py -v
```

Expected: failures for absent source, operation define, and build entries.

- [ ] **Step 3: Implement the minimal C source and build entries**

Implement a local `stream_live_region` that reads each flash word, updates
per-region and combined CRC-32, emits indexed data, and writes only CAN/runtime
state. `exploit()` captures both magic words, streams exactly two regions, emits
one zero status and END, then restores runtime state and halts.

Add `live_read.c` to build inputs, payload loop, cleanup allowlist, source
manifest and source hash. Do not create `live_read.bin` or a payload manifest
entry locally.

- [ ] **Step 4: Run source/build tests GREEN**

Run the Step 2 command. Expected: source/build-readiness tests PASS while the
explicit production-pin test proves live-read is not yet runnable.

### Task 3: Incident-aware complete-sector classification

**Files:**
- Modify: `eps_patch/restore.py`
- Modify: `tests/test_restore.py`

**Interfaces:**
- Consumes: `RestorePlan`, `TrustedProbeEvidence`, and one live-read `StreamResult`.
- Produces: immutable live classification/evidence and a fail-closed pre-arm validator.

- [ ] **Step 1: Write failing classification tests**

Build exact target/CRC source and candidate bytes from the probe fixture. Cover
the four incident rows from the design and the post-CRC-commit target precheck.
For each row assert accepted source/candidate/other combinations and reject a
contradictory non-current sector, wrong bases/order/length, bad magic, nonzero
status, extra protocol fields, and a mutable/non-byte region.

- [ ] **Step 2: Run classification tests and verify RED**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest tests/test_restore.py -k live_precheck -v
```

Expected: failures because the classifier/validator is absent.

- [ ] **Step 3: Implement exact candidate derivation and policy validation**

Use `build_crc_candidate(..., target.crc_patched_adjust_word.to_bytes(4,
"little"))`. Classify by complete byte equality only. Validate the exact result
shape, compute SHA-256 for evidence, and apply the incident/completed-sector
policy table without fallback or retry.

- [ ] **Step 4: Run classification tests GREEN**

Run the Step 2 command. Expected: PASS.

### Task 4: Require live read before every restore writer arm

**Files:**
- Modify: `eps_patch/restore.py`
- Modify: `tests/test_restore.py`

**Interfaces:**
- Consumes: payload set member `live_read`, `OP_LIVE_READ`, classifier, existing callbacks/transports.
- Produces: `CRC_LIVE_PRECHECKED` and `TARGET_LIVE_PRECHECKED` durable states before existing armed states.

- [ ] **Step 1: Write failing orchestration tests**

Extend fake restore transports with `run_payload`. For the two-sector success
path require event order:

```text
crc RAM echo -> power cycle -> crc live read -> power cycle -> crc writer ->
power cycle -> target RAM echo -> power cycle -> target live read ->
power cycle -> target writer
```

Assert each `*_ARMED` evidence includes both classifications and hashes. Add
tests proving contradictory live state stops before confirmation/writer and a
target live-read failure after CRC commit persists terminal `INDETERMINATE`.

- [ ] **Step 2: Run orchestration tests and verify RED**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest tests/test_restore.py -k 'live_read or live_precheck' -v
```

Expected: failures because restore does not request live-read payloads/states.

- [ ] **Step 3: Implement fail-closed payload validation and orchestration**

Add `LIVE_READ_ENVELOPE_SHA256: str | None = None`. Production validation must
reject `None`; tests may monkeypatch it to the SHA-256 of one exact synthetic
envelope. Insert live-read connection, identity check, validation/evidence,
durable prechecked state and required power cycle before the unchanged writer
connection/confirmation/arm/trigger block. Extend strict prior-state parsing
with the two new states.

- [ ] **Step 4: Run restore tests GREEN**

Run all of `tests/test_restore.py`. Expected: PASS.

### Task 5: BUILD_READY verification and report

**Files:**
- Modify: `.superpowers/sdd/2026-08-17-eps-patch-migration/task-5-report.md`

**Interfaces:**
- Consumes: all Task 1-4 changes.
- Produces: a documented `BUILD_READY` handoff with exact remaining remote-build outputs.

- [ ] **Step 1: Verify the writer remains byte-for-byte unchanged**

Run:

```bash
shasum -a 256 payload/restore_sector.c payload/build/restore_sector.bin
```

Require the committed binary SHA-256
`17f17104af1689a2675488957af3bcf1e96d23d2407a2f0c1ee905c691b23d63`.

- [ ] **Step 2: Run all locally runnable tests**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest -q
git diff --check
sh -n payload/build.sh
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m py_compile eps_patch/protocol.py eps_patch/transport.py eps_patch/restore.py
```

Expected: all tests/checks that do not require `live_read.bin` pass.

- [ ] **Step 3: Record BUILD_READY evidence**

Update the Task 5 report with RED/GREEN counts, source SHA-256, unchanged writer
SHA-256, no hardware/network statement, and the exact remote command:

```bash
cd payload && TOOL_PREFIX=v850-elf- ./build.sh
```

State that the next step is to return `live_read.bin`, regenerated
`payload/build/manifest.json`, and the computed zero-DID envelope SHA-256; do
not claim runtime completion before those pins are reviewed.

- [ ] **Step 4: Commit BUILD_READY**

```bash
git add eps_patch payload tests .superpowers/sdd/2026-08-17-eps-patch-migration/task-5-report.md
git commit -m "feat: gate restore writers on live flash state"
```
