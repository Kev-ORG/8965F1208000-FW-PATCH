# DCRA COUT and CRC Adjustment Correction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the comprehensive probe restore DCRA1 COUT correctly and use the mathematically correct CRC candidate adjustment while keeping all host and binary pins exact.

**Architecture:** The DCRA helper remains the sole ECU-side owner of DCRA state. It converts the hardware-visible Ethernet COUT readback into the write value at restoration time and rejects an unreviewed polynomial configuration. Python manifest/protocol/candidate code remains the single host-side owner of immutable CRC facts; V850 artifacts are rebuilt only after source and tests agree.

**Tech Stack:** Python 3.12, pytest, freestanding V850 C, LAN `v850-elf-*` Docker compiler, SHA-256 artifact manifest.

## Global Constraints

- Target identity, UDS route, `0x664e6` single-byte patch, CRC range, and FACI P/E sequences stay unchanged.
- The ECU payload is fail-closed for DCRA polynomials other than reviewed Ethernet (`CTL & 3 == 0`).
- `DCRA1COUT` restore writes `captured_read ^ 0xffffffff` for that configuration, then callers retain the existing exact readback check.
- Corrected immutable CRC tuple is `0x0962887f`, `0xbeb0b833`, `0x414f47cc`, `0xffffffff`.
- Rebuild only through the LAN V850 toolchain; never fabricate a `.bin`, manifest digest, or envelope pin.
- Run all Python tests with `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python`.

---

### Task 1: Lock the corrected host-side CRC facts

**Files:**
- Modify: `tests/test_manifest.py`, `tests/test_protocol.py`, `tests/test_candidate_writer_fault_model.py`
- Modify: `eps_patch/manifest.py`, `eps_patch/protocol.py`, `eps_patch/candidate_writer.py`

**Interfaces:**
- Consumes: `TARGET` immutable CRC fields and `validate_intermediate_crc_evidence()`.
- Produces: `TARGET.crc_patched_prefix_sw == 0xbeb0b833`, `TARGET.crc_patched_adjust_word == 0x414f47cc`, and little-endian candidate bytes `cc474f41`.

- [ ] **Step 1: Write the failing host-constant tests**

```python
assert TARGET.crc_patched_prefix_sw == 0xBEB0B833
assert TARGET.crc_patched_adjust_word == 0x414F47CC
assert CANDIDATE_ADJUSTMENT == bytes.fromhex("cc474f41")
```

- [ ] **Step 2: Run focused tests and verify RED**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_manifest.py tests/test_protocol.py tests/test_candidate_writer_fault_model.py -q`

Expected: failures naming the former prefix, adjustment, or candidate bytes.

- [ ] **Step 3: Change only the immutable tuple and its consumers**

```python
crc_patched_prefix_sw=0xBEB0B833,
crc_patched_adjust_word=0x414F47CC,
CANDIDATE_ADJUSTMENT = bytes.fromhex("cc474f41")
```

Replace corresponding literal checks in manifest and protocol validators; retain their existing exact-match and residue-formula checks.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_manifest.py tests/test_protocol.py tests/test_candidate_writer_fault_model.py -q`

Expected: all selected tests pass.

- [ ] **Step 5: Commit the host facts**

```bash
git add eps_patch/manifest.py eps_patch/protocol.py eps_patch/candidate_writer.py tests/test_manifest.py tests/test_protocol.py tests/test_candidate_writer_fault_model.py
git commit -m "fix: correct CRC candidate constants"
```

### Task 2: Correct and constrain DCRA COUT restoration

**Files:**
- Modify: `tests/test_pe_cycle_source_contracts.py`, `tests/test_crc_probe_source_contracts.py`
- Modify: `payload/dcra.h`, `payload/crc_runtime.h`

**Interfaces:**
- Consumes: captured visible `DCRA_COUT` and `DCRA_CTL`.
- Produces: a common `restore_dcra()` in each helper that writes `(cout ^ 0xffffffffu)` only for the reviewed Ethernet polynomial and returns a failure signal for any other polynomial.

- [ ] **Step 1: Write failing payload source-contract tests**

```python
assert "(ctl & 3u) != 0u" in restore
assert "DCRA_COUT = cout ^ 0xFFFFFFFFu" in restore
assert "restore_dcra" in source and "!= 0u" in source
```

The tests must also assert that each caller sets its existing CRC failure path before it emits an exit record or stream when restoration is rejected.

- [ ] **Step 2: Run source-contract tests and verify RED**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_pe_cycle_source_contracts.py tests/test_crc_probe_source_contracts.py -q`

Expected: failures because the old helpers assign `DCRA_COUT = cout` with no configuration guard.

- [ ] **Step 3: Implement minimal common helper correction**

```c
static uint32_t restore_dcra(uint32_t ctl, uint32_t cout) {
  if ((ctl & 3u) != 0u) return 1u;
  DCRA_CTL = ctl;
  syncp();
  DCRA_COUT = cout ^ 0xFFFFFFFFu;
  syncp();
  return 0u;
}
```

Update each caller to fold a nonzero helper result into its already-reported failure code before the unchanged readback comparison. Do not alter any FACI store, writer source, range, or stream frame layout.

- [ ] **Step 4: Run source-contract tests and verify GREEN**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_pe_cycle_source_contracts.py tests/test_crc_probe_source_contracts.py -q`

Expected: all selected tests pass.

- [ ] **Step 5: Commit DCRA helper correction**

```bash
git add payload/dcra.h payload/crc_runtime.h payload/probe_pe_cycle.c payload/crc_probe.c payload/crc_intermediate.c payload/crc_verify.c tests/test_pe_cycle_source_contracts.py tests/test_crc_probe_source_contracts.py
git commit -m "fix: restore Ethernet DCRA COUT readback"
```

### Task 3: Synchronize payload constants, documentation, and source contracts

**Files:**
- Modify: `payload/dcra.h`, `payload/crc_intermediate.c`, `payload/candidate_writer.h`
- Modify: `tests/test_pe_cycle_source_contracts.py`, `tests/test_crc_intermediate_source_contracts.py`, `tests/test_documentation.py`
- Modify: `docs/boot-crc-root-cause.md`, `README.md`

**Interfaces:**
- Consumes: corrected target manifest tuple.
- Produces: every ECU candidate payload writes or proves only `0x414f47cc`; operator docs describe the read-only validation probe and no longer state the former value as current.

- [ ] **Step 1: Write failing static contract/documentation tests**

```python
assert "CRC_PATCHED_ADJUST_WORD 0x414F47CCu" in dcra
assert "CRC_CANDIDATE_ADJUST 0x414F47CCu" in intermediate
assert "CANDIDATE_ADJUST_WORD 0x414F47CCu" in writer
assert "0xd1f4ce24" not in current_operator_docs
```

- [ ] **Step 2: Run selected static tests and verify RED**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_pe_cycle_source_contracts.py tests/test_crc_intermediate_source_contracts.py tests/test_documentation.py -q`

Expected: failures containing one or more obsolete source constants.

- [ ] **Step 3: Replace only obsolete constants and current operator documentation**

```c
#define CRC_PATCHED_ADJUST_WORD 0x414F47CCu
#define CRC_CANDIDATE_ADJUST 0x414F47CCu
#define CANDIDATE_ADJUST_WORD 0x414F47CCu
```

Keep the original adjustment word and residue unchanged. Preserve historical investigation records as history where appropriate, but current root-cause/operator documentation must label the former candidate as rejected.

- [ ] **Step 4: Run selected static tests and verify GREEN**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_pe_cycle_source_contracts.py tests/test_crc_intermediate_source_contracts.py tests/test_documentation.py -q`

Expected: all selected tests pass.

- [ ] **Step 5: Commit source and documentation synchronization**

```bash
git add payload/dcra.h payload/crc_intermediate.c payload/candidate_writer.h docs/boot-crc-root-cause.md README.md tests/test_pe_cycle_source_contracts.py tests/test_crc_intermediate_source_contracts.py tests/test_documentation.py
git commit -m "fix: synchronize reviewed CRC adjustment"
```

### Task 4: Rebuild and pin affected V850 artifacts

**Files:**
- Modify: `payload/build/*.bin`, `payload/build/manifest.json`
- Modify: `eps_patch/payload.py`, `eps_patch/patch.py`, `tests/test_payload_binaries.py`, `tests/test_probe.py`, `tests/test_evidence.py`, `tests/test_patch.py`

**Interfaces:**
- Consumes: LAN V850 build output from `TOOL_PREFIX=v850-elf- ./build.sh`.
- Produces: matching binary SHA-256, source-manifest hashes, and 4096-byte envelope SHA-256 pins for all changed payloads.

- [ ] **Step 1: Run source and host tests before compiling**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest -q`

Expected: only stale-artifact/pin tests may fail; any logic test failure blocks compilation.

- [ ] **Step 2: Rebuild through the LAN V850 compiler**

Run: `cd payload && TOOL_PREFIX=v850-elf- ./build.sh`

Expected: manifest and all retained `.bin` files produced; every shellcode is at most 4048 bytes.

- [ ] **Step 3: Write failing pin reconciliation tests from actual generated data**

```python
assert BUILT_PAYLOADS[name]["sha256"] == sha256(binary).hexdigest()
assert pinned_envelope == sha256(build_envelope(binary)).hexdigest()
```

Run the binary tests before changing host pins; they must report the stale digest/pin.

- [ ] **Step 4: Update host pins exactly to generated manifest and envelopes**

Update no literal except values computed from the just-built bytes. Verify the build manifest source hash set matches its checked-in sources.

- [ ] **Step 5: Run fresh full verification**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest -q && git diff --check && sh -n payload/build.sh`

Expected: all tests pass, whitespace is clean, and the build script parses.

- [ ] **Step 6: Commit reviewed artifacts and pins**

```bash
git add payload/build eps_patch/payload.py eps_patch/patch.py tests/test_payload_binaries.py tests/test_probe.py tests/test_evidence.py tests/test_patch.py
git commit -m "build: pin corrected DCRA payloads"
```

### Task 5: Final operator handoff

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: final built probe envelope hash and test evidence.
- Produces: a concise bilingual instruction that the first post-update run is `python3.12 eps_patch.py probe`, is read-only, and must reach PASS before `patch` is allowed.

- [ ] **Step 1: Verify operator wording is present**

Run: `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_documentation.py -q`

Expected: all documentation assertions pass.

- [ ] **Step 2: Commit final handoff if README changed after artifact reconciliation**

```bash
git add README.md tests/test_documentation.py
git commit -m "docs: explain corrected read-only probe"
```
