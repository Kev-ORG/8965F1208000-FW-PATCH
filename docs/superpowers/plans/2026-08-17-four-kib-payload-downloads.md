# Four-KiB-Only Payload Downloads Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every patch and restore ECU operation use only the reviewed 4 KiB envelope at `0xFEBF0000`; candidates are copied and modified locally before the unchanged FACI P/E sequence.

**Architecture:** Delete host-to-SRAM staging. A specialized envelope carries a reviewed fixed-direction intent, but the payload copies its exact live source sector into `SRAM_BUFFER`, makes its one allowed change, validates source/candidate state, then invokes the current one-shot writer. CRC prechecks read Flash directly and restore uses the same local reverse derivation.

**Tech Stack:** Python 3.12, pytest, V850 freestanding C, reviewed 4 KiB authenticated envelopes, LAN V850 Docker compiler.

## Global Constraints

- Use `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python` for every Python test command.
- Every RequestDownload is exactly `0xFEBF0000` with length `0x1000`; do not probe or use another RAM range.
- Preserve reviewed `patch_v2` / `restore_v1` FACI stores, polling bounds, cleanup order, one-shot semantics, and post-trigger indeterminate handling.
- No host 32 KiB upload, RAM chunking, or arbitrary backup restore is permitted.
- Rebuild V850 sources on the LAN compiler before changing binary, manifest, review, or envelope SHA-256 pins.
- Do not operate vehicle hardware during implementation or verification.

---

### Task 1: Replace staged transport with one-envelope execution

**Files:**

- Modify: `eps_patch/transport.py:36-447`
- Modify: `tests/test_transport.py`, `tests/test_patch.py`, `tests/test_restore.py`

**Interfaces:**

- Produces: `EcuTransport.run_payload(image, *, operation: int, new_uds: bool) -> StreamResult` as the only execution API.
- Removes: `RamBlob`, `STAGED_ENVELOPE_SHA256`, `run_staged_payload`, and `_best_effort_staged_cleanup`.

- [ ] **Step 1: Write the failing transport tests**

Add a fake-UDS writer test that asserts the sole RequestDownload call is:

```python
assert uds.request_download_calls == [(TARGET.ram_address, TARGET.envelope_length)]
assert (TARGET.ram_address, TARGET.envelope_length) == (0xFEBF0000, 0x1000)
```

Add regressions asserting the transport module has no `RamBlob` or `run_staged_payload`; update workflow fakes to record ordinary `run_payload` calls and writer `sector_base`.

- [ ] **Step 2: Verify RED**

Run:

```sh
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_transport.py tests/test_patch.py tests/test_restore.py -q
```

Expected: staged API/second-download failures.

- [ ] **Step 3: Implement the boundary**

Delete staging primitives. Have `run_payload` call `image.validate()` for a `SpecializedPayloadImage`, call `prepare_and_upload()` once, then trigger using `image.sector_base` only for specialized writers. Keep pre-trigger errors ordinary and wrap only post-trigger destructive failures in `PostTriggerTransportError`.

- [ ] **Step 4: Verify GREEN and commit**

Run the Step 2 command; then:

```sh
git add eps_patch/transport.py tests/test_transport.py tests/test_patch.py tests/test_restore.py
git commit -m "refactor: require four kib payload downloads"
```

### Task 2: Bind specialized writer intents to locally derived candidates

**Files:**

- Modify: `eps_patch/candidate_writer.py:14-217`, `eps_patch/payload.py:191-256`
- Modify: `tests/test_candidate_writer_fault_model.py`, `tests/test_payload_binaries.py`

**Interfaces:**

- Produces: a `CandidateWriterPayloadImage` bound to operation, sector base, fixed live source CRC32, fixed local-candidate CRC32 and fixed contexts.
- Removes: host sector bytes, `staged_candidate`, `staged_candidate_sha256`, and `backup_sha256` as executable-data authorization.

- [ ] **Step 1: Write failing intent tests**

Test that target/CRC writer image builders take fixed source/candidate CRCs and no 32768-byte argument:

```python
assert "staged_candidate" not in CandidateWriterPayloadImage.__dataclass_fields__
with pytest.raises(CandidateWriterError, match="candidate CRC"):
  build_target_candidate_payload_image(..., candidate_crc32=wrong_crc)
```

Also reject wrong operation, base, source CRC, candidate CRC or context before upload.

- [ ] **Step 2: Verify RED**

Run:

```sh
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_candidate_writer_fault_model.py tests/test_payload_binaries.py -q
```

Expected: current builders still require staged bytes.

- [ ] **Step 3: Implement local-candidate intent semantics**

Keep the reviewed 128-byte intent layout, but rename/bind its CRC fields to source and locally derived candidate values. Preserve base, direction, fixed contexts, magic, zero-reserved bytes and intent CRC. Make `SpecializedPayloadImage` authorize the exact template/intent/sector base without a supplied backup SHA.

- [ ] **Step 4: Verify GREEN and commit**

Run the Step 2 command; then:

```sh
git add eps_patch/candidate_writer.py eps_patch/payload.py tests/test_candidate_writer_fault_model.py tests/test_payload_binaries.py
git commit -m "refactor: bind writers to local candidates"
```

### Task 3: Construct patch candidates inside ECU payloads

**Files:**

- Modify: `payload/candidate_writer.h:49-180`, `payload/crc_probe.c`, `payload/crc_intermediate.c`
- Modify: `eps_patch/patch.py:245-460,851-895`
- Modify: `tests/test_candidate_writer_source_contracts.py`, `tests/test_crc_probe_source_contracts.py`, `tests/test_crc_intermediate_source_contracts.py`, `tests/test_patch.py`

**Interfaces:**

- Consumes: fixed Flash at `WRITER_SECTOR_BASE` and the reviewed intent.
- Produces: locally constructed `SRAM_BUFFER` candidate plus current readback/status protocol.
- Preserves: `enter_pe`, `erase_sector`, `program_sector`, `exit_pe`, cleanup and status meanings after validation.

- [ ] **Step 1: Write failing source/workflow tests**

Require a bounded copy before any P/E:

```python
assert "copy_sector_to_sram(WRITER_SECTOR_BASE" in source
assert source.index("copy_sector_to_sram(") < source.index("enter_pe(&guard)")
```

Require `crc_probe.c` and `crc_intermediate.c` to contain neither `crc_region(SRAM_BUFFER` nor `PROTO_CRC_SRAM_ECHO_` assignments. Require patch orchestration to use only `run_payload` and preserve two returned live regions plus DCRA evidence.

- [ ] **Step 2: Verify RED**

Run:

```sh
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_candidate_writer_source_contracts.py tests/test_crc_probe_source_contracts.py tests/test_crc_intermediate_source_contracts.py tests/test_patch.py -q
```

Expected: source still validates preloaded SRAM and prechecks still emit staged-SRAM evidence.

- [ ] **Step 3: Implement bounded local construction**

Copy exactly `TARGET_LENGTH` bytes from `WRITER_SECTOR_BASE` to `SRAM_BUFFER`, feeding the existing watchdog cadence. Validate live source CRC/context; alter only the target instruction or CRC adjustment word; then validate local candidate CRC/context before idle/P/E gates. Remove precheck SRAM echo fields and update Python protocol validation to retain ranges, adjustment, DCRA and returned regions. Replace patch staged calls with `run_payload`.

- [ ] **Step 4: Verify GREEN and commit**

Run the Step 2 command; then:

```sh
git add payload/candidate_writer.h payload/crc_probe.c payload/crc_intermediate.c eps_patch/patch.py eps_patch/candidate_writer.py tests/test_candidate_writer_source_contracts.py tests/test_crc_probe_source_contracts.py tests/test_crc_intermediate_source_contracts.py tests/test_patch.py
git commit -m "feat: derive patch candidates on ecu"
```

### Task 4: Construct fixed restore candidates inside the ECU

**Files:**

- Modify: `payload/restore_sector.c:1-104`, `eps_patch/restore.py:18-610,1045-1164`
- Modify: `eps_patch/protocol.py` if the SRAM-echo fields are mandatory
- Modify: `tests/test_restore_sector_source_contracts.py`, `tests/test_restore.py`, `tests/test_protocol.py`, `tests/test_end_to_end_offline.py`

**Interfaces:**

- Consumes: fixed reverse-direction intent, latest `OP_LIVE_READ` classification, selected incident order.
- Produces: one specialized 4 KiB restore envelope and a local source-to-candidate copy.
- Removes: `ram_echo` payload, echo states/checkpoints and all backup-RAM upload.

- [ ] **Step 1: Write failing restore tests**

Require no `ram_echo` input or 32768-byte argument. Require one `run_payload(... OP_RESTORE_SECTOR ...)` per writer. Source contracts must prove copy precedes `enter_pe`, target changes exactly PATCHED-to-ORIGINAL, CRC changes exactly CANDIDATE-to-ORIGINAL, and no uploaded-SRAM CRC check remains.

- [ ] **Step 2: Verify RED**

Run:

```sh
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_restore.py tests/test_restore_sector_source_contracts.py tests/test_protocol.py tests/test_end_to_end_offline.py -q
```

Expected: `ram_echo`, `RamBlob`, or uploaded-backup expectations remain.

- [ ] **Step 3: Implement fixed reverse derivation**

Delete ram-echo validation and checkpoints but retain a live-read checkpoint before each arm. Replace restore intent backup-SHA/staged-CRC values with fixed base/direction/source/candidate CRC/context. In C validate exact current PATCHED/CANDIDATE state, copy locally, change only the fixed field back to ORIGINAL, validate candidate, then use the unchanged writer sequence. Make new state records live-prechecked → armed; retain old terminal FAILED records as readable but non-resumable.

- [ ] **Step 4: Verify GREEN and commit**

Run the Step 2 command; then:

```sh
git add payload/restore_sector.c eps_patch/restore.py eps_patch/protocol.py tests/test_restore.py tests/test_restore_sector_source_contracts.py tests/test_protocol.py tests/test_end_to_end_offline.py
git commit -m "feat: derive restore candidates on ecu"
```

### Task 5: Rebuild, pin, document and release

**Files:**

- Modify: `payload/build.sh`, `payload/build/manifest.json`, changed `payload/build/*.bin`
- Modify: `eps_patch/payload.py`, `eps_patch/patch.py`, `eps_patch/restore.py`, `README.md`
- Modify: `tests/test_payload_binaries.py`, `tests/test_documentation.py`

**Interfaces:**

- Produces: exact retained 4 KiB-only source/binary/manifest/envelope pins and human guidance for pre-trigger download rejection.

- [ ] **Step 1: Write failing artifact/documentation tests**

Require no `ram_echo` in the retained build set, all binaries `<= 0xFD0`, manifest sources equal current source hashes, and README state the literal `0xFEBF0000`/`0x1000` boundary without a 32 KiB upload instruction.

- [ ] **Step 2: Verify RED**

Run:

```sh
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_payload_binaries.py tests/test_documentation.py -q
```

Expected: current build/pins retain `ram_echo` and stale source hashes.

- [ ] **Step 3: Build and update pins**

On the LAN compiler run `cd payload && TOOL_PREFIX=v850-elf- ./build.sh`. Recover only retained `.bin` files and `manifest.json`. Verify compiler versions, source hashes, sizes, binary hashes, template review hashes and deterministic zero-DID envelope hashes before updating literals. Remove `ram_echo` from the build loop, manifest and payload registry.

- [ ] **Step 4: Verify release and commit**

Run:

```sh
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest -q
git diff --check
sh -n payload/build.sh
git status --short
```

Expected: clean full suite, valid shell script, exact pins and no intermediate artifacts. Then:

```sh
git add payload/build.sh payload/build eps_patch/payload.py eps_patch/patch.py eps_patch/restore.py tests/test_payload_binaries.py tests/test_documentation.py README.md
git commit -m "build: pin four kib only payload workflow"
```

## Plan Self-Review

- Tasks 1–4 remove staging and implement local patch/restore derivation; Task 5 rebuilds and verifies all affected artifacts.
- No step permits alternate RAM download addresses, chunking, arbitrary backup restore or changes to FACI P/E safety rules.
- Every production change has a preceding focused failing test and explicit verification command.
