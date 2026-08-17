# CRC Trigger Route Recovery Release Report

## Status

Verified offline and ready for controller review. The host now keeps CRC payload
direction at actual sector `0xF8000` while routing its UDS `FF00` trampoline
through `0xE0000 / 0x8000`. The exact audited legacy NRC history receives one
fresh read-only classification before any later manually confirmed writer.

## Release commits

- `82fa543` — `fix: separate CRC payload and trigger addresses`
- `b58e1fb` — `fix: recover exact rejected CRC trigger incident`
- `4a2b0b0` — `test: strengthen legacy recovery audit coverage`
- `de48cf5` — `fix: preserve legacy recovery audit through pass`
- Task 3 is the commit containing this report with subject
  `docs: publish CRC trigger recovery procedure`; its authoritative ID is the
  commit containing this file because a commit cannot embed its own hash.

## Task 3 changes

- `tests/test_end_to_end_offline.py`
  - builds the exact pending legacy history through the public workflow;
  - proves fresh source `live_read -> CRC_PRECHECKED -> power cycle -> one
    confirmation -> one CRC writer -> CRC_COMMITTED -> power cycle -> PASS`;
  - invokes the real `EcuTransport.trigger()` route logic through test-only
    bindings and asserts exact raw `FF00` bytes;
  - proves CRC actual/result sector remains `0xF8000` while its trigger frame is
    `3101ff004500000e000000008000`;
  - proves restore order is CRC then target, with a fresh two-sector `live_read`
    immediately before each writer, exactly two confirmations, actual/result
    bases `0xF8000` then `0x60000`, and exact trigger routes `0xE0000` then
    `0x60000`.
- `README.md`
  - documents the exact incident's first post-update `patch` as read-only in
    Chinese and English;
  - documents `CRC_PRECHECKED`, `CRC_COMMITTED`, and partial/unknown outcomes,
    required complete power cycles, exact uppercase `YES`, review before
    restore, and the prohibition on editing `state.json`;
  - explains actual CRC sector `0xF8000` versus internal UDS trampoline route
    `0xE0000 / 0x8000`.
- `.superpowers/sdd/2026-08-17-crc-trigger-route-recovery-report.md`
  - this release evidence.

No production Python, payload/V850/FACI source, binary, manifest, writer
behavior, or state semantics changed in Task 3.

## Cross-workflow TDD evidence

Initial integration command:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_end_to_end_offline.py tests/test_restart_resume.py -q
```

Initial output after adding the regressions:

```text
.FF..........                                                            [100%]
2 failed, 11 passed in 0.58s
```

Both failures were the genuine missing test-fake behavior: `_TriggerPanda` did
not accept the serial argument used by the real binding. Only the test fake was
corrected. No production behavior was added.

Final output:

```text
.............                                                            [100%]
13 passed in 0.52s
```

## Focused safety verification

The brief's literal command names a nonexistent file,
`tests/test_restore_source_contracts.py`, and therefore produced:

```text
no tests ran in 0.00s
ERROR: file or directory not found: tests/test_restore_source_contracts.py
```

The repository's retained file is
`tests/test_restore_sector_source_contracts.py`. Corrected command:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_transport.py tests/test_patch.py tests/test_restore.py tests/test_restart_resume.py tests/test_end_to_end_offline.py tests/test_candidate_writer_source_contracts.py tests/test_restore_sector_source_contracts.py tests/test_payload_binaries.py -q
```

Final output:

```text
........................................................................ [ 32%]
........................................................................ [ 65%]
........................................................................ [ 98%]
....                                                                     [100%]
220 passed in 5.49s
```

## Complete repository verification

Command:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest -q
```

Final output:

```text
........................................................................ [ 15%]
........................................................................ [ 31%]
........................................................................ [ 47%]
........................................................................ [ 63%]
........................................................................ [ 79%]
........................................................................ [ 95%]
......................                                                   [100%]
454 passed in 6.79s
```

`git diff --check` was silent. `git diff --exit-code de48cf5 -- payload` was
silent and exited zero. Before report creation, `git status --short` contained
only:

```text
 M README.md
 M tests/test_end_to_end_offline.py
```

## Payload artifact hashes

```text
03dee5c0435f02bf7bb97681c4392defa61ca6d81db46ad7ae820521bef89281  payload/build/crc_intermediate.bin
2586922b12c8253fe8cbfb7860aa91201682783c6c0f61cd9ccea1aea8197eb0  payload/build/crc_probe.bin
4662f7160592d26e2fac16415cfd90224c1b7c64741254638ce27cbacb979cc0  payload/build/crc_verify.bin
3543bbe2ea4077f9cbeb9db31b0bce98636be09ed9017e826bd408eb5058d9ea  payload/build/live_read.bin
7f4c8cc9f4612d53925c4d239fea1dc4b1987676a83f22222b5e45642559f132  payload/build/probe_pe_cycle.bin
7b79cf5c13ea58e0fd1bd2766592218c42eb214ea3809b7f604c45cfe4673de0  payload/build/restore_sector.bin
17ba9ca3f1b2adaf25b91b1499437045d3402ac7408b5fbe0a45d8cd16639c40  payload/build/write_crc_candidate.bin
b3101d8a2fcb1c262c7d006fde8c156a3a28f7fd6062b8452655c2a0d1b07507  payload/build/write_target_candidate.bin
6a77492ffff58271add3cb6badd1bcf750442700f825b3f7ede791c600dad7fd  payload/build/manifest.json
```

The payload pin/source-contract tests are included in the 220-test focused
run. No payload artifact was rebuilt or modified.

## Independent safety review

Verdict: **Approve with minor corrections**.

- Critical findings: none.
- Important findings: none.
- Minor operator wording: partial/unknown now says to preserve evidence and
  run restore only after review in both languages; resolved before final tests.
- Minor plan typo: the focused command's stale filename is recorded above;
  the brief was not changed because it is outside Task 3's allowed files.

The reviewer independently confirmed the raw CRC/target trigger bytes, actual
and returned sector identities, exact legacy predicate, current reviewed-writer
rederivation before hardware, no-mutation near misses, consumed retry block,
restore order/live reads/confirmation count, operator guidance, and absence of
payload/V850/manifest changes.

## Safety boundary

No hardware, ECU, vehicle, Panda, comma, Docker, SSH, network, or external
service operation ran. All evidence came from local deterministic fakes,
read-only source/diff inspection, pinned artifacts, and offline pytest suites.
