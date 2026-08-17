# CRC Trigger Route Recovery Release Report

## Status

The final-fix wave is verified offline and awaits independent final re-review;
this is not a final approval verdict. The host keeps target/CRC payload
directions at actual sectors `0x60000` and `0xF8000`, while every validated UDS
`FF00` shellcode trigger uses the single bench-proven `0xE0000 / 0x8000`
range. The exact audited legacy NRC history receives one fresh read-only
classification before any later manually confirmed writer, and a final third
indeterminate writer outcome remains restore-loadable but never patch-resumable.

## Release commits

- `82fa543` — `fix: separate CRC payload and trigger addresses`
- `b58e1fb` — `fix: recover exact rejected CRC trigger incident`
- `4a2b0b0` — `test: strengthen legacy recovery audit coverage`
- `de48cf5` — `fix: preserve legacy recovery audit through pass`
- `ebfe3cb` — `docs: publish CRC trigger recovery procedure`
- Review fix round 1 is the commit containing the appended review-fix evidence;
  its authoritative ID is the commit containing this file because a commit
  cannot embed its own hash.
- The final-fix wave and approved fixed-route amendment are in the commit
  containing the appended final-fix evidence. Its authoritative ID is likewise
  the commit containing this file.

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

## Review fix round 1: independent raw-frame literals

The formal Task 3 review identified an Important test-quality issue: the
end-to-end route expectations reconstructed their bytes with
`struct.pack("!II", ...)`, the same operation used by production transport.
That could let production and tests share the same endianness or field-layout
defect.

The three CRC patch, CRC restore, and target restore expectations now use only
complete hand-derived `bytes.fromhex(...)` literals:

```text
CRC:    31 01 ff 00 45 00 00 0e 00 00 00 00 80 00
target: 31 01 ff 00 45 00 00 06 00 00 00 00 80 00
```

No production file is changed. The now-independent expectations initially
passed the two workflow tests:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_end_to_end_offline.py::test_supplied_legacy_crc_incident_uses_one_corrected_route_writer tests/test_end_to_end_offline.py::test_restore_routes_crc_before_target_after_fresh_live_reads -q
..                                                                       [100%]
2 passed in 0.39s
```

For mutation proof only, production trigger packing was temporarily changed
from network/big-endian (`!II`) to little-endian (`<II`). The same command produced
the intended RED:

```text
FF                                                                       [100%]
FAILED tests/test_end_to_end_offline.py::test_supplied_legacy_crc_incident_uses_one_corrected_route_writer
FAILED tests/test_end_to_end_offline.py::test_restore_routes_crc_before_target_after_fresh_live_reads
2 failed in 0.41s
```

The first CRC comparison differed at raw-frame index 7 (`00` versus literal
`0e`), and restore rejected both wrong-layout frames. The mutation was
immediately reverted; `git diff --exit-code HEAD -- eps_patch/transport.py`
was silent. Covering GREEN:

```text
..                                                                       [100%]
2 passed in 0.20s
```

Fresh post-fix verification:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_end_to_end_offline.py -q
...                                                                      [100%]
3 passed in 0.28s

/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_transport.py tests/test_patch.py tests/test_restore.py tests/test_restart_resume.py tests/test_end_to_end_offline.py tests/test_candidate_writer_source_contracts.py tests/test_restore_sector_source_contracts.py tests/test_payload_binaries.py -q
220 passed in 5.28s

/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest -q
454 passed in 6.60s
```

`git diff --check` was silent. Test counts did not change. No hardware,
network, Docker, SSH, Panda, comma, ECU, payload, V850, manifest, FACI,
production Python, writer behavior, or state semantic change occurred.

## Final-fix wave and approved route amendment

The original direction-specific route discussion above is retained as release
history. The current approved contract supersedes it: authentication remains
RAM `0xFEBF0000 / 0x1000`, while every allowed `FF00` payload trigger uses
`0xE0000 / 0x8000` after operation and actual-sector validation. Target and CRC
actual/result sectors remain `0x60000` and `0xF8000`; restore requires one of
those actual bases explicitly.

The same final-fix wave resolves the independent state-audit findings:

- an exact consumed legacy reconciliation followed by one reviewed CRC arm and
  a final third `CRC_INDETERMINATE` is loadable/selectable by restore only;
- public restore first performs identity plus one `OP_LIVE_READ`, persists the
  existing live-precheck checkpoint, and performs no confirmation/writer;
- public patch rejects that suffix before preflight/transport, and any outgoing
  `CRC_PRECHECKED` or `CRC_COMMITTED` transition is invalid;
- pending and consumed exception states bind both reconciliations, PROBED
  identity/hashes, the exact pinned `live_read`, and a currently reconstructed
  reviewed writer before preflight;
- missing, changed, and correlated near misses leave `state.json` unchanged and
  make zero preflight, transport, or confirmation calls.

Strict RED evidence was `7 failed` for the terminal restore/base cases,
`18 failed, 16 passed` for trusted evidence, `13 failed, 8 passed` for the
transport route matrix, and one failed routed target-restore workflow.

Fresh GREEN evidence:

```text
focused terminal/base: 7 passed in 0.56s
focused trusted evidence: 34 passed in 2.40s
focused trigger routes: 21 passed, 21 deselected in 0.03s
routed end to end: 2 passed in 0.21s
patch + restore + transport: 226 passed in 7.32s
focused safety suite: 264 passed in 8.59s
complete repository: 498 passed in 9.93s
```

`git diff --check`, `git diff --exit-code cd03e03 -- payload`, and
`git diff --exit-code 9f34c08 -- payload` were silent and exited zero. The
complete final-fix evidence and self-review are recorded in
`.superpowers/sdd/2026-08-17-crc-trigger-route-recovery/final-fix-report.md`.
No hardware, ECU, Panda, comma, Docker, SSH, network, external service, payload
build, or operator incident-state operation ran. Independent final re-review is
still required.
