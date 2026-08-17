# Task 5 Report: Automatic Restore Planning and Ordered Recovery

## Status

**COMPLETE:** implemented first-class recovery from persisted patch incidents
plus the source-reviewed, state-agnostic live-read precheck. The approved V850
cross-build returned `live_read.bin`; its exact binary and zero-DID envelope
hashes are now pinned in the runtime allowlists.

The restore
entry point discovers the newest canonical non-PASS incident, derives only the
persisted minimum-safe sector order, and serializes patch and restore workflows
through one nonblocking artifact-root operation lock.

The workflow preserves the reviewed recovery behavior:

1. strictly parse the patch state, its reachable transition history, incident
   binding, fixed probe evidence, and exact original sector backups;
2. reject malformed, contradictory, already-running, completed, or prior
   indeterminate restore attempts before any writer action;
3. validate bootloader identity and RAM-echo each selected original backup;
4. power-cycle, reconnect, read both affected live sectors with operation 15,
   classify their complete bytes against the incident-bound source/candidates,
   and durably record `*_LIVE_PRECHECKED`;
5. power-cycle, reconnect, require the exact incident-bound destructive
   confirmation, durably record the sector arm state, execute the unchanged
   fixed restore writer once,
   and validate its status and byte-exact readback;
6. for two-sector recovery, restore CRC first, require a complete power cycle,
   reconnect and revalidate identity, then restore the target sector;
7. atomically persist canonical restore state and a final report.

There is no automatic writer retry. Any transport loss, malformed result,
readback uncertainty, or evidence-install failure after arm is terminal
`INDETERMINATE` and directs the operator to external programming or
professional recovery.

## TDD Evidence

Initial RED:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest tests/test_restore.py -v

23 failed
```

All failures were caused by the expected missing `eps_patch.restore` module.
The requested literal `python3.12` executable was not installed, so all Python
verification used the existing project virtual environment running Python
3.12.13.

Review-driven RED added coverage for unreachable/missing transition evidence,
malformed prior restore state, patch/restore mutual exclusion, and restore-root
directory durability:

```text
5 failed
```

After those fixes, an additional producer/consumer consistency review exposed
two edge cases: the patch producer's valid `PASS -> RECOVERY_REQUIRED` path
after final-report installation failure, and in-memory transition retention
after state persistence failure. Three focused regression tests reproduced
those failures before the minimal fixes:

```text
3 failed, 31 deselected
```

The same focused regression tests then passed:

```text
3 passed, 31 deselected
```

Final review added one integrated RED for transactional commit bookkeeping: a
failed `*_COMMITTED` state write left a phantom completed sector in the
following `INDETERMINATE` summary. The new test failed once, then passed after
completed-sector state was rolled back with its unpersisted transition.

Live-read expansion RED/GREEN evidence:

- protocol/transport: `9 failed` for the absent operation, then `9 passed`;
- source/build surface: `5 failed, 3 passed`, then `8 passed`;
- exact incident classification: `21 failed`, then `21 passed`;
- restore integration: `3 failed, 21 passed`, then `24 passed`;
- warning-clean translation unit: `1 failed` on an unused helper under
  `-Werror`, then `1 passed` after isolating the live-read build surface;
- remote manifest termination: `1 failed`, then `1 passed` after binding the
  final payload comma to `live_read`;
- returned-artifact integration: the old BUILD_READY contract failed twice on
  the new binary/manifest, then the exact binary, loader, manifest, and envelope
  pin contract passed `2 passed` after the runtime pins were added.

Task 5 focused GREEN:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest tests/test_restore.py tests/test_live_read_source_contracts.py \
  tests/test_restore_sector_source_contracts.py \
  tests/test_ram_echo_source_contracts.py tests/test_payload_binaries.py -q

77 passed
```

Full-suite GREEN:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest -q

343 passed in 1.84s
```

Final scope hardening restored the 72 retained strict protocol cases in
`tests/test_protocol.py` (including the live-read and candidate-writer
grammars), added no-hardware regression coverage for preflight/transport
rejection when probe evidence already exists and when a recoverable incident
is pending. A successful incident-bound restore resolves that gate; malformed
or indeterminate restore state remains fail-closed. Obsolete protocol
operations remain excluded by the migration.

## Retained Restore Payloads

The build allowlist, runtime pins, and source manifest now include the two
previously reviewed recovery artifacts:

- `ram_echo.bin`: 1,132 bytes,
  `9ad4eb4f3e59466e05e3597d733b07dcce8e6e0751a730227f4767a8439f942e`;
- `restore_sector.bin`: 3,936 bytes,
  `17f17104af1689a2675488957af3bcf1e96d23d2407a2f0c1ee905c691b23d63`.

Both remain under the 4,048-byte shellcode boundary. The restored C sources
retain the reviewed implementation; only their shared-header include was
adapted to the migrated `patch_common.h` name.

The new `payload/live_read.c` source SHA-256 is
`c7e8aad79d44b9ec335ee90eb9974175b66f5004b88b8e7487c727c6cec6135a`.
It streams only the fixed target and CRC regions, reads the two fixed boot magic
words, and has no FACI, DCRA, erase, program, P/E-mode, intent, or staged-SRAM
capability. Host warning-clean validation uses the production `-Wall -Wextra
-Werror` surface with only the target-specific section attribute neutralized.

The returned `live_read.bin` is 1,280 bytes with SHA-256
`3543bbe2ea4077f9cbeb9db31b0bce98636be09ed9017e826bd408eb5058d9ea`.
It is recorded in the generated manifest and `BUILT_PAYLOADS`, remains below
the 4,048-byte shellcode boundary, and loads only when its size and SHA match
both pins. Its deterministic 4,096-byte zero-DID envelope SHA-256 is
`4d102f0c91e7ef8807efcbe48b5bedf8a787e37ff6d3860792b82f35ed4fca2d`
and is the exact `LIVE_READ_ENVELOPE_SHA256` accepted by restore.

## Remote Build Verification

The controller used the running `gcc-v850-elf-master` container
`d8e0d4cf5e92` to run the approved build:

```bash
cd payload
TOOL_PREFIX=v850-elf- ./build.sh
```

The refreshed artifacts establish:

1. GCC 13.2.0/binutils 2.41 in the regenerated manifest;
2. exact source hash
   `c7e8aad79d44b9ec335ee90eb9974175b66f5004b88b8e7487c727c6cec6135a`,
   binary size 1,280, and binary SHA-256
   `3543bbe2ea4077f9cbeb9db31b0bce98636be09ed9017e826bd408eb5058d9ea`;
3. unchanged hashes for every retained binary, including the restore writer;
4. zero-DID envelope SHA-256
   `4d102f0c91e7ef8807efcbe48b5bedf8a787e37ff6d3860792b82f35ed4fca2d`,
   now pinned by production.

## Review and Safety Boundary

Independent review identified and drove fixes for cross-workflow concurrency,
strict reachable histories, malformed prior-state handling, directory fsync,
patch-producer recovery compatibility, and transactional recorder state. A
final integration check also made completed-sector bookkeeping transactional
with its committed transition. The expanded design adds a generic read-only
payload because the retained CRC probes pre-gate on original or patched
instructions and cannot observe arbitrary interrupted state. Complete-sector
classification accepts `other` only for the exact sector covered by the matching
persisted `*_INDETERMINATE` incident; every unaffected or already-restored
sector must equal its incident-derived source/candidate state. The fixed writer
remains bounded by boot identity, persisted incident scope/order, original
backup hash/CRC/context, FACI-idle checks, boot magic, writer status, and complete
readback, and its source and binary were not modified.

Unchanged restore-writer hashes:

- `payload/restore_sector.c`:
  `dac734dbbb543484cfaf7831fbc6d8245cebaeef2485c9bf56a72c832361a153`;
- `payload/build/restore_sector.bin`:
  `17f17104af1689a2675488957af3bcf1e96d23d2407a2f0c1ee905c691b23d63`.

No live ECU, vehicle, Panda, network, or other hardware operation was performed.
All verification used local deterministic fakes, source contracts, and pinned
binary/manifest checks.
