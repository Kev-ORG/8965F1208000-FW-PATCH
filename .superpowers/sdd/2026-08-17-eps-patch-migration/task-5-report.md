# Task 5 Report: Automatic Restore Planning and Ordered Recovery

## Status

Implemented first-class recovery from persisted patch incidents. The restore
entry point discovers the newest canonical non-PASS incident, derives only the
persisted minimum-safe sector order, and serializes patch and restore workflows
through one nonblocking artifact-root operation lock.

The workflow preserves the reviewed recovery behavior:

1. strictly parse the patch state, its reachable transition history, incident
   binding, fixed probe evidence, and exact original sector backups;
2. reject malformed, contradictory, already-running, completed, or prior
   indeterminate restore attempts before any writer action;
3. validate bootloader identity, RAM-echo each selected original backup, and
   require the exact incident-bound destructive confirmation;
4. durably record the sector arm state, execute the fixed restore writer once,
   and validate its status and byte-exact readback;
5. for two-sector recovery, restore CRC first, require a complete power cycle,
   reconnect and revalidate identity, then restore the target sector;
6. atomically persist canonical restore state and a final report.

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

Task 5 focused GREEN:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest tests/test_restore.py tests/test_restore_sector_source_contracts.py \
  tests/test_ram_echo_source_contracts.py tests/test_payload_binaries.py -v

47 passed in 0.32s
```

Full-suite GREEN:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest -q

319 passed in 1.47s
```

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

## Review and Safety Boundary

Independent review identified and drove fixes for cross-workflow concurrency,
strict reachable histories, malformed prior-state handling, directory fsync,
patch-producer recovery compatibility, and transactional recorder state. A
final integration check also made completed-sector bookkeeping transactional
with its committed transition. A
suggestion to require an exact live affected-sector hash before restore was not
adopted: an armed incident explicitly permits partial erase/program state, and
the retained fixed probes pre-gate their reads on either original or patched
instructions. Such a check would reject the recovery state this task must
preserve. The fixed writer remains bounded by boot identity, persisted incident
scope/order, original backup hash/CRC/context, FACI-idle checks, boot magic,
writer status, and complete readback.

No live ECU, vehicle, Panda, network, or other hardware operation was performed.
All verification used local deterministic fakes, source contracts, and pinned
binary/manifest checks.
