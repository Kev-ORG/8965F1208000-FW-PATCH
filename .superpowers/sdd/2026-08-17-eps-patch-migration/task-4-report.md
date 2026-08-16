# Task 4 Report: Power-Cycle Checkpoint and Two-Sector Patch Workflow

## Status

Implemented the fail-closed comma-local target-then-CRC patch workflow. The
entry point consumes only the fixed `ArtifactLayout`, semantically reloads the
Task 3 probe PASS evidence, derives the exact reviewed two-sector candidates,
allocates a unique UTC attempt directory, and atomically overwrites one
canonical `state.json` after every transition.

The workflow preserves the reviewed order and safety boundaries:

1. complete power cycle, reconnect in application mode, and revalidate identity
   plus both live source sectors;
2. exact target-writer confirmation, durable `TARGET_ARMED`, one writer
   execution, exact status/readback validation, and `TARGET_COMMITTED`;
3. complete power cycle, reconnect in bootloader mode, and validate the exact
   intermediate target/CRC state plus software-CRC/DCRA evidence;
4. exact CRC-writer confirmation, durable `CRC_ARMED`, one writer execution,
   exact status/readback validation, and `CRC_COMMITTED`;
5. complete power cycle, reconnect in application mode, and validate both final
   sectors plus software-CRC/DCRA residue agreement before recording PASS.

There is no automatic writer retry or forward resume. Failures after an armed
or committed writer persist the exact canonical state and restore order:

- before target arm: `FAILED`, `[]`;
- target armed: `TARGET_INDETERMINATE`, `["target"]`;
- target committed: `RECOVERY_REQUIRED`, `["target"]`;
- CRC armed: `CRC_INDETERMINATE`, `["crc", "target"]`;
- CRC committed or final verification pending: `RECOVERY_REQUIRED`,
  `["crc", "target"]`.

## TDD Evidence

Initial RED:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest tests/test_power.py tests/test_patch.py -v

collected 9 items
9 failed
```

The failures were the expected missing `eps_patch.power` and `eps_patch.patch`
modules. The requested literal `python3.12` executable was not installed, so
all Python verification used the existing project virtual environment running
Python 3.12.13.

The retained source-contract and writer fault-model tests were also run before
payload migration and produced the expected source-absence RED result:

```text
23 failed, 29 passed
```

After migrating the reviewed sources, that focused group passed:

```text
52 passed
```

The payload runtime allowlist test then failed as expected while obsolete
`patch`, `patch_v2`, and restoration entries remained in `BUILT_PAYLOADS`. The
allowlist and build surface were pruned to the six retained runtime payloads.

Required Task 4 focused GREEN:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest tests/test_power.py tests/test_patch.py tests/test_crc_workflows.py \
  tests/test_candidate_writer_fault_model.py \
  tests/test_candidate_writer_source_contracts.py \
  tests/test_crc_probe_source_contracts.py \
  tests/test_crc_intermediate_source_contracts.py -v

64 passed in 0.21s
```

Full-suite GREEN:

```text
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python \
  -m pytest -q

276 passed in 1.26s
```

`git diff --check` and `sh -n payload/build.sh` completed with no errors.

## Retained Runtime Payloads

The build surface and manifest now retain only the comprehensive probe plus the
five Task 4 patch payloads. The migrated Task 4 binaries are the previously
reviewed GCC 13.2.0/binutils 2.41 artifacts:

- `crc_probe.bin`: 2,230 bytes,
  `659c845dcf7c63135d29f556fd41367b5516ca6bf9e2fa06c408bd7cdf905c16`;
- `crc_intermediate.bin`: 2,482 bytes,
  `c67fd90df1de30a0b90d5fc4bae6366a940989dc94dedcee4080fc384c40ebd7`;
- `crc_verify.bin`: 1,852 bytes,
  `ea1f7d9f2b08d0d5534a0f8e90e6797455522a2578e0227dc789663d7f794eb7`;
- `write_target_candidate.bin`: 3,934 bytes,
  `d0c600ff4ff266e491ac3a0baf4e77075c1863dc2290ae681a09a5bc1251af26`;
- `write_crc_candidate.bin`: 3,946 bytes,
  `3698aca109af9e700b36a8c7fc4c7bacc7ca22acb9a2fa40864f1abd03cd685a`.

All remain under the 4,048-byte shellcode limit. The manifest binds every
retained source/build input and all six runtime binaries. Obsolete `patch`,
`patch_v2`, and `patch_crc` source/binary/build entries are absent.

Task 3's comprehensive probe owns its narrowed `common.h`, `protocol.h`, and
`dcra.h`. To avoid weakening those reviewed source contracts, the mechanically
migrated patch-era sources retain their own exact shared headers as
`patch_common.h`, `patch_protocol.h`, and `crc_runtime.h`; only include names
were adjusted.

## Self-Review

- `run_patch` has no caller-supplied probe/evidence/output path.
- All writer inputs and envelopes are validated before workflow side effects.
- Every complete-cycle checkpoint is bilingual, Enter-only, followed by a new
  transport connection and exact mode-appropriate identity validation.
- Live two-sector evidence is checked immediately before each writer phase.
- Writer arm state is durably recorded before the one-shot trigger.
- Writer operations have fixed direction checks, six exact zero status stages,
  and complete sector readback verification.
- Final PASS requires exact candidate sectors and matching software/DCRA
  residues with DCRA control restoration.
- Canonical state replacement flushes the file and containing directory.
- Tests cover successful sequencing, all five required failure classes,
  source contracts, fault models, binary allowlisting, and the full regression
  suite.

## Safety Boundary

No live ECU, vehicle, Panda, network, or other hardware operation was performed.
All verification used local deterministic fakes, retained source inspection,
and local binary/manifest checks.
