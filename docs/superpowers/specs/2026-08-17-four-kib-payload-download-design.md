# Four-KiB-Only Payload Download Design

## Goal

Remove the unverified 32 KiB `RequestDownload` staging path. Every ECU-side
operation must download exactly one reviewed 4 KiB envelope at the already
validated payload address `0xFEBF0000` and then perform any sector copy or
candidate construction inside the running payload.

## Context

The migrated workflow invokes `run_staged_payload()` before patch prechecks,
candidate writers, restore RAM echo, and restore writers. That function first
requests a 32 KiB download at `0xFEBF2000`. The ECU rejects that range with
`REQUEST_DOWNLOAD - request out of range` before payload authentication or
triggering, so no FACI erase/program operation occurs.

The real-bench-validated `patch_v2` and `restore_v1` instead download only the
4 KiB envelope at `0xFEBF0000`. Each payload copies its fixed Flash source
sector into `SRAM_BUFFER`, makes its tightly constrained change there, validates
it, then follows the reviewed FACI P/E sequence.

## Chosen Architecture

### Download boundary

`EcuTransport` retains one execution path for all payloads:

1. validate the exact 4 KiB envelope SHA-256 pin;
2. enter programming session and unlock;
3. write the existing DID context;
4. issue exactly one `RequestDownload(0xFEBF0000, 0x1000)`;
5. authenticate the envelope and trigger its fixed operation.

There is no RequestDownload to `SRAM_BUFFER`, no arbitrary host-provided RAM
blob, and no chunking, alternate address, or speculative RAM-range probing.

### Patch candidate construction

The target and CRC writers build their own candidate in `SRAM_BUFFER` before
any FACI P/E command.

- The target writer copies exactly `0x8000` bytes from `0x60000`, verifies the
  fixed ORIGINAL instruction word, changes only the fixed target instruction
  word to its pinned PATCHED value, and verifies the candidate context and CRC.
- The CRC writer copies exactly `0x8000` bytes from `0xF8000`, verifies that
  target Flash is already patched and that the live CRC adjustment has its
  ORIGINAL value, changes only the fixed adjustment word to its pinned
  CANDIDATE value, and verifies the candidate context and CRC.
- The non-destructive patch prechecks read live Flash directly and report the
  two sectors plus CRC/DCRA observations. They do not require an SRAM echo of
  host-staged data.

The existing exact candidate intent remains an envelope-bound authorization for
the fixed operation and source/candidate expectations. It no longer represents
host RAM contents. The payload must reject the operation before P/E when any
live source, fixed context, candidate CRC, magic value, or intent field is not
exact.

### Restore candidate construction

Restore uses the same 4 KiB-only boundary. It never downloads a 32 KiB backup.

- For a target-sector restore, the writer accepts only the exact fixed PATCHED
  live state, copies the live target sector to SRAM, changes only the fixed
  instruction word back to ORIGINAL, verifies the exact derived candidate, and
  then applies the existing reviewed erase/program/readback sequence.
- For a CRC-sector restore, the writer accepts only the exact fixed CRC
  candidate state with the target already patched, copies the live CRC sector
  to SRAM, changes only the fixed adjustment word back to ORIGINAL, verifies
  the exact derived candidate, and then uses the same reviewed sequence.
- Live-read classification and incident ordering remain required before every
  writer arm. States that are unknown, mixed, indeterminate, or inconsistent
  with the persisted incident are rejected without a writer trigger.

This preserves the ability to restore the two fixed transaction changes while
deliberately rejecting a request to install an arbitrary historical 32 KiB
backup. Such an arbitrary backup transfer has no validated delivery mechanism
in this target and remains out of scope.

### Failure and resume semantics

- A RequestDownload rejection before payload trigger remains `FAILED`, with no
  erase/program operation and no automatic retry.
- Writer errors after arming retain the existing indeterminate/recovery state
  rules; this design does not weaken them.
- Planned power-cycle checkpoints and manual restart/resume behaviour are
  unchanged.
- Existing failed attempts created solely by the rejected unarmed download are
  non-recoverable failed records and must not be treated as a reason to invoke
  restore.

## Required Changes

1. Replace staged transport execution with fixed-envelope execution and remove
   `RamBlob` from patch and restore orchestration.
2. Modify the patch/restore writer payload sources so candidate construction is
   local, bounded to one sector, and completed before FACI entry.
3. Remove host-staging-only evidence fields and CRC probe SRAM-echo dependence;
   retain live-sector/readback and DCRA evidence.
4. Update intent construction, protocol validation, manifests, source-contract
   tests, transport tests, workflow tests, binary pins, and README safety text.
5. Rebuild every changed V850 payload on the LAN compiler and update only the
   resulting reviewed binaries, manifest hashes, and envelope pins.

## Acceptance Criteria

- No production code can issue RequestDownload for any address/length other
  than `0xFEBF0000`/`0x1000`.
- Patch and restore orchestration perform no host 32 KiB transfer.
- Each writer copies exactly one fixed source sector locally, modifies only its
  permitted byte/word, validates before FACI P/E, and retains exact readback
  verification.
- A rejected RequestDownload is clearly reported as pre-trigger and does not
  arm or classify a writer as indeterminate.
- All changed payload binaries are rebuilt and exact-pinned; no placeholder or
  stale build artifact is accepted.
- Python 3.12 test suite and source/binary contract tests pass.

## Out of Scope

- Testing or probing alternative ECU RAM download ranges.
- Multi-request RAM chunk staging.
- Restoring arbitrary, user-supplied 32 KiB historical content.
- Changes to the reviewed FACI erase/program ordering, polling bounds, cleanup,
  DCRA restoration, power-cycle workflow, or automatic-retry policy.
