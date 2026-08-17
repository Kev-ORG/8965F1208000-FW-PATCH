# Single Payload Per Invocation Design

## Problem

The patch state machine currently performs a read-only CRC precheck payload and
then opens a second UDS transport for the corresponding writer in the same
process invocation. Each RAM payload sends its result and then remains in its
terminal loop. The ECU therefore cannot be assumed to answer the second UDS
identity request. On the bench this produced two Panda connection messages and
then `timeout waiting for response`.

The persisted result was `FAILED`, not an armed or indeterminate state. That
means no destructive writer was authorized or triggered in the failed attempt.
The ECU must nevertheless be fully power-cycled before another command because
the read-only payload may still be running.

## Safety Invariant

One invocation of `eps_patch.py probe`, `patch`, or `restore` may trigger at
most one ECU RAM payload. A second payload always requires a persisted planned
checkpoint, process exit, complete vehicle/EPS/comma power cycle, SSH
reconnection, and rerunning the same command.

No automatic ECU reset, Panda reconnect, timeout-based retry, or assumed
watchdog recovery is accepted as proof of a complete power cycle.

## Patch State Flow

The patch workflow retains its fixed payloads and writer binaries but separates
the two prechecks from their writers:

1. `STARTED -> PROBED`: validate fixed evidence and preflight, persist and exit.
2. `PROBED -> TARGET_PRECHECKED`: run only `crc_probe`, validate and persist both
   live sectors and CRC/DCRA evidence, then persist a power-cycle checkpoint and
   exit.
3. `TARGET_PRECHECKED -> TARGET_ARMED -> TARGET_COMMITTED`: after reboot, read
   identity, require the exact target confirmation, run only the fixed target
   writer, validate its complete readback, persist a checkpoint and exit.
4. `TARGET_COMMITTED -> CRC_PRECHECKED`: after reboot, run only
   `crc_intermediate`, validate and persist its evidence, then persist a
   power-cycle checkpoint and exit.
5. `CRC_PRECHECKED -> CRC_ARMED -> CRC_COMMITTED`: after reboot, require the
   exact CRC confirmation, run only the fixed CRC writer, validate readback,
   persist a checkpoint and exit.
6. `CRC_COMMITTED -> VERIFY_PENDING -> PASS`: after reboot, run only
   `crc_verify` and publish the final report.

`TARGET_PRECHECKED` is resumable only toward `TARGET_ARMED` after its exact
checkpoint. `CRC_PRECHECKED` is resumable only toward `CRC_ARMED`. A failure
before target arm remains `FAILED` with no restore scope. A failure after the
target has committed remains `RECOVERY_REQUIRED` with target restore scope.
Armed and post-trigger uncertainty rules do not change.

Existing terminal `FAILED` attempts remain historical records and are never
resumed or retried. Because they have no restore scope, a new patch attempt may
start only after the operator performs the required complete power cycle.

## Restore Audit

Restore already follows the required separation:

- `STARTED` or `CRC_COMMITTED` runs only `live_read`, persists
  `CRC_LIVE_PRECHECKED` or `TARGET_LIVE_PRECHECKED`, and exits for a complete
  power cycle.
- A later invocation in a live-prechecked state runs exactly one restore writer.
- A two-sector restore commits CRC first, power-cycles, performs a fresh target
  live read, power-cycles again, and only then arms the target writer.

No restore production behavior needs to change. Regression tests will enforce
the shared one-payload-per-invocation invariant so a future refactor cannot
collapse a precheck and writer into one invocation.

## Testing

Tests will first demonstrate the current failure by recording every transport
and payload execution across the lifecycle. They will require:

- no invocation executes more than one payload;
- patch checkpoints include `TARGET_PRECHECKED -> TARGET_ARMED` and
  `CRC_PRECHECKED -> CRC_ARMED`;
- no writer confirmation or writer transport occurs during a precheck
  invocation;
- the target and CRC writers retain their exact order and one-shot behavior;
- restore continues to execute at most one payload per invocation for both
  one-sector and two-sector recovery;
- old schema-1 states are never newly resumable;
- the README lists every planned patch checkpoint and the rerun procedure.

The mandatory Python 3.12 full suite, `git diff --check`, and shell syntax check
must pass. No vehicle operation and no V850 rebuild are part of this change.
