# 8965B4512000 EPS patch

This repository contains one deliberately narrow, comma-local workflow for
the reviewed 8965B4512000 EPS. It is not a general ECU flashing tool. It
performs one read-only probe, one two-sector patch, and recovery only from a
persisted local incident created by that patch.

## Install and preflight

Sync this repository on comma using the normal source checkout. Do not copy a
Python cache, build cache, previous runtime-artifact directory, or incident
data into the checkout. The retained `payload/build` binaries and manifest are
the reviewed inputs; do not rebuild, replace, or edit them on the device.

Run each command from this repository with comma's supported Python 3.12
environment. `--serial <Panda serial>` is the only optional argument. The
workflow uses its fixed local evidence location:
`/data/eps-patch/artifacts`.

Before any hardware command, make the vehicle safe, use stable EPS power, and
stop comma and Panda services. The preflight checks the Python version and
dependencies, then confirms that the comma tmux session, `pandad`, and the
Python Panda wrapper are not running. Resolve every preflight error before
continuing.

## 1. Probe once

```
python3.12 eps_patch.py probe
```

Run `probe` once before `patch` or `restore`. It is read-only and creates the
fixed local evidence only after a semantic `PASS`. That PASS includes the
exact EPS/Panda identity, complete original target and CRC-sector backups,
the original instruction context, FACI P/E-cycle snapshots, CRC/DCRA checks,
and host validation. A printed path, a partial artifact, or a successful
transport connection is not a PASS.

`probe` refuses an existing fixed probe directory before preflight or any
transport action. Preserve that evidence; it is the recovery snapshot bound to
the patch workflow.

If `probe` fails, stop and correct the environment or supported-EPS mismatch;
do not proceed to `patch`. Do not change the stored evidence.

## 2. Patch

```
python3.12 eps_patch.py patch
```

The patch changes one reviewed byte in the target sector (`0x60000`) and then
updates the dependent CRC adjustment in the CRC sector (`0xf8000`). It always
writes the target sector (`0x60000`) first, then the CRC sector (`0xf8000`).
Each write is prechecked against the stored semantic PASS and a fresh live
readback.

The command stops at every displayed complete power-cycle checkpoint. Switch
off vehicle/EPS power, wait for complete discharge, restore stable power, and
Press Enter only after the complete power cycle. A UDS reset is never a power
cycle. For a successful patch, do this after `PROBED`, after
`TARGET_COMMITTED`, and after `CRC_COMMITTED`; reconnect only when prompted.

At each destructive writer prompt, inspect the displayed sector, source,
candidate, CRC, and envelope values. Enter the exact confirmation text shown
by the command for `WRITE-TARGET` or `WRITE-CRC`; any extra character,
abbreviation, or changed value stops the operation before that writer is
armed.

`PASS` means the final independent readback exactly matches both candidates
and validates the software CRC/DCRA result. `FAILED` means no writer was
armed. `TARGET_INDETERMINATE`, `CRC_INDETERMINATE`, and
`RECOVERY_REQUIRED` mean the persisted state names the minimum recovery scope;
they are not permission to retry `patch`.

`patch` also refuses to begin while a recoverable persisted patch incident
lacks a successful bound restore. Restore that incident before a new patch
attempt.

## 3. Restore a persisted incident

```
python3.12 eps_patch.py restore
```

`restore` has no path, backup, or incident selector. It discovers the newest
recoverable local patch incident and uses only the original backups bound to
the fixed semantic PASS. For a two-sector incident it restores the CRC sector
(`0xf8000`) first, then the target sector (`0x60000`). A target-only incident
restores only the target sector.

For every selected sector, the command checks the original backup in RAM,
requires a complete power cycle before the live read, checks both live sectors,
requires another complete power cycle before arming the writer, and requires
the exact displayed `RESTORE-SECTOR` confirmation. Between two sectors it
requires another complete power cycle after CRC commit before beginning the
target-sector checks. At every checkpoint: switch off vehicle/EPS power, wait
for complete discharge, restore stable power, and Press Enter only after the
complete power cycle.

`restore` never retries a writer. If it reports `INDETERMINATE`, live state is
uncertain, confirmation fails, or a writer/readback communication error occurs,
stop. Do not run another patch or restore attempt. Use an external programmer
or professional recovery with the persisted local incident and original
backups intact.

## Scope limits

This workflow supports only the exact 8965B4512000 identity and reviewed
old-UDS configuration encoded here. It does not support another EPS, arbitrary
firmware, altered payloads, manual sector selection, manual evidence edits, or
automatic retries. Hardware work remains the operator's responsibility.
