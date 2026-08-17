# EPS Restore Live-Read Precheck Design

## Goal

Add one state-agnostic, read-only RAM payload that returns the complete live
target and CRC sectors before each restore writer is armed. The host binds that
observation to the selected persisted patch incident and the trusted original
backups. The existing fixed restore writer, its intent format, and its binary
remain unchanged.

## Safety Boundary

The new `live_read` payload has operation `OP_LIVE_READ = 15`. It always reads
exactly these two 32 KiB Code Flash regions, in this order:

1. target: `[0x60000, 0x68000)`;
2. CRC: `[0xF8000, 0x100000)`.

It has no input intent and no state-dependent instruction gate. It does not
include FACI or DCRA headers, enter P/E mode, erase, program, write Code Flash,
or write any non-CAN MMIO. Its only writes are the already reviewed runtime/CAN
transmit bookkeeping needed to stream the observation. The stream contains an
operation/version header, two fixed region descriptors, complete indexed data,
per-region CRC-32, both fixed boot magic observations, one zero status, and one
combined CRC-32.

The Python protocol collector accepts no omitted, reordered, duplicated,
truncated, extra, or mislabeled region and no nonzero status. The restore host
also requires exact boot identity, both magic words, two immutable sector byte
strings of exact length, and an empty destructive/diagnostic result surface.

## Live Classification

The host deterministically reconstructs the reviewed patch candidates from the
trusted probe backups and the fixed manifest constants. Each live sector is
classified only by complete byte equality as `source`, `candidate`, or
`other`; instruction bytes or CRC words alone never establish a classification.

The selected patch incident defines the allowed pre-arm state:

| Incident | Target live state | CRC live state |
| --- | --- | --- |
| `TARGET_INDETERMINATE` | source, candidate, or other | source |
| target-only `RECOVERY_REQUIRED` | candidate | source |
| `CRC_INDETERMINATE` | candidate | source, candidate, or other |
| two-sector `RECOVERY_REQUIRED` | candidate | candidate |

After the CRC sector has been restored in a two-sector attempt, the next target
precheck requires CRC=`source` and target=`candidate`. Thus `other` is accepted
only for the exact sector whose persisted armed incident explicitly permits a
partial erase/program outcome. A contradictory observation fails before writer
confirmation or arm; no automatic retry or alternate restore order is added.

## Orchestration

For every sector in the persisted restore order:

1. validate boot identity and RAM-echo the exact original backup;
2. persist `*_ECHO_VERIFIED` and request a complete power cycle;
3. reconnect, validate boot identity, run the fixed `live_read` payload, classify
   both live sectors, persist `*_LIVE_PRECHECKED`, and request another complete
   power cycle because the RAM payload is non-returning;
4. reconnect, validate boot identity, obtain the existing exact incident-bound
   destructive confirmation, durably persist `*_ARMED`, and invoke the existing
   restore writer once;
5. validate and persist the existing byte-exact writer readback and
   `*_COMMITTED` state.

Every pre-arm live-read failure is handled by the existing state policy. Before
any writer has armed it becomes `FAILED`; after a previous sector has armed it
becomes terminal `INDETERMINATE`, preserving the no-retry external-recovery
boundary.

## Build-Ready Boundary

Local work prepares `payload/live_read.c`, the operation/collector/transport
surface, source contracts, build-loop and cleanup entries, and the manifest's
source hash. It must not invent a binary hash or envelope pin.

Before the binary is available, runtime validation fails closed with an
explicit “reviewed live_read payload is not built and pinned” error. Tests cover
protocol strictness, classification and orchestration with a test-only exact
envelope pin, plus the missing-production-pin gate. This state is reported as
`BUILD_READY`.

A later approved V850 GCC 13.2.0/binutils 2.41 build must provide
`payload/build/live_read.bin`, its size and SHA-256 manifest entry, and the
resulting 4,096-byte envelope SHA-256 pin. After those exact values are added,
the complete restore integration and retained-binary allowlist tests can run
without test overrides.

## Verification

- protocol tests prove strict two-region live-read collection;
- source contracts forbid FACI/DCRA capability and restrict flash reads and
  MMIO stores;
- classification tests cover every incident/order combination and reject
  contradictory unaffected-sector state;
- restore integration tests prove live-read and its added power cycle occur
  before confirmation/arm for each writer;
- fault tests prove malformed/unknown-disallowed observations never invoke the
  writer and preserve existing `FAILED`/`INDETERMINATE` behavior;
- existing restore-writer source and binary SHA-256 values remain unchanged;
- no hardware or network operation is performed.
