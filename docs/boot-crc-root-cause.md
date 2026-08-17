# Boot CRC root cause and two-sector repair

The reviewed target instruction is at `0x664E4` in the `0x60000` target
sector. Its third byte is `0x31`; the patch changes only that byte to `0x10`
at `0x664E6`. The rest of the target sector remains byte-identical to the
semantic probe backup.

The EPS verifies Code Flash through a CRC/DCRA calculation whose physical
range ends in the final CRC sector (`0xf8000`). The four-byte adjustment word
at `0xffdec` compensates for the target-byte change. Its reviewed original
value is `0x0962887f`; the reviewed patched value is `0x414f47cc`. Updating
only `0x60000` would therefore leave the boot-time CRC relationship
inconsistent. Updating only `0xf8000` would make the adjustment describe code
that was not written.

The workflow resolves that dependency with separate one-shot writers. It
writes and verifies the target sector first, power-cycles into the bootloader,
then writes and verifies the CRC sector, power-cycles again, and performs an
independent final CRC/DCRA verification. The persisted state records the
smallest safe restore order before each writer is armed.

If the target writer may have run, the original target backup is the minimum
recovery requirement. If the CRC writer may have run, both original sectors
are required and recovery writes `0xf8000` before `0x60000`. This order puts
the original CRC adjustment back before restoring the code it describes.

These relationships are specific to the reviewed 8965B4512000 layout and
constants. They are not a procedure for other firmware or ECUs.
