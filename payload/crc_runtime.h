#ifndef SIENNA_PAYLOAD_DCRA_H
#define SIENNA_PAYLOAD_DCRA_H

#define DCRA_IN   MMIO32(0xFFD51000u)
#define DCRA_COUT MMIO32(0xFFD51004u)
#define DCRA_CTL  MMIO32(0xFFD51020u)

#define CRC_RANGE_START 0x00018000u
#define CRC_RANGE_END   0x000FFDF0u
#define CRC_PATCH_VALUE 0x10u

#if !defined(PATCH_CRC_PAYLOAD)
static uint32_t crc_adjustment(uint32_t prefix_crc) {
  return prefix_crc ^ 0xFFFFFFFFu;
}
#endif

static uint32_t flash_crc_byte(
  uint32_t address, uint8_t hypothetical, uint32_t new_adjust
) {
  if (hypothetical != 0u) {
    if (address == PATCH_ADDRESS) return CRC_PATCH_VALUE;
    if (address >= CRC_ADJUST && address < CRC_RANGE_END) {
      return (new_adjust >> ((address - CRC_ADJUST) * 8u)) & 0xFFu;
    }
  }
  return MMIO8(address);
}

static uint32_t crc_prefix_sw(
  uint8_t patched_target, const struct runtime_guard *guard
) {
  uint32_t address;
  uint32_t crc = 0xFFFFFFFFu;
  for (address = CRC_RANGE_START; address < CRC_ADJUST; ++address) {
    uint8_t value = MMIO8(address);
    if (patched_target != 0u && address == PATCH_ADDRESS) value = CRC_PATCH_VALUE;
    crc = crc32_update(crc, value);
    if ((address & 0x7FFu) == 0u) feed_watchdog(guard);
  }
  return crc ^ 0xFFFFFFFFu;
}

static uint32_t crc_full_sw(
  uint8_t hypothetical, uint32_t new_adjust, const struct runtime_guard *guard
) {
  uint32_t address;
  uint32_t crc = 0xFFFFFFFFu;
  for (address = CRC_RANGE_START; address < CRC_RANGE_END; ++address) {
    crc = crc32_update(
      crc, (uint8_t)flash_crc_byte(address, hypothetical, new_adjust)
    );
    if ((address & 0x7FFu) == 0u) feed_watchdog(guard);
  }
  return crc ^ 0xFFFFFFFFu;
}

static uint32_t dcra_full_raw(
  uint8_t hypothetical, uint32_t new_adjust, const struct runtime_guard *guard
) {
  uint32_t address;
  DCRA_CTL = 0u;
  DCRA_COUT = 0xFFFFFFFFu;
  syncp();
  for (address = CRC_RANGE_START; address < CRC_RANGE_END; address += 4u) {
    uint32_t word = MMIO32(address);
    if (hypothetical != 0u && address == (PATCH_ADDRESS & ~3u)) {
      word = (word & 0xFF00FFFFu) | (CRC_PATCH_VALUE << 16);
    }
    if (hypothetical != 0u && address == CRC_ADJUST) word = new_adjust;
    DCRA_IN = word;
    if ((address & 0x7FFu) == 0u) feed_watchdog(guard);
  }
  syncp();
  return DCRA_COUT;
}

static void capture_dcra(uint32_t *ctl, uint32_t *cout) {
  uint32_t entry_ctl = DCRA_CTL;
  uint32_t entry_cout = DCRA_COUT;
  *ctl = entry_ctl;
  *cout = entry_cout;
}

static uint32_t restore_dcra(uint32_t entry_ctl, uint32_t entry_cout) {
  if ((entry_ctl & 3u) != 0u) return 1u;
  DCRA_CTL = entry_ctl;
  syncp();
  DCRA_COUT = entry_cout ^ 0xFFFFFFFFu;
  syncp();
  return 0u;
}

static int stream_crc_region(
  uint8_t operation,
  uint8_t slot,
  uint32_t base,
  const struct runtime_guard *guard,
  uint32_t *combined_crc
) {
  uint32_t offset;
  uint32_t region_crc = 0xFFFFFFFFu;
  uint32_t header = ((uint32_t)PROTO_VERSION << 8)
    | ((uint32_t)operation << 16) | ((uint32_t)slot << 24);

  if (can_send(PROTO_REGION_BEGIN | header, base, guard) != 0) return 1;
  if (can_send(PROTO_REGION_LENGTH | header, TARGET_LENGTH, guard) != 0) return 2;
  for (offset = 0u; offset < TARGET_LENGTH; offset += 4u) {
    uint32_t word = MMIO32(base + offset);
    uint32_t byte_index;
    for (byte_index = 0u; byte_index < 4u; ++byte_index) {
      uint8_t value = (uint8_t)(word >> (byte_index * 8u));
      region_crc = crc32_update(region_crc, value);
      *combined_crc = crc32_update(*combined_crc, value);
    }
    if (can_send(PROTO_DATA | ((offset >> 2) << 8), word, guard) != 0) return 3;
    if ((offset & 0x7FFu) == 0u) feed_watchdog(guard);
  }
  if (can_send(
    PROTO_REGION_END | header, region_crc ^ 0xFFFFFFFFu, guard
  ) != 0) return 4;
  return 0;
}

#if !defined(PATCH_CRC_PAYLOAD)
static int send_crc_stream(
  uint8_t operation,
  const uint32_t values[PROTO_CRC_RECORD_COUNT],
  const struct runtime_guard *guard
) {
  uint32_t combined_crc = 0xFFFFFFFFu;
  uint32_t slot;
  uint32_t begin = ((uint32_t)PROTO_VERSION << 8)
    | ((uint32_t)operation << 16);

  (void)send_begin;

  if (can_send(PROTO_BEGIN0 | begin, CRC_RANGE_START, guard) != 0) return 1;
  if (can_send(PROTO_BEGIN1 | begin | (1u << 24), 2u, guard) != 0) return 2;
  if (stream_crc_region(operation, 0u, TARGET_BASE, guard, &combined_crc) != 0) return 3;
  if (stream_crc_region(operation, 1u, CRC_SECTOR_BASE, guard, &combined_crc) != 0) return 4;
  for (slot = 0u; slot < PROTO_CRC_RECORD_COUNT; ++slot) {
    if (can_send(
      PROTO_CRC_RECORD | (slot << 8) | (4u << 16), values[slot], guard
    ) != 0) return 5;
  }
  if (can_send(PROTO_MAGIC, MMIO32(MAGIC0_ADDRESS), guard) != 0) return 6;
  if (can_send(PROTO_MAGIC | (1u << 8), MMIO32(MAGIC1_ADDRESS), guard) != 0) return 7;
  if (can_send(PROTO_STATUS | (1u << 8), 0u, guard) != 0) return 8;
  if (can_send(PROTO_END, combined_crc ^ 0xFFFFFFFFu, guard) != 0) return 9;
  return 0;
}

static void halt_crc_error(
  uint8_t operation,
  uint8_t stage,
  uint32_t code,
  const struct runtime_guard *guard
) {
  uint32_t begin = ((uint32_t)PROTO_VERSION << 8)
    | ((uint32_t)operation << 16);
  (void)can_send(PROTO_BEGIN0 | begin, CRC_RANGE_START, guard);
  (void)send_error(stage, code, guard);
  runtime_end(guard);
  for (;;) {
  }
}
#endif

#endif
