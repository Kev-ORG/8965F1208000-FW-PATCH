#ifndef EPS_PATCH_PAYLOAD_DCRA_H
#define EPS_PATCH_PAYLOAD_DCRA_H

#define DCRA_IN MMIO32(0xFFD51000u)
#define DCRA_COUT MMIO32(0xFFD51004u)
#define DCRA_CTL MMIO32(0xFFD51020u)
#define CRC_RANGE_START 0x00018000u
#define CRC_RANGE_END 0x000FFDF0u
#define CRC_PATCH_VALUE 0x10u

static uint32_t crc_adjustment(uint32_t prefix_crc) {
  return prefix_crc ^ 0xFFFFFFFFu;
}

static uint32_t flash_crc_byte(uint32_t address, uint8_t hypothetical, uint32_t adjustment) {
  if (hypothetical != 0u) {
    if (address == PATCH_ADDRESS) return CRC_PATCH_VALUE;
    if (address >= CRC_ADJUST && address < CRC_RANGE_END) {
      return (adjustment >> ((address - CRC_ADJUST) * 8u)) & 0xFFu;
    }
  }
  return MMIO8(address);
}

static uint32_t crc_prefix_sw(uint8_t patched, const struct runtime_guard *guard) {
  uint32_t address;
  uint32_t crc = 0xFFFFFFFFu;
  for (address = CRC_RANGE_START; address < CRC_ADJUST; ++address) {
    uint8_t value = MMIO8(address);
    if (patched != 0u && address == PATCH_ADDRESS) value = CRC_PATCH_VALUE;
    crc = crc32_update(crc, value);
    if ((address & 0x7FFu) == 0u) feed_watchdog(guard);
  }
  return crc ^ 0xFFFFFFFFu;
}

static uint32_t crc_full_sw(
  uint8_t hypothetical, uint32_t adjustment, const struct runtime_guard *guard
) {
  uint32_t address;
  uint32_t crc = 0xFFFFFFFFu;
  for (address = CRC_RANGE_START; address < CRC_RANGE_END; ++address) {
    crc = crc32_update(crc, (uint8_t)flash_crc_byte(address, hypothetical, adjustment));
    if ((address & 0x7FFu) == 0u) feed_watchdog(guard);
  }
  return crc ^ 0xFFFFFFFFu;
}

static uint32_t dcra_full_raw(
  uint8_t hypothetical, uint32_t adjustment, const struct runtime_guard *guard
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
    if (hypothetical != 0u && address == CRC_ADJUST) word = adjustment;
    DCRA_IN = word;
    if ((address & 0x7FFu) == 0u) feed_watchdog(guard);
  }
  syncp();
  return DCRA_COUT;
}

static uint32_t crc_region(
  const volatile uint8_t *data, uint32_t length, const struct runtime_guard *guard
) {
  uint32_t crc = 0xFFFFFFFFu;
  uint32_t offset;
  for (offset = 0u; offset < length; ++offset) {
    crc = crc32_update(crc, data[offset]);
    if ((offset & 0x7FFu) == 0u) feed_watchdog(guard);
  }
  return crc ^ 0xFFFFFFFFu;
}

static void capture_dcra(uint32_t *ctl, uint32_t *cout) {
  *ctl = DCRA_CTL;
  *cout = DCRA_COUT;
}

static void restore_dcra(uint32_t ctl, uint32_t cout) {
  DCRA_CTL = ctl;
  syncp();
  DCRA_COUT = cout;
  syncp();
}

#endif
