#ifndef EPS_PATCH_PAYLOAD_DCRA_H
#define EPS_PATCH_PAYLOAD_DCRA_H

#define DCRA_IN MMIO32(0xFFD51000u)
#define DCRA_COUT MMIO32(0xFFD51004u)
#define DCRA_CTL MMIO32(0xFFD51020u)
#define CRC_RANGE_START 0x00018000u
#define CRC_RANGE_END 0x000FFDF0u
#define CRC_PATCH_VALUE 0x10u
#define CRC_PATCHED_ADJUST_WORD 0xD1F4CE24u

static uint32_t dcra_full_raw(
  uint8_t hypothetical,
  const struct runtime_guard *guard
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
    if (hypothetical != 0u && address == CRC_ADJUST) {
      word = CRC_PATCHED_ADJUST_WORD;
    }
    DCRA_IN = word;
    if ((address & 0x7FFu) == 0u) feed_watchdog(guard);
  }
  syncp();
  return DCRA_COUT;
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
