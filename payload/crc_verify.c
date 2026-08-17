#define CRC_PAYLOAD 1
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
  uint32_t live_adjust;
  uint32_t live_sw;
  uint32_t live_dcra;
  uint32_t verify_code;

  __asm__ volatile ("di");
  runtime_begin(&guard);
  if (MMIO32(PATCH_ADDRESS - 2u) != PATCHED_INSTRUCTION_WORD) {
    halt_crc_error(PROTO_OP_VERIFY_CRC, 1u, MMIO32(PATCH_ADDRESS - 2u), &guard);
  }

  capture_dcra(&entry_ctl, &entry_cout);
  if ((entry_ctl & 3u) != 0u) {
    halt_crc_error(PROTO_OP_VERIFY_CRC, 3u, entry_ctl, &guard);
  }
  live_adjust = MMIO32(CRC_ADJUST);
  prefix_crc = crc_prefix_sw(0u, &guard);
  new_adjust = crc_adjustment(prefix_crc);
  live_sw = crc_full_sw(0u, 0u, &guard);
  live_dcra = dcra_full_raw(0u, 0u, &guard);
  if (restore_dcra(entry_ctl, entry_cout) != 0u) {
    halt_crc_error(PROTO_OP_VERIFY_CRC, 4u, entry_ctl, &guard);
  }

  values[PROTO_CRC_ENTRY_CTL] = entry_ctl;
  values[PROTO_CRC_ENTRY_COUT] = entry_cout;
  values[PROTO_CRC_RANGE_START] = CRC_RANGE_START;
  values[PROTO_CRC_RANGE_END] = CRC_RANGE_END;
  values[PROTO_CRC_ADJUST_ADDRESS] = CRC_ADJUST;
  values[PROTO_CRC_OLD_ADJUST_WORD] = live_adjust;
  values[PROTO_CRC_PATCHED_PREFIX_SW] = prefix_crc;
  values[PROTO_CRC_NEW_ADJUST_WORD] = new_adjust;
  values[PROTO_CRC_ORIGINAL_SW_FULL] = live_sw;
  values[PROTO_CRC_PATCHED_SW_FULL] = live_sw;
  values[PROTO_CRC_ORIGINAL_DCRA_RAW] = live_dcra;
  values[PROTO_CRC_PATCHED_DCRA_RAW] = live_dcra;
  values[PROTO_CRC_EXIT_CTL] = DCRA_CTL;
  values[PROTO_CRC_EXIT_COUT] = DCRA_COUT;
  values[PROTO_CRC_SRAM_ECHO_LENGTH] = 0u;
  values[PROTO_CRC_SRAM_ECHO_CRC32] = 0u;

  verify_code = 0u;
  if (!(live_adjust == new_adjust)) verify_code |= 1u;
  if (!(live_sw == 0xFFFFFFFFu)) verify_code |= 2u;
  if (!(live_dcra == 0xFFFFFFFFu)) verify_code |= 4u;
  if (verify_code != 0u) {
    halt_crc_error(PROTO_OP_VERIFY_CRC, 2u, verify_code, &guard);
  }

  (void)send_crc_stream(PROTO_OP_VERIFY_CRC, values, &guard);
  runtime_end(&guard);
  for (;;) {
  }
}
