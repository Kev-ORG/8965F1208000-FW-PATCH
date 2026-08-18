#ifndef SIENNA_PAYLOAD_COMMON_H
#define SIENNA_PAYLOAD_COMMON_H

#include <stdint.h>

#include "patch_protocol.h"

#define TARGET_BASE       0x00088000u
#define TARGET_LENGTH     0x00008000u
#define TARGET_END        (TARGET_BASE + TARGET_LENGTH)
#define PATCH_ADDRESS     0x0008E6C7u
#define PATCH_OFFSET      (PATCH_ADDRESS - TARGET_BASE)
#define CRC_SECTOR_BASE   0x000F8000u
#define CRC_ADJUST        0x000FFDECu
#define ORIGINAL_INSTRUCTION_WORD 0xD1E0301Du
#define PATCHED_INSTRUCTION_WORD  0x01E0301Du
#define PAGE_SIZE         0x100u
#define SRAM_BUFFER       ((volatile uint8_t *)0xFEBF2000u)
#define MAGIC_WORD        0x5AA5A55Au
#define MAGIC0_ADDRESS    0x00017E00u
#define MAGIC1_ADDRESS    0x000FFE00u

#define MMIO8(address)  (*(volatile uint8_t *)(address))
#define MMIO16(address) (*(volatile uint16_t *)(address))
#define MMIO32(address) (*(volatile uint32_t *)(address))

#define CAN_TMSTS   ((volatile uint8_t *)0xFFD202D0u)
#define CAN_TMID    ((volatile uint32_t *)0xFFD24000u)
#define CAN_TMDF0   ((volatile uint32_t *)0xFFD2400Cu)
#define CAN_TMDF1   ((volatile uint32_t *)0xFFD24010u)
#define CAN_TMPTR   ((volatile uint32_t *)0xFFD24004u)
#define CAN_TMFDCTR ((volatile uint32_t *)0xFFD24008u)
#define CAN_TMC     ((volatile uint8_t *)0xFFD20250u)
#define CAN_SLOT    0x10u
#define CAN_ID      0x7A9u
#define CAN_WAIT_LIMIT 0x01000000u

typedef void (*watchdog_fn)(uint32_t);
typedef uint32_t (*critical_enter_fn)(uint32_t);
typedef void (*critical_exit_fn)(uint32_t);

struct runtime_guard {
  uint32_t saved_state;
  uint8_t stubs_valid;
};

static inline void syncp(void) {
  __asm__ volatile (".short 0x001f" ::: "memory");
}

static void runtime_begin(struct runtime_guard *guard) {
  volatile uint32_t *stub = (volatile uint32_t *)0xFEBF1188u;
  guard->saved_state = 0u;
  guard->stubs_valid = (*stub != 0u && *stub != 0xFFFFFFFFu) ? 1u : 0u;
  if (guard->stubs_valid != 0u) {
    guard->saved_state = ((critical_enter_fn)0xFEBF11ACu)(0xFFFFu);
    ((watchdog_fn)0xFEBF1188u)(0xFEBF102Cu);
  }
}

static void feed_watchdog(const struct runtime_guard *guard) {
  if (guard->stubs_valid != 0u) {
    ((watchdog_fn)0xFEBF1188u)(0u);
  }
}

static void runtime_end(const struct runtime_guard *guard) {
  if (guard->stubs_valid != 0u) {
    ((watchdog_fn)0xFEBF1188u)(0u);
    ((critical_exit_fn)0xFEBF11D2u)(guard->saved_state);
  }
}

static int can_send(uint32_t word0, uint32_t word1, const struct runtime_guard *guard) {
  uint32_t spins = CAN_WAIT_LIMIT;
  while ((CAN_TMSTS[CAN_SLOT] & 0x06u) != 0u) {
    if (spins == 0u) return 1;
    --spins;
    if ((spins & 0xFFFFu) == 0u) feed_watchdog(guard);
  }
  CAN_TMPTR[8u * CAN_SLOT] = 8u << 28;
  CAN_TMID[8u * CAN_SLOT] = CAN_ID;
  CAN_TMDF0[8u * CAN_SLOT] = word0;
  CAN_TMDF1[8u * CAN_SLOT] = word1;
  CAN_TMFDCTR[8u * CAN_SLOT] = 0u;
  CAN_TMC[CAN_SLOT] |= 1u;
  spins = CAN_WAIT_LIMIT;
  while ((CAN_TMSTS[CAN_SLOT] & 0x06u) == 0u) {
    if (spins == 0u) return 2;
    --spins;
    if ((spins & 0xFFFFu) == 0u) feed_watchdog(guard);
  }
  CAN_TMSTS[CAN_SLOT] &= 0xF9u;
  return 0;
}

#if !defined(PATCH_CRC_PAYLOAD)
#if !defined(RESTORE_SECTOR_PAYLOAD)
#if !defined(CANDIDATE_WRITER_PAYLOAD)
#if !defined(PATCH_V2_PAYLOAD)
static int send_begin(uint8_t operation, const struct runtime_guard *guard) {
  if (can_send(PROTO_BEGIN0 | (PROTO_VERSION << 8) | ((uint32_t)operation << 16), TARGET_BASE, guard) != 0) return 1;
  return can_send(PROTO_BEGIN1 | (PROTO_VERSION << 8) | ((uint32_t)operation << 16) | (1u << 24), TARGET_LENGTH, guard);
}
#endif
#endif
#endif
#endif

#if !defined(PATCH_V2_PAYLOAD) && !defined(CRC_PAYLOAD)
static int send_data(uint16_t index, uint32_t value, const struct runtime_guard *guard) {
  return can_send(PROTO_DATA | ((uint32_t)index << 8), value, guard);
}
#endif

#if !defined(PATCH_V2_PAYLOAD) && !defined(CRC_PAYLOAD)
static int send_magic(uint8_t slot, uint32_t value, const struct runtime_guard *guard) {
  return can_send(PROTO_MAGIC | ((uint32_t)slot << 8), value, guard);
}
#endif

#if defined(PROBE_PAYLOAD) || defined(PROBE_UNLOCK_PAYLOAD) || defined(PROBE_PE_CYCLE_PAYLOAD)
static int send_diagnostic(
  uint8_t slot,
  uint8_t width,
  uint32_t value,
  const struct runtime_guard *guard
) {
  return can_send(
    PROTO_DIAGNOSTIC | ((uint32_t)slot << 8) | ((uint32_t)width << 16),
    value,
    guard
  );
}
#endif

#if defined(PROBE_UNLOCK_PAYLOAD) || defined(PROBE_PE_CYCLE_PAYLOAD)
static int send_status_code(
  uint8_t stage, uint32_t code, const struct runtime_guard *guard
) {
  return can_send(PROTO_STATUS | ((uint32_t)stage << 8), code, guard);
}
#elif !defined(PATCH_V2_PAYLOAD) && !defined(CRC_PAYLOAD) \
  && !defined(RESTORE_SECTOR_PAYLOAD) && !defined(CANDIDATE_WRITER_PAYLOAD)
static int send_status(uint8_t stage, const struct runtime_guard *guard) {
  return can_send(PROTO_STATUS | ((uint32_t)stage << 8), 0u, guard);
}
#endif

#if !defined(PROBE_UNLOCK_PAYLOAD) && !defined(PROBE_PE_CYCLE_PAYLOAD) \
  && !defined(PATCH_V2_PAYLOAD) && !defined(RESTORE_SECTOR_PAYLOAD) \
  && !defined(PATCH_CRC_PAYLOAD)
static int send_error(uint8_t stage, uint32_t code, const struct runtime_guard *guard) {
  return can_send(PROTO_ERROR | ((uint32_t)stage << 8), code, guard);
}
#endif

static uint32_t crc32_update(uint32_t crc, uint8_t value) {
  uint32_t bit;
  crc ^= value;
  for (bit = 0u; bit < 8u; ++bit) {
    crc = (crc >> 1) ^ ((0u - (crc & 1u)) & 0xEDB88320u);
  }
  return crc;
}

#if !defined(PATCH_V2_PAYLOAD) && !defined(CRC_PAYLOAD) \
  && !defined(LIVE_READ_PAYLOAD)
static int stream_sector(
  const volatile uint8_t *sector,
  const struct runtime_guard *guard,
  uint32_t *crc_out
) {
  uint32_t crc = 0xFFFFFFFFu;
  uint32_t offset;
  for (offset = 0u; offset < TARGET_LENGTH; offset += 4u) {
    uint32_t value = (uint32_t)sector[offset]
      | ((uint32_t)sector[offset + 1u] << 8)
      | ((uint32_t)sector[offset + 2u] << 16)
      | ((uint32_t)sector[offset + 3u] << 24);
    crc = crc32_update(crc, sector[offset]);
    crc = crc32_update(crc, sector[offset + 1u]);
    crc = crc32_update(crc, sector[offset + 2u]);
    crc = crc32_update(crc, sector[offset + 3u]);
    if (send_data((uint16_t)(offset >> 2), value, guard) != 0) return 1;
    if ((offset & 0x7FFu) == 0u) {
      feed_watchdog(guard);
    }
  }
  *crc_out = crc ^ 0xFFFFFFFFu;
  return 0;
}
#endif

#if !defined(PROBE_PAYLOAD) && !defined(PROBE_UNLOCK_PAYLOAD) \
  && !defined(PROBE_PE_CYCLE_PAYLOAD) && !defined(PATCH_V2_PAYLOAD) \
  && !defined(CRC_PAYLOAD) && !defined(RAM_ECHO_PAYLOAD) \
  && !defined(RESTORE_SECTOR_PAYLOAD) && !defined(CANDIDATE_WRITER_PAYLOAD) \
  && !defined(LIVE_READ_PAYLOAD)
static int send_success_trailer(
  uint8_t operation,
  const volatile uint8_t *sector,
  const struct runtime_guard *guard,
  uint8_t stage_mask
) {
  uint32_t crc;
  uint8_t expected_mask = operation == PROTO_OP_PATCH ? 0x3Fu : 0x01u;
  if (stage_mask != expected_mask) return 1;
  if (send_begin(operation, guard) != 0) return 2;
  if (stream_sector(sector, guard, &crc) != 0) return 3;
  if (send_magic(0u, MMIO32(MAGIC0_ADDRESS), guard) != 0) return 4;
  if (send_magic(1u, MMIO32(MAGIC1_ADDRESS), guard) != 0) return 5;
  if (operation == PROTO_OP_PATCH) {
    uint8_t stage;
    for (stage = 1u; stage <= 6u; ++stage) {
      if (send_status(stage, guard) != 0) return 6;
    }
  } else {
    if (send_status(1u, guard) != 0) return 6;
  }
  if (can_send(PROTO_END, crc, guard) != 0) return 7;
  return 0;
}
#endif

#if !defined(PROBE_UNLOCK_PAYLOAD) && !defined(PROBE_PE_CYCLE_PAYLOAD) \
  && !defined(PATCH_V2_PAYLOAD) && !defined(CRC_PAYLOAD) \
  && !defined(RESTORE_SECTOR_PAYLOAD) && !defined(CANDIDATE_WRITER_PAYLOAD)
static void halt_with_error(
  uint8_t operation,
  uint8_t stage,
  uint32_t code,
  const struct runtime_guard *guard
) {
  (void)send_begin(operation, guard);
  (void)send_error(stage, code, guard);
  runtime_end(guard);
  for (;;) {
  }
}
#endif

#endif
