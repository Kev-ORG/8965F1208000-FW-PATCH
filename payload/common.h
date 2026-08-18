#ifndef EPS_PATCH_PAYLOAD_COMMON_H
#define EPS_PATCH_PAYLOAD_COMMON_H

#include <stdint.h>
#include "protocol.h"

#define TARGET_BASE 0x00088000u
#define TARGET_LENGTH 0x00008000u
#define PATCH_ADDRESS 0x0008E6C7u
#define CRC_SECTOR_BASE 0x000F8000u
#define CRC_ADJUST 0x000FFDECu
#define SRAM_BUFFER ((volatile uint8_t *)0xFEBF2000u)
#define MAGIC_WORD 0x5AA5A55Au
#define MAGIC0_ADDRESS 0x00017E00u
#define MAGIC1_ADDRESS 0x000FFE00u

#define MMIO8(address) (*(volatile uint8_t *)(address))
#define MMIO16(address) (*(volatile uint16_t *)(address))
#define MMIO32(address) (*(volatile uint32_t *)(address))

#define CAN_TMSTS ((volatile uint8_t *)0xFFD202D0u)
#define CAN_TMID ((volatile uint32_t *)0xFFD24000u)
#define CAN_TMDF0 ((volatile uint32_t *)0xFFD2400Cu)
#define CAN_TMDF1 ((volatile uint32_t *)0xFFD24010u)
#define CAN_TMPTR ((volatile uint32_t *)0xFFD24004u)
#define CAN_TMFDCTR ((volatile uint32_t *)0xFFD24008u)
#define CAN_TMC ((volatile uint8_t *)0xFFD20250u)
#define CAN_SLOT 0x10u
#define CAN_ID 0x7A9u
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
  if (guard->stubs_valid != 0u) ((watchdog_fn)0xFEBF1188u)(0u);
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

static uint32_t crc32_update(uint32_t crc, uint8_t value) {
  uint32_t bit;
  crc ^= value;
  for (bit = 0u; bit < 8u; ++bit) {
    crc = (crc >> 1) ^ ((0u - (crc & 1u)) & 0xEDB88320u);
  }
  return crc;
}

static int send_diagnostic(
  uint8_t slot, uint8_t width, uint32_t value, const struct runtime_guard *guard
) {
  return can_send(
    PROTO_DIAGNOSTIC | ((uint32_t)slot << 8) | ((uint32_t)width << 16),
    value, guard
  );
}

static int send_status_code(
  uint8_t stage, uint32_t code, const struct runtime_guard *guard
) {
  return can_send(PROTO_STATUS | ((uint32_t)stage << 8), code, guard);
}

static int stream_probe_region(
  uint8_t operation, uint8_t slot, uint32_t base,
  const struct runtime_guard *guard, uint32_t *combined_crc
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
  return can_send(PROTO_REGION_END | header, region_crc ^ 0xFFFFFFFFu, guard);
}

#endif
