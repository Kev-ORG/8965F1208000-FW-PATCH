#define RESTORE_SECTOR_PAYLOAD 1
#include "patch_common.h"
#include "faci_dual.h"

#define TARGET_SECTOR_BASE 0x00088000u
#define CRC_SECTOR_BASE 0x000F8000u
#define TARGET_INSTRUCTION_OFFSET 0x66C4u
#define SOURCE_ADJUST_OFFSET 0x7DECu
#define CRC_MAGIC_OFFSET 0x7E00u
#define ORIGINAL_ADJUST_WORD 0x0962887Fu
#define CANDIDATE_ADJUST_WORD 0x41C90FF2u
#define INTENT_MAGIC 0x52535452u
#define INTENT_SCHEMA 2u
#define INTENT_LENGTH 0x80u
#define INTENT_CRC_OFFSET 124u

struct restore_intent {
  uint32_t magic;
  uint16_t schema;
  uint16_t length;
  uint32_t sector_base;
  uint32_t source_crc32;
  uint32_t candidate_crc32;
  uint32_t source_context;
  uint32_t candidate_context;
  uint32_t magic0;
  uint32_t magic1;
  uint8_t reserved[88];
  uint32_t crc32;
} __attribute__((packed));
const volatile struct restore_intent restore_intent_block
  __attribute__((section(".intent"),used))={0};
typedef char intent_size_check[sizeof(struct restore_intent)==INTENT_LENGTH?1:-1];

static uint32_t intent_word(uint32_t offset){
  return MMIO32((uint32_t)&restore_intent_block+offset);
}
static uint32_t restore_crc32(
  const volatile uint8_t *data,const struct runtime_guard *guard
){
  uint32_t crc=0xFFFFFFFFu,index;
  for(index=0u;index<TARGET_LENGTH;++index){
    crc=crc32_update(crc,data[index]);
    if((index&0x7FFu)==0u)feed_watchdog(guard);
  }
  return crc^0xFFFFFFFFu;
}
static uint32_t intent_crc(void){
  const volatile uint8_t *p=(const volatile uint8_t *)&restore_intent_block;
  uint32_t crc=0xFFFFFFFFu,index;
  for(index=0u;index<INTENT_CRC_OFFSET;++index)crc=crc32_update(crc,p[index]);
  for(index=0u;index<4u;++index)crc=crc32_update(crc,0u);
  return crc^0xFFFFFFFFu;
}
static void copy_sector_to_sram(uint32_t base,const struct runtime_guard *guard){
  uint32_t index;
  for(index=0u;index<TARGET_LENGTH;++index){
    SRAM_BUFFER[index]=MMIO8(base+index);
    if((index&0x7FFu)==0u)feed_watchdog(guard);
  }
}
static int validate_restore_intent(const struct runtime_guard *guard){
  uint32_t index,base=intent_word(8u);
  if(intent_word(0u)!=INTENT_MAGIC||intent_word(4u)!=0x00800002u
    ||(base!=TARGET_SECTOR_BASE&&base!=CRC_SECTOR_BASE)
    ||intent_crc()!=intent_word(INTENT_CRC_OFFSET))return 1;
  for(index=0u;index<22u;++index)
    if(((const volatile uint8_t *)&restore_intent_block)[36u+index*4u]
      ||((const volatile uint8_t *)&restore_intent_block)[37u+index*4u]
      ||((const volatile uint8_t *)&restore_intent_block)[38u+index*4u]
      ||((const volatile uint8_t *)&restore_intent_block)[39u+index*4u])return 2;
  if(intent_word(28u)!=MAGIC_WORD||intent_word(32u)!=MAGIC_WORD
    ||MMIO32(MAGIC0_ADDRESS)!=MAGIC_WORD||MMIO32(MAGIC1_ADDRESS)!=MAGIC_WORD)return 3;
  if(base==TARGET_SECTOR_BASE){
    if(intent_word(20u)!=PATCHED_INSTRUCTION_WORD
      ||intent_word(24u)!=ORIGINAL_INSTRUCTION_WORD
      ||MMIO32(TARGET_SECTOR_BASE+TARGET_INSTRUCTION_OFFSET)!=PATCHED_INSTRUCTION_WORD
      ||MMIO32(CRC_ADJUST)!=ORIGINAL_ADJUST_WORD)return 4;
  }else{
    if(intent_word(20u)!=CANDIDATE_ADJUST_WORD
      ||intent_word(24u)!=ORIGINAL_ADJUST_WORD
      ||MMIO32(TARGET_SECTOR_BASE+TARGET_INSTRUCTION_OFFSET)!=PATCHED_INSTRUCTION_WORD
      ||MMIO32(CRC_SECTOR_BASE+SOURCE_ADJUST_OFFSET)!=CANDIDATE_ADJUST_WORD
      ||MMIO32(CRC_SECTOR_BASE+CRC_MAGIC_OFFSET)!=MAGIC_WORD)return 5;
  }
  if(restore_crc32((const volatile uint8_t *)base,guard)!=intent_word(12u))return 6;
  copy_sector_to_sram(base,guard);
  if(base==TARGET_SECTOR_BASE)
    MMIO32((uint32_t)SRAM_BUFFER+TARGET_INSTRUCTION_OFFSET)=intent_word(24u);
  else
    MMIO32((uint32_t)SRAM_BUFFER+SOURCE_ADJUST_OFFSET)=intent_word(24u);
  if(restore_crc32(SRAM_BUFFER,guard)!=intent_word(16u))return 7;
  if(base==TARGET_SECTOR_BASE
    &&MMIO32((uint32_t)SRAM_BUFFER+TARGET_INSTRUCTION_OFFSET)!=ORIGINAL_INSTRUCTION_WORD)return 8;
  if(base==CRC_SECTOR_BASE
    &&(MMIO32((uint32_t)SRAM_BUFFER+SOURCE_ADJUST_OFFSET)!=ORIGINAL_ADJUST_WORD
      ||MMIO32((uint32_t)SRAM_BUFFER+CRC_MAGIC_OFFSET)!=MAGIC_WORD))return 9;
  return 0;
}
static void send_restore_result(const volatile uint8_t *sector,const uint32_t codes[6],const struct runtime_guard *guard){
  uint32_t crc,stage,base=intent_word(8u);
  (void)can_send(PROTO_BEGIN0|(PROTO_VERSION<<8)|((uint32_t)PROTO_OP_RESTORE_SECTOR<<16),base,guard);
  (void)can_send(PROTO_BEGIN1|(PROTO_VERSION<<8)|((uint32_t)PROTO_OP_RESTORE_SECTOR<<16)|(1u<<24),TARGET_LENGTH,guard);
  if(stream_sector(sector,guard,&crc)!=0)return;
  (void)send_magic(0u,MMIO32(MAGIC0_ADDRESS),guard);(void)send_magic(1u,MMIO32(MAGIC1_ADDRESS),guard);
  for(stage=0u;stage<6u;++stage)(void)can_send(PROTO_STATUS|((stage+1u)<<8),codes[stage],guard);
  (void)can_send(PROTO_END,crc,guard);
}
static void restore_exploit(void)__attribute__((noinline,noreturn));
static void restore_exploit(void){
  struct runtime_guard guard;struct faci_snapshot entry,exit;
  uint32_t codes[6];uint32_t failed_page=0u,stage;int error;
  uint32_t sector_base=intent_word(8u);
  for(stage=0u;stage<6u;++stage)codes[stage]=0u;
  __asm__ volatile("di");runtime_begin(&guard);
  error=validate_restore_intent(&guard);if(error!=0){(void)can_send(PROTO_ERROR|(1u<<8),(uint32_t)error,&guard);goto halt;}
  take_faci_snapshot(&entry);if(!exact_idle(&entry)){codes[0]=8u;goto readback;}
  error=enter_pe(&guard);if(error!=0){codes[1]=(uint32_t)error;codes[4]=(uint32_t)failure_cleanup(&guard);goto readback;}
  error=erase_sector(sector_base,&guard);if(error!=0){codes[2]=(uint32_t)error;codes[4]=(uint32_t)failure_cleanup(&guard);goto readback;}
  error=program_sector(sector_base,SRAM_BUFFER,&failed_page,&guard);
  if(error!=0){codes[3]=(failed_page<<16)|(uint32_t)error;codes[4]=(uint32_t)failure_cleanup(&guard);goto readback;}
  error=exit_pe(&guard);take_faci_snapshot(&exit);if(error!=0||!exact_idle(&exit))codes[4]=(uint32_t)(error!=0?error:4);
readback:send_restore_result((const volatile uint8_t *)sector_base,codes,&guard);
halt:runtime_end(&guard);for(;;){}
}
void exploit(void)__attribute__((section(".text.entry"),used,noreturn));
void exploit(void){restore_exploit();}
