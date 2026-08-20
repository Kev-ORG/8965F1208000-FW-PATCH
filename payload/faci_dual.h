#ifndef SIENNA_FACI_DUAL_H
#define SIENNA_FACI_DUAL_H

/* Register names follow the RH850/P1M-E hardware manual, confirmed against
 * the manufacturer's own CUW flash-programming shellcode:
 *   FPMON@0xFFA10000, FASTAT@0xFFA10010, FAREASELC@0xFFA10020,
 *   FSADDR@0xFFA10030, FSTATR@0xFFA10080, FENTRYR@0xFFA10084,
 *   FPROTR@0xFFA10088, FPSADDR@0xFFA100E0, command area@0xFFA20000,
 *   FHVE15@0xFFF8A430, FHVE3@0xFFF82410.
 * (Legacy aliases in the payload: FLWL/FLWE, REG84/REG88/REG20, FASTAT/FAESTAT.) */
#define FACI_FPMON     MMIO8(0xFFA10000u)
#define FACI_FASTAT    MMIO8(0xFFA10010u)
#define FACI_FAREASELC MMIO16(0xFFA10020u)
#define FACI_FSADDR    MMIO32(0xFFA10030u)
#define FACI_FSTATR    MMIO32(0xFFA10080u)
#define FACI_FENTRYR   MMIO16(0xFFA10084u)
#define FACI_FPROTR    MMIO16(0xFFA10088u)
#define FACI_FPSADDR   MMIO16(0xFFA100E0u)
#define FACI_CMD8      MMIO8(0xFFA20000u)
#define FACI_DATA16    MMIO16(0xFFA20000u)
#define FHVE15         MMIO32(0xFFF8A430u)
#define FHVE3          MMIO32(0xFFF82410u)
#define FRDY_LIMIT 1000000u
#define DBFULL_LIMIT 1000000u
#define FENTRYR_POLL_LIMIT 100000u
/* FSTATR error bits, matching the manufacturer's CUW shellcode mask 0x7040:
 * FLWEERR|DBFULL|PRGERR|ERSERR|ILGLERR.  (The prior 0x7800 wrongly included
 * SUSRDY and dropped FLWEERR/DBFULL.) */
#define FSTATR_ERROR_MASK 0x00007040u
#define PAGE_COUNT 128u
#define PAGE_HALFWORDS 128u
#define FACI_BEFORE_INTENT __attribute__((section(".text.before_intent"),noinline))

struct faci_snapshot { uint32_t fpmon,fstatr,fastat,fentryr,fprotr,fareaselc,fhve15,fhve3; };

#if !defined(CANDIDATE_WRITER_PAYLOAD)
static FACI_BEFORE_INTENT void take_faci_snapshot(struct faci_snapshot *v) {
  v->fpmon=FACI_FPMON;v->fstatr=FACI_FSTATR;v->fastat=FACI_FASTAT;v->fentryr=FACI_FENTRYR;
  v->fprotr=FACI_FPROTR;v->fareaselc=FACI_FAREASELC;v->fhve15=FHVE15;v->fhve3=FHVE3;
}
static FACI_BEFORE_INTENT int exact_idle(const struct faci_snapshot *v) {
  return v->fpmon==0x80u&&v->fstatr==0x8000u
    &&(v->fastat|v->fentryr|v->fprotr|v->fareaselc|v->fhve15|v->fhve3)==0u;
}
#endif
static FACI_BEFORE_INTENT int wait_frdy(const struct runtime_guard *guard) {
  uint32_t n=FRDY_LIMIT;
  while ((FACI_FSTATR&0x8000u)==0u) { if(n==0u)return 1;--n;if((n&0xFFFFu)==0u)feed_watchdog(guard); }
  return 0;
}
static FACI_BEFORE_INTENT int status_error(void) {
  if((FACI_FSTATR&FSTATR_ERROR_MASK)!=0u)return 2;
  if((FACI_FASTAT&0x10u)!=0u)return 3;
  return 0;
}
static FACI_BEFORE_INTENT int wait_ready(const struct runtime_guard *guard) { int e=wait_frdy(guard);return e!=0?e:status_error(); }
static __attribute__((noinline)) int wait_fentryr(uint16_t mask,uint16_t expected,const struct runtime_guard *guard) {
  uint32_t n=FENTRYR_POLL_LIMIT;
  while(n!=0u){uint16_t v=FACI_FENTRYR;syncp();if((v&mask)==expected)return 0;--n;if((n&0xFFFu)==0u)feed_watchdog(guard);}
  return 1;
}
static FACI_BEFORE_INTENT int unlock_fentryr(const struct runtime_guard *guard) {
  uint32_t attempts=3u;
  while(attempts!=0u){--attempts;if(wait_ready(guard)==0){FACI_FENTRYR = 0xAA01u;if(wait_fentryr(0xFFFFu,1u,guard)==0)return 0;}feed_watchdog(guard);}
  return 1;
}
static FACI_BEFORE_INTENT int enter_pe(const struct runtime_guard *guard) {
  if(unlock_fentryr(guard)!=0)return 2;
  FHVE15 = 1u;FHVE3 = 1u;syncp();if(wait_ready(guard)!=0)return 3;
  FACI_FAREASELC = 0x3B00u;FACI_FPROTR = 0x5501u;syncp();return 0;
}
static FACI_BEFORE_INTENT int exit_pe(const struct runtime_guard *guard) {
  int e=0;FHVE15 = 0u;FHVE3 = 0u;(void)FHVE3;syncp();FACI_FPROTR = 0x5500u;
  if (wait_frdy(guard) != 0) { e=1; }
  FACI_FENTRYR = 0xAA00u;syncp();
  if(wait_fentryr(0x0081u,0u,guard)!=0)e=2;
  if(FHVE15!=0u||FHVE3!=0u||(FACI_FPROTR&1u)!=0u)e=2;
  return e;
}
static FACI_BEFORE_INTENT int failure_cleanup(const struct runtime_guard *guard) {
  int e=0;
  if((FACI_FSTATR&0x8000u)==0u){FACI_CMD8=0xB3u;if(wait_frdy(guard)!=0)e=1;}
  if((FACI_FSTATR&0x8000u)!=0u&&status_error()!=0){FACI_CMD8=0x50u;if(wait_frdy(guard)!=0||status_error()!=0)e=2;}
  if (exit_pe(guard) != 0) { e=3; }
  return e;
}
static FACI_BEFORE_INTENT int erase_sector(uint32_t sector_base,const struct runtime_guard *guard) {
  FACI_FPSADDR = 1u;FACI_FSADDR = sector_base;syncp();FACI_CMD8 = 0x20u;FACI_CMD8 = 0xD0u;return wait_ready(guard);
}
static FACI_BEFORE_INTENT int program_sector(uint32_t sector_base,const volatile uint8_t *source,uint32_t *failed_page,const struct runtime_guard *guard) {
  uint32_t page;
  for(page=0u;page<PAGE_COUNT;++page){
    uint32_t halfword,address=sector_base+page*PAGE_SIZE;const volatile uint8_t *src=source+page*PAGE_SIZE;
    FACI_FSADDR = address;syncp();FACI_CMD8 = 0xE8u;FACI_CMD8 = 0x80u;
    for(halfword=0u;halfword<PAGE_HALFWORDS;++halfword){
      uint32_t n=DBFULL_LIMIT;
      /* Wait on FSTATR bit 11 (SUSRDY) exactly as the manufacturer's CUW
       * programming shellcode does; the prior bit 21 is a reserved always-0
       * bit, so the old poll never actually paced the data writes. */
      while((FACI_FSTATR&0x00000800u)!=0u){if(n==0u){*failed_page=page;return 1;}--n;if((n&0xFFFFu)==0u)feed_watchdog(guard);}
      FACI_DATA16=(uint16_t)src[halfword*2u]|((uint16_t)src[halfword*2u+1u]<<8);
    }
    FACI_CMD8 = 0xD0u;if(wait_ready(guard)!=0){*failed_page=page;return 2;}
    if((page&7u)==0u)feed_watchdog(guard);
  }
  return 0;
}

#endif
