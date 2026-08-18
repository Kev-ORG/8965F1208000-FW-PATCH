#define CANDIDATE_WRITER_PAYLOAD 1
#define WRITER_OPERATION PROTO_OP_WRITE_TARGET_CANDIDATE
#define WRITER_DIRECTION 1u
#define WRITER_SECTOR_BASE 0x00088000u
#define WRITER_CONTEXT_TAG 0x54524754u
#include "patch_common.h"
#include "candidate_writer.h"

void exploit(void)__attribute__((section(".text.entry"),used,noreturn));
void exploit(void){write_candidate_exploit();}
