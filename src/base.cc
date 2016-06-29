#include "base.h"
#include <libelf.h>
#include <glog/logging.h>
#include <udis86.h>

namespace dynhook {

bool init_the_world( int argc , char* argv[] ) {
  ::google::InitGoogleLogging(argv[0]);
  elf_version(EV_CURRENT);
  return true;
}

namespace base {
void dump_assembly( const char* cd , size_t sz ,
    std::ostream& output ) {
  ud_t ud_obj;
  ud_init(&ud_obj);
  ud_set_mode(&ud_obj,64);
  ud_set_input_buffer(&ud_obj,reinterpret_cast<const uint8_t*>(cd),sz);
  ud_set_syntax(&ud_obj,UD_SYN_INTEL);
  int cnt=0;
  while(ud_disassemble(&ud_obj)) {
    output<<cnt<<":"<<ud_insn_asm(&ud_obj)<<"\n";
    cnt += ud_insn_len(&ud_obj);
  }
  output.flush();
}
} // namespace base

} // namespace dynhook
