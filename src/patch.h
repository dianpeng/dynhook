#ifndef PATCH_H_
#define PATCH_H_
#include "process_info.h"

#include <boost/scoped_array.hpp>
#include <boost/noncopyable.hpp>
#include <cstddef>
#include <iostream>
#include <inttypes.h>
#include <set>

#include "../instr/insn.h"

namespace dynhook {
class remote_allocator;
class patch_manager;

// Patch. A patch class represents one patch towards the functions.
// A patch is created through patch manager who includes all the
// patch runtime. User is not allowed to patch a function more than
// ones. A patch will clean its patched function once the patch object
// goes out of the scope.

class patch {
 public:
  patch( const process_info& pinfo ,
      const process_info::symbol_info& target ,
      uintptr_t new_func_addr ,
      remote_allocator* alloc ):
    m_pinfo(pinfo),
    m_target(target),
    m_new_func(new_func_addr),
    m_func_code(),
    m_patched_entry(0),
    m_trampoline_code(),
    m_trampoline_code_size(0),
    m_detour_buffer(),
    m_detour_buffer_size(0),
    m_detour_buffer_addr(0),
    m_alloc(alloc),
    m_body_modified(false),
    m_checked(false)
  {}

  virtual ~patch() = 0;

  virtual void dump( std::ostream& );

  // Used to check whether the patch can be performed or not
  bool check();

  // Function that actually does the patch operation
  bool perform( uintptr_t* patched_entry );

  const process_info& proc() const {
    return m_pinfo;
  }

  const process_info::symbol_info& target() const {
    return m_target;
  }

  uintptr_t new_function() const {
    return m_new_func;
  }

 protected: // Interfaces
  virtual size_t max_hook_size() const =0;
  virtual bool get_hook_code() = 0;
  virtual size_t hook_code_size() const = 0;
  virtual const char* hook_code() const = 0;

 private: // Interfaces for patch_manager.

  // Check whether the target function can be used for a specific type
  // of hooking. It is typically used for checking whether the function
  // body size is too small which we cannot even install a hook code
  virtual bool precheck_hook() = 0;

 protected:
  bool get_trampoline_code( uintptr_t back );
  bool get_function_body();
  bool can_patch( size_t patch_size );
  int copy_detour( void* buffer , size_t hook_size , uintptr_t dest_addr );
  bool write_hook();
  bool write_ool( uintptr_t where , const void* , size_t len );
 private:
  int copy_instruction( const void* src , void* dest,
      uintptr_t src_addr,
      uintptr_t dest_addr );

  bool insn_is_indirect_jmp(const struct insn& insn) {
    return ((insn.opcode.bytes[0] == 0xff &&
             (X86_MODRM_REG(insn.modrm.value) & 6) == 4) ||
             insn.opcode.bytes[0] == 0xea);
  }

  bool insn_is_jmp_instruction(const struct insn& insn) {
    switch(insn.opcode.bytes[0]) {
      case 0xe0: /* loopne */
      case 0xe1: /* loope */
      case 0xe2: /* loop */
      case 0xe3: /* jcxz */
      case 0xe9: /* near relative jump */
      case 0xeb: /* short relative jump */
        return true;
      case 0x0f:
        if((insn.opcode.bytes[1] &0xf0) == 0x80)
          return true;
        return false;
      default:
        if((insn.opcode.bytes[0] &0xf0) == 0x70)
          return true;
        return false;
    }
  }

  bool insn_jump_into_range(const struct insn& insn,
      uintptr_t start, uintptr_t end ) {
    uintptr_t target = 0;
    if(!insn_is_jmp_instruction(insn)) return false;
    target = reinterpret_cast<uintptr_t>(insn.next_byte)
      + insn.immediate.value;
    return (start<=target && target<=end);
  }

  bool write_remote( uintptr_t , const char* , size_t len );

 protected:
  const process_info& m_pinfo; // Process information
  const process_info::symbol_info& m_target; // Which function to hooked
  uintptr_t m_new_func; // Which function is used to replace the target
  boost::scoped_array<char> m_func_code; // Function body's code
  uintptr_t m_patched_entry; // Where the function gets patched

  // Currently our trampoline code is always the same , an absolute jump
  // with push/ret pair which saves us from using registers
  static const size_t kTrampolineMaximumCodeSize = 14;
  boost::scoped_array<char> m_trampoline_code;
  size_t m_trampoline_code_size;

  // OOL buffer/Detour buffer
  boost::scoped_array<char> m_detour_buffer;
  size_t m_detour_buffer_size;
  uintptr_t m_detour_buffer_addr;

  remote_allocator* m_alloc;

  // For recovery
  bool m_body_modified;

  // For whether the target function is checked or not
  bool m_checked;

  friend class patch_manager;
};

class patch_manager : private boost::noncopyable {
 public:
  // Create a patch , user is responsible for reclaiming its memory.
  // The patch is performed until user calls the perform functions.
  // Once after the patch, the patched code will be recovery automatically
  // once the object is deleted. You will fail to get a patch object
  // if you try to patch the same function multiple times.
  patch* create_patch( remote_allocator* alloc ,
      const process_info& pinfo ,
      const std::string& hooked_function,
      uintptr_t new_func );

  size_t size() const {
    return m_patch_list.size();
  }

 private:
  std::set<std::string> m_patch_list;
  friend class patch;
};

} // namespace dynhook
#endif // PATCH_H_
