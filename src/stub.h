#ifndef STUB_H_
#define STUB_H_
#include <cstddef>
#include <string>
#include <memory>
#include <iostream>

#include <inttypes.h>

#include <boost/scoped_array.hpp>
#include <boost/noncopyable.hpp>


// All these following stub classes are used for code injection.
// The contains specific machine code that perform specific injection
// steps in the remote processes.
//
// Look for the specific notes for how the registers protocol works

namespace dynhook {
class process_info;

class stub {
 public:
  virtual void* code() const = 0;
  virtual size_t size() const = 0;
  virtual size_t rip_offset() const = 0;
  virtual ~stub() {}
};

// This class is used to perform the following function:
// 1) open a so object via dlopen.
// 2) load a symbol name from a so object
// The protocol is as follow, the r8 register contains where the
// code is mapped into the target memory. This is important since
// we need to use it as base address to locate the so object's stirng
// and also the hooked symbol's name string inside of the memory.
//
// The return value is stored in RAX , if rax is 1 , it means failed
// at opening the library, if rax is 0, it means failed at loading
// the symbol ; otherwise it is the pointer of that symbol
class load_symbol : public stub , private boost::noncopyable {
 public:
  static load_symbol* create( const process_info& proc ,
      const std::string& so,
      const std::string& name ) {
    std::auto_ptr<load_symbol> ret(  new load_symbol() );
    if(!ret->init(proc,so,name)) return NULL;
    return ret.release();
  }

  virtual void* code() const {
    return m_code.get();
  }

  virtual size_t size() const {
    return m_code_size;
  }

  virtual size_t rip_offset() const {
    return m_data_size;
  }

  const std::string& so_name() const {
    return m_so;
  }

  const std::string& hook_name() const {
    return m_hook;
  }

  // Dump the whole freaking code body
  void dump( std::ostream& );

 private:
  load_symbol():
    stub(),
    m_code(),
    m_code_size(0),
    m_data_size(0),
    m_so(),
    m_hook()
  {}

  bool init( const process_info& , const std::string& ,
      const std::string& );

 private:
  boost::scoped_array<char> m_code;
  size_t m_code_size;
  size_t m_data_size;
  std::string m_so;
  std::string m_hook;
};

// This class is used to create a machine code chunk to perform
// 1) allocate a memory in remote process.
//
// The return value of this function will be stored inside of the
// rax register.
//
// Status code is returned also via rax register. If rax is 1,
// then faied at loading so object ; if rax is 2, then failed at
// searching the symbol.
class mem_map : public stub , private boost::noncopyable {
 public:
  static mem_map* create( const process_info& info , size_t size ,
      uintptr_t addr , int flag ) {
    std::auto_ptr<mem_map> ptr( new mem_map() );
    if(!ptr->init(info,size,addr,flag)) return NULL;
    return ptr.release();
  }

  virtual void* code() const {
    return m_code.get();
  }

  virtual size_t size() const {
    return m_code_size;
  }

  virtual size_t rip_offset() const {
    return 0;
  }

  size_t alloc_size() const {
    return m_alloc_size;
  }

  uintptr_t addr() const {
    return m_addr;
  }

  int flag() const {
    return m_flag;
  }

  void dump( std::ostream& );

 private:
  bool init( const process_info&  , size_t size , uintptr_t addr , int flag );

 private:
  mem_map():
    stub(),
    m_code(),
    m_code_size(0),
    m_alloc_size(0),
    m_addr(0),
    m_flag(0)
  {}

  boost::scoped_array<char> m_code;
  size_t m_code_size;
  size_t m_alloc_size;
  uintptr_t m_addr;
  int m_flag;
};

// Used to reclaim memory via munmap remotely
class mem_unmap : public stub {
 public:
  static mem_unmap* create( const process_info& proc ,
      uintptr_t addr ,
      size_t cap ) {
    std::auto_ptr<mem_unmap> ret( new mem_unmap() );
    if(!ret->init(proc,addr,cap))
      return NULL;
    return ret.release();
  }

  virtual void* code() const {
    return m_code.get();
  }

  virtual size_t size() const {
    return m_code_size;
  }

  virtual size_t rip_offset() const {
    return 0;
  }

  uintptr_t mem_addr() const {
    return m_addr;
  }

  size_t mem_size() const {
    return m_size;
  }

  virtual void dump( std::ostream& );

 private:
  bool init( const process_info& , uintptr_t addr , size_t size );

 private:
  mem_unmap():
    stub(),
    m_code(),
    m_code_size(0),
    m_addr(0),
    m_size(0)
  {}

  boost::scoped_array<char> m_code;
  size_t m_code_size;
  uintptr_t m_addr;
  size_t m_size;
};

// This class is used to create machine code to perform
// 1) open a so object via dlopen
// 2) load a specific function set by user via dlsym
// 3) call that function to set the *OLD* hooked function's pointer
//
// The r8 is used to store the base address of mapped memory
// The r9 is used to store where the *OLD* hooked function's pointer
//
// Return value is stored inside of rax.
// If rax is 1, then failed at loading so object;
// if rax is 2, then failed at loading the sybmol;
// If rax is 0, then it means success
class set_patched_func : public stub , private boost::noncopyable {
 public:
  static set_patched_func* create( const process_info& info ,
      const std::string& so,
      const std::string& func ) {
    std::auto_ptr<set_patched_func> ptr( new set_patched_func() );
    if(!ptr->init(info,so,func)) return NULL;
    return ptr.release();
  }

  virtual void* code() const {
    return m_code.get();
  }

  virtual size_t size() const {
    return m_code_size;
  }

  virtual size_t rip_offset() const {
    return m_data_size;
  }

  const std::string& so_name() const {
    return m_so_name;
  }

  const std::string& func_name() const {
    return m_func_name;
  }

  void dump( std::ostream& );

 private:
  bool init( const process_info& , const std::string& , const std::string& );

 private:
  set_patched_func():
    stub(),
    m_code(),
    m_code_size(0),
    m_data_size(0),
    m_so_name(),
    m_func_name()
  {}

  boost::scoped_array<char> m_code;
  size_t m_code_size;
  size_t m_data_size;
  std::string m_so_name;
  std::string m_func_name;
};

// This shell is used to patch the hooked function and make it work/function.
// The patch is doing as follow:
// 1) We will use mem_map to grab a chunk of memory that can be really
// executed.
// 2) The header of the old(hooked) function will have a jump instruction to
// the function that we loaded inside of the shared objects.
// 3) The original instruction of the hold function is COPIED

// This function is used to *INVOKE* at function in
// the remote target process
// The argument r9 is used when you put stub as set_patched_func
// the r8 register is always set to where the code gets mapped
// automatically inside of the invoke call
bool invoke( process_info* , const stub& code ,
    uintptr_t r9 , uintptr_t *ret );

} // namespace dynhook
#endif // STUB_H_
