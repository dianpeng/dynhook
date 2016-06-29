#ifndef PTRACE_UTIL_H_
#define PTRACE_UTIL_H_
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include <cstring>
#include <cstddef>
#include <glog/logging.h>
#include <iomanip>

namespace dynhook {

// Ptrace helper functions
inline bool ptrace_peek( pid_t pid , uintptr_t address , uintptr_t* ret ) {
  errno = 0;
  *ret = ::ptrace(PTRACE_PEEKTEXT,pid,address,0);
  if(errno) {
    LOG(ERROR)<<"ptrace(PTRACE_PEEKTEXT,"<<pid<<","<<address<<") failed with:"
      <<std::strerror(errno);
    return false;
  }
  return true;
}

inline bool ptrace_poke( pid_t pid , uintptr_t address , uintptr_t value ) {
  errno = 0;
  ::ptrace(PTRACE_POKETEXT,pid,address,value);
  if(errno) {
    LOG(ERROR)<<"ptrace(PTRACE_POKETEXT,"<<pid<<","<<address<<","
      <<value<<") failed with:"<<std::strerror(errno);
    return false;
  }
  return true;
}

inline bool ptrace_getregs( pid_t pid , struct user_regs_struct* output ) {
  errno = 0;
  ::ptrace(PTRACE_GETREGS,pid,0,output);
  if(errno) {
    LOG(ERROR)<<"ptrace(PTRACE_GETREGS,"<<pid<<","
      <<std::hex<<output<<std::dec<<") failed with:"<<std::strerror(errno);
    return false;
  }
  return true;
}

inline bool ptrace_setregs( pid_t pid ,
    const struct user_regs_struct& output ) {
  errno = 0;
  ::ptrace(PTRACE_SETREGS,pid,0,&output);
  if(errno) {
    LOG(ERROR)<<"ptrace(PTRACE_SETREGS,"<<pid<<","
      <<") failed with:"<<std::strerror(errno);
    return false;
  }
  return true;
}

inline bool ptrace_continue( pid_t pid ) {
  errno = 0;
  ::ptrace(PTRACE_CONT,pid,0,0);
  if(errno) {
    LOG(ERROR)<<"ptrace(PTRACE_CONT,"<<pid<<") failed with:"
      <<std::strerror(errno);
    return false;
  }
  return true;
}

inline bool ptrace_signal( pid_t pid , int sig ) {
  errno = 0;
  ::ptrace(PTRACE_CONT,pid,0,sig);
  if(errno) {
    LOG(ERROR)<<"ptrace(PTRACE_CONT,"<<pid<<") failed with:"
      <<std::strerror(errno);
    return false;
  }
  return true;
}

inline bool ptrace_cont_and_wait_event( pid_t pid , int* status ) {
  if(!ptrace_continue(pid))
    return false;
  // Now blocked for events send by peers
  errno = 0;
  pid_t p = ::waitpid(pid,status,__WALL);
  if(errno) {
    LOG(ERROR)<<"waitpid("<<pid<<") failed with:"
      <<std::strerror(errno);
    return false;
  }
  assert(p == pid);
  return true;
}

inline bool ptrace_attach( pid_t pid ) {
  errno = 0;
  ::ptrace(PTRACE_ATTACH,pid,0,0);
  if(errno) {
    LOG(ERROR)<<"ptrace(PTRACE_ATTACH,"<<pid<<") failed with:"
      <<std::strerror(errno);
    return false;
  }
  return true;
}

inline bool ptrace_attach_and_wait( pid_t pid , int* status ) {
  if(!ptrace_attach(pid))
    return false;
  errno = 0;
  ::pid_t p = ::waitpid(pid,status,__WALL);
  if(errno) {
    LOG(ERROR)<<"waitpid("<<pid<<") failed with:"
      <<std::strerror(errno);
    return false;
  }
  assert(p == pid);
  return true;
}

} // namespace dynhook
#endif // PTRACE_UTIL_H_
