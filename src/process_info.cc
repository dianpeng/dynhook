#include "process_info.h"
#include "ptrace_util.h"

#include <errno.h>
#include <fstream>
#include <iostream>
#include <iomanip>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>

#include <glog/logging.h>

#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <libelf.h> // For handling ELF files

namespace dynhook {


namespace {
uintptr_t address_cast( const std::string& src ) {
  std::stringstream formatter;
  formatter<<std::hex<<src;
  uintptr_t ret;
  formatter >> ret;
  return ret;
}
} // namespace

bool process_info::parse_process_module_line( const std::string& line,
    module_info* output ) {
  std::vector<std::string> words;
  boost::split(words,line,
      boost::is_any_of(" "),boost::token_compress_on);
  if(!words.empty()) {
    // Check the permision is executable or not
    if(words.size() >1 && words[1].find("x") != std::string::npos) {
      // Parse the start-end
      const std::string& range = words[0];
      std::string::size_type pos = range.find_first_of("-");
      if(pos == std::string::npos) {
        goto fail;
      } else {
        output->start = address_cast(range.substr(0,pos));
        output->end = address_cast(range.substr(pos+1,range.size()-pos-1));
      }
      // Parse the module path information
      const std::string& path = words[words.size()-1];
      if(is_abs_path(path)) {
        output->path = path;
        return true;
      }
    }
  }
fail:
  LOG(INFO)<<"cannot process line:"<<line<<" in maps file!";
  return false;
}

bool process_info::load_process_so_list( pid_t pid ) {
  std::string path = (boost::format("/proc/%d/maps")%pid).str();
  std::fstream file(path.c_str(),std::ios::in);
  if(!file) {
    LOG(ERROR)<<"Cannot open file:"
      <<path<<" with error :"<<std::strerror(errno);
    return false;
  }

  // Now we start to parse the process/maps file
  std::string line;

  while( std::getline(file,line) ) {
    if(!line.empty()) {
      module_info minfo;
      if(parse_process_module_line(line,&minfo)) {
        m_modules.insert(minfo);
        // Assume very first line is the path of the executable
        if(m_entry_info.path.empty()) {
          m_entry_info = minfo;
        }
      }
    }
  }

  return true;
}

bool process_info::load_symbol_info() {
  BOOST_FOREACH(const module_info& minfo, m_modules) {
    if(!load_symbol_info(minfo)) {
      return false;
    }
  }
  return true;
}

bool process_info::load_symbol_info(
    const module_info& minfo ) {
  // Whether this module is the ELF loaded for execution
  const bool is_entry = minfo.path == path();

  const uintptr_t offset = is_entry ? 0 : minfo.start;

  base::scoped_fd fd( ::open(minfo.path.c_str(),O_RDONLY) );
  if(!fd) {
    LOG(ERROR)<<"Cannot load module:"<<minfo.path<<" with error:"
      << std::strerror(errno);
    return false;
  }

  Elf* elf = elf_begin(fd.fd(),ELF_C_READ,NULL);
  if(elf == NULL) {
    LOG(ERROR)<<"Cannot call function elf_begin with error: "
      <<elf_errmsg(elf_errno());
    return false;
  }

  // Find the elf symbol section
  //
  // Per ELF standard , an ELF binary can at most have 2 different
  // symbol table . One for symtab , one for dynamic symbol
  // So for a executable, we may find 2 symbol tables in its binary,
  // for a so , there should be one only.
  int cnt = 0;
  Elf_Scn* elf_section = NULL;
  Elf64_Shdr* elf_shdr;

  do {
    while((elf_section = elf_nextscn(elf,elf_section)) != NULL) {
      if((elf_shdr = elf64_getshdr(elf_section)) != NULL) {
        if(is_entry) {
          if(elf_shdr->sh_type == SHT_SYMTAB ||
             elf_shdr->sh_type == SHT_DYNSYM) {
            cnt++;
            break;
          }
        } else {
          if(elf_shdr->sh_type == SHT_DYNSYM) {
            cnt++;
            break;
          }
        }
      }
    }

    // do a search
    LOG(INFO)<<"For module:"<<minfo.path<<" we find one elf section with"<<
      " type "<<(elf_shdr->sh_type == SHT_SYMTAB ? "SYMTAB" : "DYNSYM")<<"!";

    {
      Elf_Data* elf_data = elf_getdata(elf_section,NULL);
      if(elf_data == NULL || elf_data->d_size == 0) {
        LOG(INFO)<<"elf_getdata returns empty data/symbol table "
          <<elf_errmsg(elf_errno());
        goto fail;
      }

      Elf64_Sym* elf_sym = static_cast<Elf64_Sym*>(elf_data->d_buf);
      Elf64_Sym* elf_end = reinterpret_cast<Elf64_Sym*>(
          static_cast<char*>(elf_data->d_buf) + elf_data->d_size);

      for( ; elf_sym != elf_end ; ++elf_sym ) {
        if(elf_sym->st_value == 0 ||
           (ELF64_ST_BIND(elf_sym->st_info) == STB_NUM) ||
           (ELF64_ST_TYPE(elf_sym->st_info) != STT_FUNC)) {
          // Skip none function type
          // The STB_NUM really just means that the binding type
          // has 3 different types. Here I do check simply because
          // I saw some other guy did it. I don't really know why
          // or is there any valid ELF will contain a st_info bits
          // set to STB_NUM.
          continue;
        }
        // We have a function symbol here
        symbol_info sinfo;
        sinfo.name = elf_strptr(elf,elf_shdr->sh_link,static_cast<size_t>(
              elf_sym->st_name));
        sinfo.size = elf_sym->st_size;
        sinfo.weak = ELF64_ST_BIND(elf_sym->st_info) == STB_WEAK;
        sinfo.base = elf_sym->st_value + offset;

        // Push the symbol_info into our list
        push_symbol_info(sinfo);
      }
    }
  } while(is_entry && cnt < 2);

  LOG(INFO)<<"Load "<<m_symbol_info.size()<<" symbols!";

  elf_end(elf);
  return true;
fail:
  elf_end(elf);
  return false;
}


bool process_info::init() {
  if(!load_process_so_list(m_pid))
    return false;
  if(!load_symbol_info())
    return false;
  return true;
}

const process_info::symbol_info*
process_info::find_symbol( const std::string& name ) const {
  // Query address by the symbol name
  typedef symbol_index::const_iterator itr;
  std::pair<itr,itr> ret = m_symbol_name_index.equal_range(name);
  if(ret.first == ret.second) {
    return NULL;
  }
  // Try to find a strong symbol
  for( itr beg = ret.first ; beg != ret.second ; ++beg ) {
    const symbol_info& sinfo = beg->second;
    if(!sinfo.weak) {
      return &sinfo;
    }
  }

  // Just return a weak symbol
  return &ret.first->second;
}

const process_info::symbol_info*
process_info::find_symbol( uintptr_t address ) const {
  std::vector<symbol_info>::const_iterator itr =
    std::lower_bound(m_symbol_info.begin(),m_symbol_info.end(),
        address,
        symbol_info_less_than());
  if(itr == m_symbol_info.end()) return NULL;
  const symbol_info& sinfo = *itr;
  assert(address >= sinfo.base && address <= sinfo.base + sinfo.size);
  return &sinfo;
}

namespace bfs = boost::filesystem;

bool process_info::snapshot_thread_list( std::vector<pid_t>* output ) {
  std::string path = (boost::format("/proc/%d/task")%m_pid).str();
  try {
    if(bfs::exists(path) && bfs::is_directory(path)) {
      bfs::directory_iterator itr(path);
      bfs::directory_iterator end;
      for( ; itr != end ; ++itr ) {
        if(bfs::is_directory(itr->status())) {
          try {
            output->push_back(
                boost::lexical_cast<pid_t>(itr->path().filename().string()));
          } catch ( const boost::bad_lexical_cast& e ) {
            LOG(WARNING)<<"Failed to convert thread in path:"
              <<path<<" to pid_t with reason:"<<e.what();
            continue;
          }
        }
      }
    }
  } catch( const bfs::filesystem_error& ex ) {
    LOG(WARNING)<<"File system error when load thread info for pid:"
      <<m_pid<<"with reason:"<<ex.what();
    return false;
  }
  return true;
}

bool process_info::diff_thread_list( const std::vector<pid_t>& input ,
    std::vector<pid_t>* output ) {
  BOOST_FOREACH(pid_t pid,input) {
    if(m_thread_list.find(pid) == m_thread_list.end()) {
      output->push_back(pid);
    }
  }
  return output->empty();
}

bool process_info::attach_all() {
  std::vector<pid_t> tlist;
  std::vector<pid_t> diff;

  do {
    if(!snapshot_thread_list(&tlist)) return false;
    if(diff_thread_list(tlist,&diff)) {
      sync_thread_status(tlist);
      break;
    }
    BOOST_FOREACH(pid_t pid,diff) {
      int status;
      if(!ptrace_attach_and_wait(pid,&status))
        return false;
      m_thread_list.insert(
          std::make_pair(pid,thread(pid,thread::STOPPED)));
    }
    tlist.clear();
    diff.clear();
  }while(true);
  return true;
}

bool process_info::stop_pid( pid_t pid ) {
  errno = 0;
  if(::kill(pid,SIGSTOP)) {
    if(errno == ESRCH) {
      return true;
    } else {
      LOG(ERROR)<<"kill("<<pid<<") failed with:"<<
        std::strerror(errno);
      return false;
    }
  }
  errno = 0;
  int status;
  pid_t p = ::waitpid(pid,&status,__WALL);
  if(errno) {
    LOG(ERROR)<<"waitpid("<<pid<<") failed with:"<<
      std::strerror(errno);
    return false;
  }
  assert(p == pid);
  (void)status; // Don't care about the signal code
  return true;
}

bool process_info::stop_all() {
  std::vector<pid_t> tlist;
  std::vector<pid_t> diff;

  // 1. Stop all attached threads
  for( thread_list::iterator itr = m_thread_list.begin() ;
      itr != m_thread_list.end() ; ++itr ) {
    if(itr->second.state == thread::RUNNING) {
      if(!stop_pid(itr->second.pid)) return false;
    }
  }
  // 2. Attach all the rest thread. In case ~
  return attach_all();
}

bool process_info::resume_all() {
  for( thread_list::iterator itr = m_thread_list.begin() ;
      itr != m_thread_list.end() ; ++itr ) {
    if(itr->second.state == thread::STOPPED) {
      if(!ptrace_continue(itr->second.pid))
        return false;
      itr->second.state = thread::RUNNING;
    }
  }
  return true;
}

bool process_info::resume_and_wait( pid_t pid , int* status ) {
  thread_list::iterator itr = m_thread_list.find(pid);
  if(itr == m_thread_list.end()) {
    LOG(ERROR)<<"Try to resume and wait on pid:"<<pid<<
      "However this pid is not attached or existed!";
    return false;
  }
  if(itr->second.state == thread::RUNNING) {
    LOG(ERROR)<<"Try to resume and wait on pid:"<<pid<<
      "However it is running!";
    return false;
  }
  if(!ptrace_cont_and_wait_event(pid,status))
    return false;
  return true;
}

bool process_info::stop_thread( pid_t pid ) {
  thread_list::iterator itr = m_thread_list.find(pid);
  if(itr == m_thread_list.end()) {
    LOG(ERROR)<<"Try to stop on pid:"<<pid<<
      "However this pid is not attached or existed!";
    return false;
  }
  if(itr->second.state == thread::STOPPED) {
    return true;
  } else {
    if(!stop_pid(pid)) return false;
  }
  return true;
}

// Syncing the thread status with the latest snapshots
void process_info::sync_thread_status( const std::vector<pid_t>& pids ) {
  for( thread_list::iterator itr = m_thread_list.begin() ;
      itr != m_thread_list.end() ; ) {
    std::vector<pid_t>::const_iterator ret = std::find(
        pids.begin(),pids.end(),itr->second.pid);
    if(ret == pids.end()) {
      m_thread_list.erase(itr++);
    } else {
      ++itr;
    }
  }
}

const process_info::thread*
process_info::get_thread( pid_t pid ) const {
  thread_list::const_iterator itr = m_thread_list.find(pid);
  return itr == m_thread_list.end() ? NULL : &(itr->second);
}

void process_info::dump( std::ostream& output ) const {
  output<<"Process path:"<<path()<<"\n";
  output<<"Pid:"<<m_pid<<"\n";
  output<<"Symbol Table\n";
  BOOST_FOREACH(const symbol_info& sinfo, m_symbol_info) {
    output<<"Name:"<<sinfo.name<<" "
      <<"Weak:"<<std::boolalpha<<sinfo.weak<<std::noboolalpha<<" "
      <<"Base:"<<std::hex<<sinfo.base<<" "
      <<"Offset:"<<sinfo.size<<std::dec<<"\n";
  }
}

process_info::process_info( pid_t pid ):
  m_modules(),
  m_pid(pid),
  m_entry_info(),
  m_symbol_info(),
  m_symbol_name_index(),
  m_thread_list()
{}

} // namespace dynhook
