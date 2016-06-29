#include "dynhook.h"
#include "base.h"
#include "patch.h"
#include "process_info.h"
#include "stub.h"
#include "remote_allocator.h"
#include "ptrace_util.h"

#include <cstdio>
#include <vector>
#include <string>
#include <iostream>
#include <boost/scoped_ptr.hpp>
#include <boost/program_options.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <unistd.h>

namespace dynhook {
namespace {

namespace po = boost::program_options;

// Parse the program options
bool parse_command( int argc , char* argv[] , po::variables_map* vm ) {
  po::options_description desc("DynHook ----------------");
  desc.add_options()
    ("help","Show help message!")
    ("pid",po::value<pid_t>(),"Specify the pid of running process!")

    ("hook",
     po::value< std::vector<std::string> >()->composing(),
     "Specify the hook!")
    ("debug","Show verbose debug output!")
    ;

  po::store(po::parse_command_line(argc,argv,desc),*vm);
  po::notify(*vm);

  if(vm->count("help")) {
    std::cerr<<"Usage: sudo dynhook [options] \n";
    std::cerr<<desc;
    return false;
  }

  if(vm->count("pid") != 1 && vm->count("hook") == 0) {
    std::cerr<<"Usage: sudo dynhook [options] \n";
    std::cerr<<desc;
    return false;
  }

  return true;
}

struct hook {
  std::string path; // Path
  std::string target; // Target function
  std::string hook; // Hooked function
  std::string entry;// Entry function
};

// Hook string: path@target_function:hooked_function:entry_function
bool parse_hook( const std::string& str , hook* h ) {
  std::string::size_type start,end;
  start = 0;
  end = 0;

  if((end = str.find("@",start)) != std::string::npos ) {
    h->path = str.substr(start,end-start);
  } else {
    std::cerr<<"The hook argument is wrong, haven't found \"@\" for "
      "path of the so object!";
    return false;
  }

  start = end + 1;
  if ((end = str.find(":",start)) != std::string::npos ) {
    h->target = str.substr(start,end-start);
  } else {
    std::cerr<<"The hook argument is wrong, haven't found \":\" for "
      "target function!";
    return false;
  }

  start = end + 1;
  if((end = str.find(":",start)) != std::string::npos) {
    h->hook = str.substr(start,end-start);
  } else {
    std::cerr<<"The hook argument is wrong, haven't found \":\" for "
      "hook function!";
    return false;
  }

  start = end + 1;
  h->entry = str.substr(start,str.size()-start);

  LOG(INFO)<<"Hook option:"<<h->path<<"@"
    <<h->target<<":"<<h->hook<<":"<<h->entry;
  return true;
}

bool main( int argc , char* argv[] ) {
  po::variables_map config;
  std::vector<hook> hook_name_list;
  pid_t pid;
  patch_manager mgr;
  bool debug = false;
  if(!parse_command(argc,argv,&config))
    return false;

  if(config.count("debug"))
    debug = true;

  // Get the pid
  try {
    pid = config["pid"].as<pid_t>();
  } catch( po::error& e ) {
    std::cerr<<"Pid value invalid : "<<e.what()<<"!";
    return false;
  }

  // Get the hook list
  std::vector<std::string> hooks;
  try {
    hooks = config["hook"].as<std::vector<std::string> >();
  } catch( po::error& e ) {
    std::cerr<<"hook value invalid!";
    return false;
  }

  BOOST_FOREACH(std::string& str, hooks) {
    hook hk;
    if(!parse_hook(str,&hk))
      return false;
    hook_name_list.push_back(hk);
  }

  // Now start to do our patching job here
  {
    boost::scoped_ptr<process_info> pinfo(
        process_info::create(pid));
    if(!pinfo) {
      std::cerr<<"Cannot create process_info objects, see log for detail!";
      return false;
    }

    if(debug) pinfo->dump(std::cout);

    // Now attach all the process
    if(!pinfo->attach_all()) {
      std::cerr<<"Failed to attach all threads, see log for detail!";
      return false;
    }

    // Now create remote allocator
    remote_allocator alloc(pinfo.get());
    if(!alloc.init()) {
      std::cerr<<"Cannot initialize remote allocator, see log for detail!";
      return false;
    }

    // Now create all the patches
    boost::ptr_vector<patch> patch_list;

    BOOST_FOREACH(const hook& hk , hook_name_list) {
      boost::scoped_ptr<stub> ls_stub(load_symbol::create(
          *pinfo,hk.path,hk.hook));
      if(!ls_stub){
        std::cerr<<"Cannot create stub code , see log for detail!";
        return false;
      }
      uintptr_t new_function;
      if(!invoke(pinfo.get(),*ls_stub,0,&new_function)) {
        std::cerr<<"Cannot load new function in remote process, see log for "
          "detail!";
        return false;
      }
      if(new_function == 0) {
        std::cerr<<"Cannot load function:"<<hk.hook<<", see log for detail!";
        return false;
      }

      patch* p = mgr.create_patch(
            &alloc,
            *pinfo,
            hk.target,
            new_function);
      if(!p) {
        std::cerr<<"Cannot create patch, see log for detail!";
        return false;
      }
      // Do the check
      if(!p->check()) {
        std::cerr<<"Cannot do the patch since check doesn't pass, see log for "
          "detail!";
        return false;
      }

      patch_list.push_back(p);
    }

    // Now perform all the patches
    size_t idx = 0 ;
    BOOST_FOREACH(patch& p , patch_list) {
      uintptr_t ret;
      if(!p.perform(&ret)) {
        std::cerr<<"Failed to perform patches , see log for detail!";
        return false;
      }

      boost::scoped_ptr<stub> setter(set_patched_func::create(
          *pinfo,
          hook_name_list[idx].path,
          hook_name_list[idx].entry));
      if(!setter) {
        std::cerr<<"Cannot create set_patched_func stub code, see log for "
          "detail!";
        return false;
      }

      uintptr_t ret_value;
      if(!invoke(pinfo.get(),*setter,ret,&ret_value)) {
        std::cerr<<"Cannot invoke set_patched_func code, see log for "
          "detail!";
        return false;
      }
      if(ret_value) {
        std::cerr<<"Invoke function:"<<hook_name_list[idx].entry<<" in "
          <<hook_name_list[idx].path<<" failed, see log for detail!";
        return false;
      }
      ++idx;
    }

    if(debug) {
      BOOST_FOREACH(patch& p, patch_list) {
        p.dump(std::cout);
      }
    }

    // resumse all the process and waiting for user to exit us
    pinfo->resume_all();

    // now waiting here for user to notify us for exiting
    std::cout<<"Press any key to exit the process!";
    std::getchar();

    // stop all process for recovery
    pinfo->stop_all();

    return true;
  }
}

} // namespace

bool run_main( int argc, char* argv[] ) {
  init_the_world(argc,argv);
  return main(argc,argv);
}

} // namespace dynhook
