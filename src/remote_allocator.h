#ifndef REMOTE_ALLOCATOR_H_
#define REMOTE_ALLOCATOR_H_
#include "base.h"
#include <boost/scoped_ptr.hpp>

namespace dynhook {
class process_info;

class remote_allocator {
 public:

  remote_allocator( process_info* pinfo );
  ~remote_allocator();

  bool init();
  uintptr_t allocate( size_t addr_size , uintptr_t hint = 0 );
  size_t size() const;
  size_t capacity() const;
 private:
  class pool;
  boost::scoped_ptr<pool> m_low_pool;
  boost::scoped_ptr<pool> m_high_pool;
};

} // namespace dynhook

#endif // REMOTE_ALLOCATOR_H_
