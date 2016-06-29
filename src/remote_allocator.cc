#include "remote_allocator.h"
#include "stub.h"
#include "process_info.h"

#include <glog/logging.h>
#include <boost/foreach.hpp>
#include <boost/scoped_ptr.hpp>
#include <vector>
#include <sys/mman.h>

namespace dynhook {

static const size_t kPageSize = 4096;

class remote_allocator::pool {
 public:
  static const size_t kDefaultCapacity = kPageSize;
  static const uintptr_t kLowHint = 0x400000;
  static const uintptr_t kHighHint= 0x7f0000000000U;

  enum { HIGH, LOW };

  pool( process_info* pinfo , int type ):
    m_pinfo(pinfo),
    m_size(0),
    m_capacity(0),
    m_start(0),
    m_addr(0),
    m_flag(0)
  {
    if(type == HIGH) {
      m_flag = MAP_ANONYMOUS | MAP_PRIVATE ;
      m_addr = kHighHint;
    } else {
      m_flag = MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT;
      m_addr = kLowHint;
    }
  }

  bool init() {
    if(!grow(0)) {
      LOG(WARNING)<<"Cannot initialize memory pool with hint:"
        <<std::hex<<m_addr<<std::dec;
      return false;
    }
    return true;
  }

  uintptr_t allocate( size_t cap ) {
    cap = base::alignment(cap,8);
    if(m_size + cap > m_capacity) {
      if(!grow( cap )) return 0;
    }
    assert(m_size + cap < m_capacity);
    uintptr_t ret = m_start + m_size;
    m_size += cap;
    return ret;
  }

  size_t size() const {
    return m_size;
  }

  size_t capacity() const {
    return m_capacity;
  }

 private:
  bool grow( size_t gaurantee ) {
    const size_t cap = (m_capacity == 0 ? kDefaultCapacity :
      (m_capacity*2 + gaurantee));

    boost::scoped_ptr<stub> mmap(mem_map::create(*m_pinfo,
          cap,
          m_addr,
          m_flag));
    if(!mmap) return false;
    uintptr_t ret;
    if(!invoke(m_pinfo,*mmap,0,&ret))
      return false;

    if(!ret && m_flag & MAP_32BIT) {
      m_flag &= ~MAP_32BIT;
      mmap.reset(mem_map::create(*m_pinfo,
            cap,
            m_addr,
            m_flag));
      if(!invoke(m_pinfo,*mmap,0,&ret))
        return false;
    }

    if(ret) {
      m_size = 0;
      m_capacity = cap;
      m_start = ret;
      return true;
    } else {
      LOG(WARNING)<<"Cannot allocate memory from remote process!";
      return false;
    }
  }

 private:
  process_info* m_pinfo;
  size_t m_size;
  size_t m_capacity;
  uintptr_t m_start;
  uintptr_t m_addr;
  int m_flag;

  struct segment {
    segment( uintptr_t addr , size_t cap ):
      address(addr),
      capacity(cap)
    {}
    uintptr_t address;
    size_t capacity;
  };
};

bool remote_allocator::init() {
  bool r1 = m_low_pool->init();
  bool r2 = m_high_pool->init();
  return r1 || r2;
}

uintptr_t remote_allocator::allocate( size_t cap , uintptr_t hint ) {
  if(hint < pool::kHighHint) {
    // Try to allocate it from low address pool
    uintptr_t ret = m_low_pool->allocate(cap);
    if(ret == 0) {
      // Try high pool since low pool may not be able to allocate
      return m_high_pool->allocate(cap);
    }
  } else {
    return m_high_pool->allocate(cap);
  }
}

size_t remote_allocator::size() const {
  return m_low_pool->size() + m_high_pool->size();
}

size_t remote_allocator::capacity() const {
  return m_low_pool->capacity() + m_high_pool->capacity();
}

remote_allocator::remote_allocator( process_info* pinfo ):
  m_low_pool( new pool( pinfo , pool::LOW ) ),
  m_high_pool(new pool( pinfo , pool::HIGH) )
{}

remote_allocator::~remote_allocator()
{}

} // namespace dynhook
