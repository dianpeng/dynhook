#ifndef BASE_H_
#define BASE_H_

#include <cstddef>
#include <inttypes.h>
#include <unistd.h>
#include <cstring>
#include <boost/array.hpp>

#define UNUSED_ARG(X) (void)(X)

namespace dynhook {
static const size_t kWordSize = sizeof(uintptr_t);

namespace base {

void dump_assembly( const char* cd , size_t sz ,
    std::ostream& output );

class scoped_fd {
 public:
  explicit scoped_fd( int fd ):
    m_fd(fd) {}

  int fd() const {
    return m_fd;
  }

  operator bool() const {
    return m_fd >= 0;
  }

  ~scoped_fd() {
    if(m_fd>=0)
      ::close(m_fd);
  }
 private:
  int m_fd;
};

class int64_array {
 public:
  int64_array( uintptr_t value ) {
    memcpy(m_arr.c_array(),&value,sizeof(uintptr_t));
  }

  char operator [] ( int idx ) const  {
    assert(idx >=0);
    assert(idx < sizeof(uintptr_t));
    return m_arr[idx];
  }

  char&operator [] ( int idx ) {
    assert(idx >=0);
    assert(idx < sizeof(uintptr_t));
    return m_arr[idx];
  }

  uintptr_t to_int64() const {
    uintptr_t n = 0;
    n = (((uintptr_t)m_arr[7] << 56) & 0xFF00000000000000U)
      | (((uintptr_t)m_arr[6] << 48) & 0x00FF000000000000U)
      | (((uintptr_t)m_arr[5] << 40) & 0x0000FF0000000000U)
      | (((uintptr_t)m_arr[4] << 32) & 0x000000FF00000000U)
      | ((m_arr[3] << 24) & 0x00000000FF000000U)
      | ((m_arr[2] << 16) & 0x0000000000FF0000U)
      | ((m_arr[1] <<  8) & 0x000000000000FF00U)
      | (m_arr[0]        & 0x00000000000000FFU);
    return n;
  }

 private:
  boost::array<char,sizeof(uintptr_t)> m_arr;
};

template< typename T , typename U >
inline T alignment( T value , U target ) {
  return (value + target-1) &~(target-1);
}
} // namespace base

bool init_the_world( int argc, char* argv[] );

} // namespace dynhook

#endif // BASE_H_
