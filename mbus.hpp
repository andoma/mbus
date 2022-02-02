#include "mbus.h"
#include <functional>

namespace MBUS {

class DsigSub {

public:
  DsigSub(mbus_t *m, uint8_t signal,
          std::function<void(const uint8_t *pkt, size_t len)> fn)
    : m_fn(fn)
    , m_sub(mbus_dsig_sub(m, signal, &cb,  this))
  {

  }

private:
  std::function<void(const uint8_t *pkt, size_t len)> m_fn;
  mbus_dsig_sub_t *m_sub;

  static void cb(void *self, const uint8_t *pkt, size_t len)
  {
    DsigSub *ds = (DsigSub *)self;
    ds->m_fn(pkt, len);
  }



};

}
