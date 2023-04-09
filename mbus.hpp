#pragma once

#include "mbus.h"
#include <functional>

namespace MBUS {

class DsigSub {

public:
    DsigSub(mbus_t *m, uint16_t signal, int64_t ttl,
          std::function<void(const uint8_t *pkt, size_t len)> fn)
    : m_fn(fn)
    , m_sub(mbus_dsig_sub(m, signal, &cb, this, ttl))
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


class DsigDrive {
public:
    DsigDrive(mbus_t *m, uint16_t signal, int period_ms)
        : m_mbus(m)
        , m_driver(mbus_dsig_drive2(m, signal, period_ms))
    {};

    void set(const void *data, size_t len) {
        mbus_dsig_set(m_mbus, m_driver, data, len);
    }

    void clear() {
        mbus_dsig_clear(m_mbus, m_driver);
    }

private:

    mbus_t *m_mbus;
    mbus_dsig_driver_t *m_driver;
};

}
