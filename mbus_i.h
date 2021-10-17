#pragma once

#include <sys/queue.h>
#include <pthread.h>

LIST_HEAD(mbus_method_list, mbus_method);
LIST_HEAD(mbus_rpc_list, mbus_rpc);

struct timespec;

typedef struct mbus {
  pthread_mutex_t m_mutex;
  struct mbus_rpc_list m_rpcs;
  struct mbus_method_list m_methods;
  uint8_t m_our_addr;
  uint8_t m_txid_gen[16];

  mbus_error_t (*m_send)(struct mbus *m, uint8_t addr, const void *data,
                         size_t len, const struct timespec *deadline);

  void (*m_destroy)(struct mbus *m);

} mbus_t;

uint32_t mbus_crc32(uint32_t crc, const void *data, size_t n_bytes);

void mbus_rx_handle_pkt(mbus_t *m, const uint8_t *pkt, size_t len);

void mbus_cancel_rpc(mbus_t *m);
