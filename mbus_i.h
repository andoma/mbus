#pragma once

#include "mbus.h"
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

  pthread_t m_timer_thread;
  pthread_cond_t m_dsig_driver_cond;

  LIST_HEAD(, mbus_dsig_driver) m_dsig_drivers;
  LIST_HEAD(, mbus_dsig_sub) m_dsig_subs;

#ifdef MBUS_ENABLE_PCS
  pcs_iface_t *m_pcs;
  pthread_t m_pcs_thread;
#endif

  struct mbus_gateway *m_gateway;

  int m_debug_level;

  mbus_log_cb_t *m_log_cb;
  void *m_aux;
  int64_t m_def_log_prev;

  const void *m_ota_image;
  size_t m_ota_image_size;
  int m_ota_completed;
  pthread_cond_t m_ota_cond;
  uint8_t m_ota_remote_addr;
  mbus_error_t m_ota_xfer_error;

  uint8_t host_active[16];
  int64_t next_host_active_clear;

} mbus_t;


void mbus_init_common(mbus_t *m, mbus_log_cb_t *log_cb, void *aux);

uint32_t mbus_crc32(uint32_t crc, const void *data, size_t n_bytes);

void mbus_rx_handle_pkt(mbus_t *m, const uint8_t *pkt, size_t len,
                        int check_crc);

void mbus_cancel_rpc(mbus_t *m);

void mbus_log(const mbus_t *m, const char *fmt, ...);

void mbus_hexdump(const mbus_t *m, const char *prefix, const void* data_, int len);

mbus_error_t mbus_invoke_locked(mbus_t *m, uint8_t addr,
                                const char *name, const void *req,
                                size_t req_size, void *reply,
                                size_t* reply_size,
                                const struct timespec* deadline);

struct timespec mbus_deadline_from_timeout(int timeout_ms);

void mbus_pkt_trace(const mbus_t *m, const char *prefix,
                    const uint8_t *pkt, size_t len);

int mbus_gateway_intercept(struct mbus *m, const uint8_t *pkt, size_t len);
