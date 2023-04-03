#pragma once

#include "mbus.h"
#include <sys/queue.h>
#include <pthread.h>

LIST_HEAD(mbus_method_list, mbus_method); // TODO: Used?
LIST_HEAD(mbus_seqpkt_con_list, mbus_seqpkt_con);
LIST_HEAD(mbus_timer_list, mbus_timer);
LIST_HEAD(mbus_flow_list, mbus_flow);

struct timespec;


typedef struct mbus_flow {

  LIST_ENTRY(mbus_flow) mf_link;
  uint16_t mf_flow;
  uint8_t mf_remote_addr;

  void (*mf_input)(struct mbus *m, struct mbus_flow *mf,
                   const uint8_t *pkt, size_t len);

} mbus_flow_t;




typedef struct mbus_timer {
  LIST_ENTRY(mbus_timer) mt_link;
  void (*mt_cb)(struct mbus *m, void *opaque, int64_t expire);
  void *mt_opaque;
  int64_t mt_expire;
} mbus_timer_t;


typedef struct mbus {
  pthread_mutex_t m_mutex;
  uint8_t m_our_addr;

  int m_connection_id_gen;

  mbus_error_t (*m_send)(struct mbus *m, const void *data,
                         size_t len, const struct timespec *deadline);

  void (*m_destroy)(struct mbus *m);

  pthread_t m_timer_thread;
  pthread_cond_t m_timer_cond;

  LIST_HEAD(, mbus_dsig_driver) m_dsig_drivers;
  LIST_HEAD(, mbus_dsig_sub) m_dsig_subs;

  struct mbus_gateway *m_gateway;

  int m_debug_level;

  mbus_log_cb_t *m_log_cb;
  void *m_aux;
  int64_t m_def_log_prev;

  struct mbus_flow_list m_flows;

  struct mbus_seqpkt_con_list m_seqpkt_cons;

  struct mbus_timer_list m_timers;

  struct mbus_seqpkt_con *m_rpc_channels[32];

} mbus_t;

void mbus_timer_arm(mbus_t *m, mbus_timer_t *t, int64_t expire);

void mbus_timer_disarm(mbus_timer_t *t);

void mbus_init_common(mbus_t *m, mbus_log_cb_t *log_cb, void *aux);

uint32_t mbus_crc32(uint32_t crc, const void *data, size_t n_bytes);

void mbus_rx_handle_pkt(mbus_t *m, const uint8_t *pkt, size_t len,
                        int check_crc);

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

void mbus_gateway_recv_multicast(struct mbus *m, const uint8_t *pkt,
                                 size_t len);

mbus_flow_t *mbus_flow_find(mbus_t *m, uint8_t remote_addr, uint16_t flow);

void mbus_flow_insert(mbus_t *m, mbus_flow_t *mf);

void mbus_flow_remove(mbus_flow_t *mf);

void mbus_flow_create(mbus_t *m, mbus_flow_t *mf);

void mbus_flow_write_header(uint8_t pkt[static 3],
                            const mbus_t *m, const mbus_flow_t *mf, int init);


mbus_seqpkt_con_t *mbus_seqpkt_connect_locked(mbus_t *m, uint8_t remote_addr,
                                              const char *service);

mbus_error_t mbus_seqpkt_send_locked(mbus_seqpkt_con_t *msc, const void *data,
                                     size_t len);

int mbuf_seqpkt_recv_locked(mbus_seqpkt_con_t *msc, void **ptr, mbus_t *m);

void mbus_seqpkt_shutdown_locked(mbus_seqpkt_con_t *msc);

