#include "mbus.h"
#include "mbus_i.h"

#include <assert.h>
#include <sys/param.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MBUS_FRAGMENT_SIZE 56

#define SP_FF   0x1
#define SP_LF   0x2

TAILQ_HEAD(mbus_gdpkt_queue, mbus_gdpkt);

typedef struct mbus_gdpkt {
  TAILQ_ENTRY(mbus_gdpkt) ms_link;

  size_t ms_len;

  uint8_t ms_flags;
  uint8_t ms_data[MBUS_FRAGMENT_SIZE];

} mbus_gdpkt_t;

typedef struct mbus_gdpkt_con {
  mbus_flow_t msc_flow;

  uint8_t msc_remote_flags;
  uint8_t msc_local_flags;

  uint8_t msc_seqgen;
  uint8_t msc_local_flags_sent;
  uint8_t msc_local_close;

  uint8_t msc_remote_close;
  uint8_t msc_new_fragment;

  struct mbus_gdpkt_queue msc_rxq;
  LIST_ENTRY(mbus_gdpkt_con) msc_link;

  mbus_t *msc_mbus;

  pthread_cond_t msc_rx_cond;
  pthread_cond_t msc_tx_cond;

  int64_t msc_last_rx;
  int64_t msc_last_tx;

  int32_t msc_next_xmit;

  uint16_t msc_xmit_credits;

} mbus_gdpkt_con_t;

static mbus_error_t mbus_gdpkt_send_locked(void *be,
                                            const void *data, size_t len);

static int mbus_gdpkt_recv_locked(void *be, void **ptr);

static void mbus_gdpkt_shutdown_locked(void *be);

static void mbus_gdpkt_close_locked(void *be, int wait);

static void mbus_gdpkt_input(struct mbus *m, struct mbus_flow *mf,
                              const uint8_t *pkt, size_t len);

mbus_con_t *
mbus_gdpkt_connect_locked(mbus_t *m, uint8_t remote_addr, const char *service)
{
  mbus_gdpkt_con_t *msc = calloc(1, sizeof(mbus_gdpkt_con_t));

  msc->msc_xmit_credits = 1;

  pthread_cond_init(&msc->msc_tx_cond, NULL);
  pthread_cond_init(&msc->msc_rx_cond, NULL);
  msc->msc_mbus = m;

  TAILQ_INIT(&msc->msc_rxq);

  msc->msc_flow.mf_remote_addr = remote_addr;
  msc->msc_flow.mf_input = mbus_gdpkt_input;
  mbus_flow_create(m, &msc->msc_flow);

  const size_t svclen = strlen(service);
  const size_t pktlen = 4 + svclen;
  uint8_t pkt[pktlen];

  mbus_flow_write_header(pkt, m, &msc->msc_flow, 1);

  pkt[3] = 0x3; // MBUS_GDPKT

  memcpy(pkt + 4, service, svclen);

  struct timespec deadline = mbus_deadline_from_timeout(10000);
  m->m_send(m, pkt, pktlen, &deadline);

  mbus_con_t *mc = calloc(1, sizeof(mbus_con_t));
  mc->backend = msc;
  mc->m = m;
  mc->send_locked = mbus_gdpkt_send_locked;
  mc->recv_locked = mbus_gdpkt_recv_locked;
  mc->shutdown_locked = mbus_gdpkt_shutdown_locked;
  mc->close_locked = mbus_gdpkt_close_locked;
  return mc;
}

static void
mbus_gdpkt_input(struct mbus *m, struct mbus_flow *mf,
                 const uint8_t *pkt, size_t len)
{
  mbus_gdpkt_con_t *msc = (mbus_gdpkt_con_t *)mf;

  if(len < 1)
    return;

  uint8_t flags = pkt[0];

  pkt += 1;
  len -= 1;

  if(flags & 0x80) {
    // Remote close
    msc->msc_remote_close = 1;
    pthread_cond_signal(&msc->msc_tx_cond);
  } else {
    const int credz = (flags >> 2) & 0xf;

    msc->msc_xmit_credits += credz;
    if(credz) {
      pthread_cond_signal(&msc->msc_tx_cond);
    }

    if(len) {
      mbus_gdpkt_t *ms = calloc(1, sizeof(mbus_gdpkt_t));
      ms->ms_flags = flags;
      ms->ms_len = len;
      memcpy(ms->ms_data, pkt, len);
      TAILQ_INSERT_TAIL(&msc->msc_rxq, ms, ms_link);
    }
  }

  pthread_cond_signal(&msc->msc_rx_cond);
}


static mbus_error_t
mbus_gdpkt_send_locked(void *be, const void *data, size_t len)
{
  mbus_gdpkt_con_t *msc = be;
  mbus_t *m = msc->msc_mbus;

  uint8_t flags = SP_FF;

  msc->msc_next_xmit = INT32_MAX;

  while(len) {

    if(msc->msc_remote_close || msc->msc_local_close)
      return MBUS_ERR_NOT_CONNECTED;

    if(msc->msc_xmit_credits == 0) {
      printf("credit stall\n");
      pthread_cond_wait(&msc->msc_tx_cond, &m->m_mutex);
      continue;
    }

    const size_t fragment_size = MIN(MBUS_FRAGMENT_SIZE, len);
    size_t pktlen = 4 + fragment_size;
    uint8_t pkt[pktlen];

    memcpy(pkt + 4, data, fragment_size);
    pkt[3] = 0;

    len -= fragment_size;
    data += fragment_size;

    if(len == 0)
      flags |= SP_LF;

    pkt[3] = flags;
    flags &= ~SP_FF;
    mbus_flow_write_header(pkt, m, &msc->msc_flow, 0);

    m->m_send(m, pkt, pktlen, NULL);
    msc->msc_xmit_credits--;
  }
  return 0;
}



static void
mbus_gdpkt_shutdown_locked(void *be)
{
  mbus_gdpkt_con_t *msc = be;
  mbus_t *m = msc->msc_mbus;

  uint8_t pkt[4];
  mbus_flow_write_header(pkt, m, &msc->msc_flow, 0);
  pkt[3] = 0x80;
  m->m_send(m, pkt, sizeof(pkt), NULL);
}


static int
mbus_gdpkt_reassembly(mbus_gdpkt_con_t *msc, void **ptr)
{
  size_t total_len = 0;

  mbus_gdpkt_t *ms = TAILQ_FIRST(&msc->msc_rxq);
  if(ms == NULL)
    return 0;

  if(!(ms->ms_flags & SP_FF))
    return -1; // Huh, strange errors

  while(1) {
    if(ms == NULL)
      return 0;

    total_len += ms->ms_len;

    if(ms->ms_flags & SP_LF)
      break;
    ms = TAILQ_NEXT(ms, ms_link);
  }

  void *pkt = malloc(total_len);
  size_t offset = 0;

  while(1) {
    ms = TAILQ_FIRST(&msc->msc_rxq);

    TAILQ_REMOVE(&msc->msc_rxq, ms, ms_link);
    memcpy(pkt + offset, ms->ms_data, ms->ms_len);
    offset += ms->ms_len;

    int last = ms->ms_flags & SP_LF;
    free(ms);
    if(last)
      break;
  }

  *ptr = pkt;
  return total_len;
}


static int
mbus_gdpkt_recv_locked(void *be, void **ptr)
{
  mbus_gdpkt_con_t *msc = be;
  mbus_t *m = msc->msc_mbus;
  while(1) {
    if(msc->msc_remote_close || msc->msc_local_close)
      return 0;

    int result = mbus_gdpkt_reassembly(msc, ptr);
    if(result)
      return result;
    pthread_cond_wait(&msc->msc_rx_cond, &m->m_mutex);
  }
}


static void
clearq(struct mbus_gdpkt_queue *msq)
{
  mbus_gdpkt_t *ms, *n;
  for(ms = TAILQ_FIRST(msq); ms != NULL; ms = n) {
    n = TAILQ_NEXT(ms, ms_link);
    free(ms);
  }
}

static void
mbus_gdpkt_close_locked(void *be, int wait)
{
  mbus_gdpkt_con_t *msc = be;

  clearq(&msc->msc_rxq);
  mbus_flow_remove(&msc->msc_flow);
  free(msc);
}
