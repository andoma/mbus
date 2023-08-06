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

#define SP_TIME_TIMEOUT  2500000
#define SP_TIME_KA       300000
#define SP_TIME_RTX      100000
#define SP_TIME_ACK      20000
#define SP_TIME_FAST_ACK 1000


#define SP_FF   0x1
#define SP_LF   0x2
#define SP_ESEQ 0x4
#define SP_SEQ  0x8
#define SP_CTS  0x10
#define SP_MORE 0x20
#define SP_EOS  0x40


// Transmit because sequence bumped, we're sending a new fragment
#define SP_XMIT_NEW_FRAGMENT  0x1

// Transmit because RTX timer has expired
#define SP_XMIT_RTX           0x2

// Transmit because CTS changed
#define SP_XMIT_CTS_CHANGED   0x4

// Transmit because expected SEQ changed
#define SP_XMIT_ESEQ_CHANGED  0x8

// Transmit because close
#define SP_XMIT_CLOSE         0x10

// Transmit because KA
#define SP_XMIT_KA            0x20




TAILQ_HEAD(mbus_seqpkt_queue, mbus_seqpkt);

typedef struct mbus_seqpkt {
  TAILQ_ENTRY(mbus_seqpkt) ms_link;

  uint8_t ms_flags;

  size_t ms_len;
  uint8_t ms_data[MBUS_FRAGMENT_SIZE];

} mbus_seqpkt_t;

typedef struct mbus_seqpkt_con {
  mbus_flow_t msc_flow;

  uint8_t msc_remote_flags;
  uint8_t msc_local_flags;

  uint8_t msc_seqgen;
  uint8_t msc_local_flags_sent;
  uint8_t msc_local_close;

  uint8_t msc_remote_close;
  uint8_t msc_new_fragment;

  size_t msc_txq_len;
  struct mbus_seqpkt_queue msc_txq;
  struct mbus_seqpkt_queue msc_rxq;
  LIST_ENTRY(mbus_seqpkt_con) msc_link;

  mbus_timer_t msc_ack_timer;
  mbus_timer_t msc_rtx_timer;
  mbus_timer_t msc_ka_timer;

  mbus_t *msc_mbus;

  pthread_cond_t msc_rx_cond;
  pthread_cond_t msc_tx_cond;

  int64_t msc_last_rx;
  int64_t msc_last_tx;

  int32_t msc_next_xmit;

} mbus_seqpkt_con_t;

static mbus_error_t mbus_seqpkt_send_locked(void *be,
                                            const void *data, size_t len);

static int mbus_seqpkt_recv_locked(void *be, void **ptr);

static void mbus_seqpkt_shutdown_locked(void *be);

static void mbus_seqpkt_close_locked(void *be, int wait);

static void mbus_seqpkt_rtx_timer(mbus_t *m, void *opaque, int64_t expire);

static void mbus_seqpkt_ack_timer(mbus_t *m, void *opaque, int64_t expire);

static void mbus_seqpkt_ka_timer(mbus_t *m, void *opaque, int64_t expire);

static void mbus_seqpkt_input(struct mbus *m, struct mbus_flow *mf,
                              const uint8_t *pkt, size_t len);

mbus_con_t *
mbus_seqpkt_connect_locked(mbus_t *m, uint8_t remote_addr, const char *service)
{
  mbus_seqpkt_con_t *msc = calloc(1, sizeof(mbus_seqpkt_con_t));

  msc->msc_rtx_timer.mt_cb = mbus_seqpkt_rtx_timer;
  msc->msc_rtx_timer.mt_opaque = msc;

  msc->msc_ack_timer.mt_cb = mbus_seqpkt_ack_timer;
  msc->msc_ack_timer.mt_opaque = msc;

  msc->msc_ka_timer.mt_cb = mbus_seqpkt_ka_timer;
  msc->msc_ka_timer.mt_opaque = msc;

  msc->msc_local_flags = SP_CTS;
  msc->msc_remote_flags = 0;

  msc->msc_new_fragment = 1;

  pthread_cond_init(&msc->msc_tx_cond, NULL);
  pthread_cond_init(&msc->msc_rx_cond, NULL);
  msc->msc_mbus = m;
  TAILQ_INIT(&msc->msc_txq);
  TAILQ_INIT(&msc->msc_rxq);

  msc->msc_flow.mf_remote_addr = remote_addr;
  msc->msc_flow.mf_input = mbus_seqpkt_input;
  mbus_flow_create(m, &msc->msc_flow);

  const size_t svclen = strlen(service);
  const size_t pktlen = 4 + svclen;
  uint8_t pkt[pktlen];

  mbus_flow_write_header(pkt, m, &msc->msc_flow, 1);

  pkt[3] = 0x1; // MBUS_SEQPKT

  memcpy(pkt + 4, service, svclen);

  struct timespec deadline = mbus_deadline_from_timeout(1000);
  m->m_send(m, pkt, pktlen, &deadline);
  msc->msc_last_rx = mbus_get_ts();

  mbus_timer_arm(m, &msc->msc_ka_timer, msc->msc_last_rx + SP_TIME_KA);

  mbus_con_t *mc = calloc(1, sizeof(mbus_con_t));
  mc->backend = msc;
  mc->m = m;
  mc->send_locked = mbus_seqpkt_send_locked;
  mc->recv_locked = mbus_seqpkt_recv_locked;
  mc->shutdown_locked = mbus_seqpkt_shutdown_locked;
  mc->close_locked = mbus_seqpkt_close_locked;
  return mc;
}



static void
release_txq(mbus_seqpkt_con_t *msc)
{
  mbus_seqpkt_t *ms = TAILQ_FIRST(&msc->msc_txq);
  if(ms == NULL)
    return;

  const int sent_seq = !!(ms->ms_flags & SP_SEQ);
  const int expected_seq = !!(msc->msc_remote_flags & SP_ESEQ);
  if(sent_seq == expected_seq)
    return;

  TAILQ_REMOVE(&msc->msc_txq, ms, ms_link);
  msc->msc_txq_len--;
  free(ms);
  mbus_timer_disarm(&msc->msc_rtx_timer);
  msc->msc_new_fragment = 1;

  pthread_cond_signal(&msc->msc_tx_cond);
}


static void
mbus_seqpkt_remote_close(mbus_seqpkt_con_t *msc, const char *reason)
{
  mbus_log(msc->msc_mbus, "Disconnected -- %s", reason);
  msc->msc_remote_close = 1;
  pthread_cond_signal(&msc->msc_rx_cond);
  pthread_cond_signal(&msc->msc_tx_cond);
}


static void
mbus_seqpkt_output(mbus_seqpkt_con_t *msc, int xmit)
{
  if(msc->msc_remote_close)
    return;

  uint8_t pkt[64];
  size_t pktlen = 4;


  mbus_seqpkt_t *tx = TAILQ_FIRST(&msc->msc_txq);
  if(tx != NULL) {
    const int send_seq = !!(tx->ms_flags & SP_SEQ);
    const int expected_seq = !!(msc->msc_remote_flags & SP_ESEQ);
    if(send_seq != expected_seq || !(msc->msc_remote_flags & SP_CTS)) {
      tx = NULL;
    } else if(msc->msc_new_fragment) {
      msc->msc_new_fragment = 0;
      xmit |= SP_XMIT_NEW_FRAGMENT;
    }
  }

  xmit |= msc->msc_local_close ? SP_XMIT_CLOSE : 0;

  // We always assert CTS as we have "infinite" buffers
  // (At least compared to an embedded system)
  //  xmit |= update_local_cts(msc);

  if(!xmit)
    return;

  int64_t now = mbus_get_ts();

  mbus_flow_write_header(pkt, msc->msc_mbus, &msc->msc_flow, 0);
  pkt[3] = msc->msc_local_flags;

  if(tx != NULL && (xmit & (SP_XMIT_NEW_FRAGMENT | SP_XMIT_RTX))) {

    msc->msc_local_flags =
      (msc->msc_local_flags & ~SP_SEQ) | (tx->ms_flags & SP_SEQ);

    pkt[3] = msc->msc_local_flags | (tx->ms_flags & (SP_FF | SP_LF));
    if(TAILQ_NEXT(tx, ms_link))
      pkt[3] |= SP_MORE;

    memcpy(pkt + 4, tx->ms_data, tx->ms_len);
    pktlen += tx->ms_len;

    mbus_timer_arm(msc->msc_mbus, &msc->msc_rtx_timer, now + SP_TIME_RTX);

  } else if(msc->msc_local_close) {

    const int last_seq = !!(msc->msc_local_flags_sent & SP_SEQ);
    const int expected_seq = !!(msc->msc_remote_flags & SP_ESEQ);

    if(last_seq != expected_seq) {
      pkt[3] = 0x80; // Send close
    }
  }

  msc->msc_local_flags_sent = pkt[3];

  msc->msc_last_tx = now;

  mbus_t *m = msc->msc_mbus;
  m->m_send(m, pkt, pktlen, NULL);
}




static void
mbus_seqpkt_input(struct mbus *m, struct mbus_flow *mf,
                  const uint8_t *pkt, size_t len)
{
  mbus_seqpkt_con_t *msc = (mbus_seqpkt_con_t *)mf;

  if(pkt[0] & 0x80) {
    // Got close
    mbus_seqpkt_remote_close(msc, "Received close");
    return;
  }

  msc->msc_last_rx = mbus_get_ts();
  msc->msc_remote_flags = pkt[0];

  release_txq(msc);

  pkt += 1;
  len -= 1;

  if(len > MBUS_FRAGMENT_SIZE) {
    mbus_seqpkt_remote_close(msc, "Oversized frame");
    return;
  }

  if(len) {

    const int recv_seq = !!(msc->msc_remote_flags & SP_SEQ);
    const int expect_seq = !!(msc->msc_local_flags & SP_ESEQ);

    if(recv_seq == expect_seq && msc->msc_local_flags & SP_CTS) {

      msc->msc_local_flags ^= SP_ESEQ;

      const int ack_time = msc->msc_remote_flags & SP_MORE ?
        SP_TIME_FAST_ACK : SP_TIME_ACK;
      mbus_timer_arm(m, &msc->msc_ack_timer, msc->msc_last_rx + ack_time);

      mbus_seqpkt_t *ms = calloc(1, sizeof(mbus_seqpkt_t));
      ms->ms_flags = msc->msc_remote_flags;
      ms->ms_len = len;
      memcpy(ms->ms_data, pkt, len);
      TAILQ_INSERT_TAIL(&msc->msc_rxq, ms, ms_link);
      pthread_cond_signal(&msc->msc_rx_cond);
    }
  }

  mbus_seqpkt_output(msc, 0);
}



static mbus_error_t
mbus_seqpkt_send_locked(void *be, const void *data, size_t len)
{
  mbus_seqpkt_con_t *msc = be;
  uint8_t flags = SP_FF;

  msc->msc_next_xmit = INT32_MAX;

  while(len) {
    if(msc->msc_remote_close || msc->msc_local_close)
      return MBUS_ERR_NOT_CONNECTED;

    if(msc->msc_txq_len > 5) {
      pthread_cond_wait(&msc->msc_tx_cond, &msc->msc_mbus->m_mutex);
      continue;
    }

    size_t fragment_size = MIN(MBUS_FRAGMENT_SIZE, len);

    mbus_seqpkt_t *ms = calloc(1, sizeof(mbus_seqpkt_t));
    ms->ms_flags = flags;
    flags = 0;
    memcpy(ms->ms_data, data, fragment_size);
    ms->ms_len = fragment_size;

    len -= fragment_size;
    data += fragment_size;

    if(len == 0)
      ms->ms_flags |= SP_LF;

    if(msc->msc_seqgen & 1)
      ms->ms_flags |= SP_SEQ;

    msc->msc_seqgen++;
    TAILQ_INSERT_TAIL(&msc->msc_txq, ms, ms_link);
    msc->msc_txq_len++;
  }

  mbus_seqpkt_output(msc, 0);
  return 0;
}

static void
mbus_seqpkt_shutdown_locked(void *be)
{
  mbus_seqpkt_con_t *msc = be;

  msc->msc_local_close = 1;
  pthread_cond_signal(&msc->msc_rx_cond);
  pthread_cond_signal(&msc->msc_tx_cond);
  mbus_seqpkt_output(msc, 0);
}


static int
mbus_seqpkt_reassembly(mbus_seqpkt_con_t *msc, void **ptr)
{
  size_t total_len = 0;

  mbus_seqpkt_t *ms = TAILQ_FIRST(&msc->msc_rxq);
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
mbus_seqpkt_recv_locked(void *be, void **ptr)
{
  mbus_seqpkt_con_t *msc = be;
  mbus_t *m = msc->msc_mbus;
  while(1) {
    if(msc->msc_remote_close || msc->msc_local_close)
      return 0;

    int result = mbus_seqpkt_reassembly(msc, ptr);
    if(result)
      return result;
    pthread_cond_wait(&msc->msc_rx_cond, &m->m_mutex);
  }
}


static void
clearq(struct mbus_seqpkt_queue *msq)
{
  mbus_seqpkt_t *ms, *n;
  for(ms = TAILQ_FIRST(msq); ms != NULL; ms = n) {
    n = TAILQ_NEXT(ms, ms_link);
    free(ms);
  }
}

static void
mbus_seqpkt_close_locked(void *be, int wait)
{
  mbus_seqpkt_con_t *msc = be;
  mbus_t *m = msc->msc_mbus;

  if(wait) {
    while(msc->msc_txq_len) {
      pthread_cond_wait(&msc->msc_tx_cond, &m->m_mutex);
    }
  }

  clearq(&msc->msc_txq);
  clearq(&msc->msc_rxq);
  mbus_flow_remove(&msc->msc_flow);
  mbus_timer_disarm(&msc->msc_ack_timer);
  mbus_timer_disarm(&msc->msc_rtx_timer);
  mbus_timer_disarm(&msc->msc_ka_timer);
  free(msc);
}

static void
mbus_seqpkt_rtx_timer(mbus_t *m, void *opaque, int64_t now)
{
  mbus_seqpkt_output(opaque, SP_XMIT_RTX);
}

static void
mbus_seqpkt_ack_timer(mbus_t *m, void *opaque, int64_t now)
{
  mbus_seqpkt_output(opaque, SP_XMIT_ESEQ_CHANGED);
}

static void
mbus_seqpkt_ka_timer(mbus_t *m, void *opaque, int64_t now)
{
  mbus_seqpkt_con_t *msc = opaque;

  if(now > msc->msc_last_rx + SP_TIME_TIMEOUT) {
    msc->msc_remote_close = 1;
    pthread_cond_signal(&msc->msc_rx_cond);
    pthread_cond_signal(&msc->msc_tx_cond);
  } else {
    mbus_timer_arm(m, &msc->msc_ka_timer, now + SP_TIME_KA);

    if(now > msc->msc_last_tx + SP_TIME_KA)
      mbus_seqpkt_output(opaque, SP_XMIT_KA);

  }
}
