#include "mbus.h"
#include "mbus_i.h"

#include <sys/param.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>
#include <stdarg.h>

#include "mbus_gateway.h"




static int
str_tokenize(char *buf, char **vec, int vecsize, int delimiter)
{
  int n = 0;

  while(1) {
    while((*buf > 0 && *buf < 33) || *buf == delimiter)
      buf++;
    if(*buf == 0)
      break;
    vec[n++] = buf;
    if(n == vecsize)
      break;
    while(*buf > 32 && *buf != delimiter)
      buf++;
    if(*buf == 0)
      break;
    *buf = 0;
    buf++;
  }
  return n;
}

static mbus_t *mbus_create_dummy(void);


mbus_t *
mbus_create_from_constr(const char *str0, uint8_t local_addr,
                        mbus_log_cb_t *log_cb, void *aux)
{
#ifdef HAVE_BLE
  if(!strncmp(str0, "ble:", 4)) {
    return mbus_create_ble(str0+4, // Hostname
                           local_addr, log_cb, aux);
  }
#endif
  const size_t slen = strlen(str0) + 1;
  char *str = alloca(slen);
  strcpy(str, str0);

  char *argv[10];
  int argc = str_tokenize(str, argv, 10, ':');

  if(argc == 3 && !strcmp(argv[0], "tcp")) {
    return mbus_create_tcp(argv[1], // Hostname
                           atoi(argv[2]), // Port
                           local_addr, log_cb, aux);
  } else if(argc >= 3 && !strcmp(argv[0], "usb")) {
    return mbus_create_usb(strtol(argv[1], NULL, 16),    // VID
                           strtol(argv[2], NULL, 16),    // PID
                           argc > 3 ? atoi(argv[3]) : 0, // vendor subclass
                           argc > 4 ? argv[4] : NULL,    // Serial number
                           local_addr,
                           log_cb,
                           NULL, aux);
  } else if(argc == 1 && !strcmp(argv[0], "none")) {
    return mbus_create_dummy();
  } else {
    fprintf(stderr, "Unknown connection-string: %s\n", str0);
    return NULL;
  }
}


void
mbus_set_debug_level(mbus_t *m, int level)
{
  m->m_debug_level = level;
}

uint8_t
mbus_get_local_addr(mbus_t *m)
{
  return m->m_our_addr;
}

int64_t
mbus_get_ts(void)
{
#ifdef __linux__
  struct timespec tv;
  clock_gettime(CLOCK_MONOTONIC, &tv);
  return (int64_t)tv.tv_sec * 1000000LL + (tv.tv_nsec / 1000);
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
#endif
}

static struct timespec
usec_to_timespec(uint64_t ts)
{
  return (struct timespec){.tv_sec = ts / 1000000LL,
                           .tv_nsec = (ts % 1000000LL) * 1000};
}


struct timespec
mbus_deadline_from_timeout(int timeout_ms)
{
  int64_t when = mbus_get_ts() + timeout_ms * 1000;
  return usec_to_timespec(when);
}

void
mbus_hexdump(const mbus_t *m, const char *prefix, const void* data_, int len)
{
  int i, j, k;
  const uint8_t* data = data_;
  char buf[100];

  for (i = 0; i < len; i += 16) {
    int p = snprintf(buf, sizeof(buf), "0x%06x: ", i);

    for (j = 0; j + i < len && j < 16; j++) {
      p += snprintf(buf + p, sizeof(buf) - p, "%s%02x ",
                    j == 8 ? " " : "", data[i + j]);
    }
    const int cnt = (17 - j) * 3 + (j < 8);
    for (k = 0; k < cnt; k++)
      buf[p + k] = ' ';
    p += cnt;

    for (j = 0; j + i < len && j < 16; j++)
      buf[p++] =
        data[i + j] < 32 || data[i + j] > 126 ? '.' : data[i + j];
    buf[p] = 0;
    mbus_log(m, "%s: %s", prefix, buf);
  }
}


static const uint32_t crc32table[256] = {
    0xd202ef8d, 0xa505df1b, 0x3c0c8ea1, 0x4b0bbe37, 0xd56f2b94, 0xa2681b02,
    0x3b614ab8, 0x4c667a2e, 0xdcd967bf, 0xabde5729, 0x32d70693, 0x45d03605,
    0xdbb4a3a6, 0xacb39330, 0x35bac28a, 0x42bdf21c, 0xcfb5ffe9, 0xb8b2cf7f,
    0x21bb9ec5, 0x56bcae53, 0xc8d83bf0, 0xbfdf0b66, 0x26d65adc, 0x51d16a4a,
    0xc16e77db, 0xb669474d, 0x2f6016f7, 0x58672661, 0xc603b3c2, 0xb1048354,
    0x280dd2ee, 0x5f0ae278, 0xe96ccf45, 0x9e6bffd3, 0x0762ae69, 0x70659eff,
    0xee010b5c, 0x99063bca, 0x000f6a70, 0x77085ae6, 0xe7b74777, 0x90b077e1,
    0x09b9265b, 0x7ebe16cd, 0xe0da836e, 0x97ddb3f8, 0x0ed4e242, 0x79d3d2d4,
    0xf4dbdf21, 0x83dcefb7, 0x1ad5be0d, 0x6dd28e9b, 0xf3b61b38, 0x84b12bae,
    0x1db87a14, 0x6abf4a82, 0xfa005713, 0x8d076785, 0x140e363f, 0x630906a9,
    0xfd6d930a, 0x8a6aa39c, 0x1363f226, 0x6464c2b0, 0xa4deae1d, 0xd3d99e8b,
    0x4ad0cf31, 0x3dd7ffa7, 0xa3b36a04, 0xd4b45a92, 0x4dbd0b28, 0x3aba3bbe,
    0xaa05262f, 0xdd0216b9, 0x440b4703, 0x330c7795, 0xad68e236, 0xda6fd2a0,
    0x4366831a, 0x3461b38c, 0xb969be79, 0xce6e8eef, 0x5767df55, 0x2060efc3,
    0xbe047a60, 0xc9034af6, 0x500a1b4c, 0x270d2bda, 0xb7b2364b, 0xc0b506dd,
    0x59bc5767, 0x2ebb67f1, 0xb0dff252, 0xc7d8c2c4, 0x5ed1937e, 0x29d6a3e8,
    0x9fb08ed5, 0xe8b7be43, 0x71beeff9, 0x06b9df6f, 0x98dd4acc, 0xefda7a5a,
    0x76d32be0, 0x01d41b76, 0x916b06e7, 0xe66c3671, 0x7f6567cb, 0x0862575d,
    0x9606c2fe, 0xe101f268, 0x7808a3d2, 0x0f0f9344, 0x82079eb1, 0xf500ae27,
    0x6c09ff9d, 0x1b0ecf0b, 0x856a5aa8, 0xf26d6a3e, 0x6b643b84, 0x1c630b12,
    0x8cdc1683, 0xfbdb2615, 0x62d277af, 0x15d54739, 0x8bb1d29a, 0xfcb6e20c,
    0x65bfb3b6, 0x12b88320, 0x3fba6cad, 0x48bd5c3b, 0xd1b40d81, 0xa6b33d17,
    0x38d7a8b4, 0x4fd09822, 0xd6d9c998, 0xa1def90e, 0x3161e49f, 0x4666d409,
    0xdf6f85b3, 0xa868b525, 0x360c2086, 0x410b1010, 0xd80241aa, 0xaf05713c,
    0x220d7cc9, 0x550a4c5f, 0xcc031de5, 0xbb042d73, 0x2560b8d0, 0x52678846,
    0xcb6ed9fc, 0xbc69e96a, 0x2cd6f4fb, 0x5bd1c46d, 0xc2d895d7, 0xb5dfa541,
    0x2bbb30e2, 0x5cbc0074, 0xc5b551ce, 0xb2b26158, 0x04d44c65, 0x73d37cf3,
    0xeada2d49, 0x9ddd1ddf, 0x03b9887c, 0x74beb8ea, 0xedb7e950, 0x9ab0d9c6,
    0x0a0fc457, 0x7d08f4c1, 0xe401a57b, 0x930695ed, 0x0d62004e, 0x7a6530d8,
    0xe36c6162, 0x946b51f4, 0x19635c01, 0x6e646c97, 0xf76d3d2d, 0x806a0dbb,
    0x1e0e9818, 0x6909a88e, 0xf000f934, 0x8707c9a2, 0x17b8d433, 0x60bfe4a5,
    0xf9b6b51f, 0x8eb18589, 0x10d5102a, 0x67d220bc, 0xfedb7106, 0x89dc4190,
    0x49662d3d, 0x3e611dab, 0xa7684c11, 0xd06f7c87, 0x4e0be924, 0x390cd9b2,
    0xa0058808, 0xd702b89e, 0x47bda50f, 0x30ba9599, 0xa9b3c423, 0xdeb4f4b5,
    0x40d06116, 0x37d75180, 0xaede003a, 0xd9d930ac, 0x54d13d59, 0x23d60dcf,
    0xbadf5c75, 0xcdd86ce3, 0x53bcf940, 0x24bbc9d6, 0xbdb2986c, 0xcab5a8fa,
    0x5a0ab56b, 0x2d0d85fd, 0xb404d447, 0xc303e4d1, 0x5d677172, 0x2a6041e4,
    0xb369105e, 0xc46e20c8, 0x72080df5, 0x050f3d63, 0x9c066cd9, 0xeb015c4f,
    0x7565c9ec, 0x0262f97a, 0x9b6ba8c0, 0xec6c9856, 0x7cd385c7, 0x0bd4b551,
    0x92dde4eb, 0xe5dad47d, 0x7bbe41de, 0x0cb97148, 0x95b020f2, 0xe2b71064,
    0x6fbf1d91, 0x18b82d07, 0x81b17cbd, 0xf6b64c2b, 0x68d2d988, 0x1fd5e91e,
    0x86dcb8a4, 0xf1db8832, 0x616495a3, 0x1663a535, 0x8f6af48f, 0xf86dc419,
    0x660951ba, 0x110e612c, 0x88073096, 0xff000000
};


uint32_t
mbus_crc32(uint32_t crc, const void *data, size_t n_bytes)
{
  for (size_t i = 0; i < n_bytes; ++i)
    crc = crc32table[(uint8_t)crc ^ ((uint8_t*)data)[i]] ^ crc >> 8;

  return crc;
}



struct mbus_rpc {
  LIST_ENTRY(mbus_rpc) mr_link;
  uint8_t mr_txid;
  uint8_t mr_remote_addr;
  pthread_cond_t mr_cond;
  int mr_completed;
  int mr_error;
  size_t mr_reply_len;
  uint8_t mr_reply[64];
};

typedef struct mbus_method {
  LIST_ENTRY(mbus_method) mm_link;
  uint32_t mm_id;
  uint8_t mm_addr;
  char mm_name[0];
} mbus_method_t;


typedef struct mbus_rpc mbus_rpc_t;


static void *timer_thread(void *aux);

static void dsig_handle(mbus_t *m, uint16_t signal, const uint8_t *pkt, size_t len);



static int
get_delta_time(mbus_t *m)
{
  int r = 0;
  int64_t now = mbus_get_ts();
  if(m->m_def_log_prev == 0)
    r = 0;
  else
    r = now - m->m_def_log_prev;
  m->m_def_log_prev = now;
  return r;
}


static void
def_log_cb(void *aux, const char *msg)
{
  mbus_t *m = aux;
  fprintf(stderr, "mbus: %7d | %s\n", get_delta_time(m), msg);
}



void
mbus_log(const mbus_t *m, const char *fmt, ...)
{
  va_list ap;
  char buf[1024];
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  m->m_log_cb(m->m_aux, buf);
  va_end(ap);
}



void
mbus_init_common(mbus_t *m, mbus_log_cb_t *log_cb, void *aux)
{
  m->m_log_cb = log_cb ?: def_log_cb;
  m->m_aux = log_cb ? aux : m;

  if(m->m_connect_locked == NULL)
    m->m_connect_locked = mbus_seqpkt_connect_locked;

  m->m_connection_id_gen = rand();

  pthread_mutex_init(&m->m_mutex, NULL);

  pthread_condattr_t attr;
  pthread_condattr_init(&attr);
#ifdef __linux__
  pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
  pthread_cond_init(&m->m_timer_cond, &attr);

  pthread_create(&m->m_timer_thread, NULL, timer_thread, m);

  pthread_condattr_destroy(&attr);
}

void
mbus_destroy(mbus_t *m)
{
  m->m_destroy(m);
}


void
mbus_pkt_trace(const mbus_t *m, const char *prefix,
               const uint8_t *pkt, size_t len, int level)
{
  if(m->m_debug_level >= level) {
    mbus_hexdump(m, prefix, pkt, len);
  }
}


void
mbus_rx_handle_pkt(mbus_t *m, const uint8_t *pkt, size_t len, int check_crc)
{
  mbus_pkt_trace(m, "RX", pkt, len, 3);

  if(check_crc) {
    if(len < 4 || ~mbus_crc32(0, pkt, len)) {
      return;
    }
    len -= 4;
  }

  if(len < 2)
    return;

  uint32_t dst_addr = pkt[0];
  if(dst_addr >= 32) {
    // Multicast
    const uint16_t signal = ((dst_addr & 0x1f) << 8) | pkt[1];

    if(m->m_gateway)
      mbus_gateway_recv_multicast(m, pkt, len);

    if(signal < 4096)
      dsig_handle(m, signal, pkt + 2, len - 2);

  } else if(dst_addr == m->m_our_addr) {

    if(len < 3)
      return;

    const uint16_t flow = pkt[2] | ((pkt[1] << 3) & 0x300);
    const uint8_t src_addr = pkt[1] & 0x1f;
    const int init = pkt[1] & 0x80;

    if(init) {
      // Not really supported yet
    } else {
      mbus_flow_t *mf = mbus_flow_find(m, src_addr, flow);
      if(mf != NULL) {
        mf->mf_input(m, mf, pkt + 3, len - 3);
      } else {
        mbus_log(m, "No flow for %d:%d", src_addr, flow);
      }
    }
  }
}


mbus_error_t
mbus_invoke_locked(mbus_t *m, uint8_t addr,
                   const char *name, const void *req,
                   size_t req_size, void *reply,
                   size_t* reply_size,
                   const struct timespec* deadline)
{

  mbus_con_t *c;

  const size_t namelen = strlen(name);
  const size_t hdrlen = (1 + namelen + 3) & ~3;

  for(int i = 0; i < 2; i++) {
    c = m->m_rpc_channels[addr];
    if(c == NULL) {
      c = m->m_connect_locked(m, addr, "rpc");
    } else {
      m->m_rpc_channels[addr] = NULL;
    }

    uint8_t opkt[hdrlen + req_size];
    opkt[0] = namelen;
    memcpy(opkt + 1, name, namelen);
    memcpy(opkt + hdrlen, req, req_size);

    c->send_locked(c->backend, opkt, hdrlen + req_size);

    void *ipkt;
    int res = c->recv_locked(c->backend, &ipkt);
    if(res < 4) {
      c->shutdown_locked(c->backend);
      continue;
    }

    uint32_t err;
    memcpy(&err, ipkt, sizeof(err));
    if(!err) {
      size_t received_size = res - 4;
      if(reply_size && *reply_size >= res) {
        memcpy(reply, ipkt + 4, received_size);
        *reply_size = received_size;
      }
    }
    free(ipkt);
    if(m->m_rpc_channels[addr] == NULL) {
      m->m_rpc_channels[addr] = c;
    } else {
      c->shutdown_locked(c->backend);
    }

    return err;
  }

  return MBUS_ERR_OPERATION_FAILED;

}

mbus_error_t
mbus_invoke(mbus_t *m, uint8_t addr, const char *name,
            const void *req, size_t req_size, void *reply,
            size_t* reply_size, int timeout_ms)
{
  pthread_mutex_lock(&m->m_mutex);

  mbus_error_t err = mbus_invoke_locked(m, addr, name, req, req_size, reply,
                                        reply_size, NULL);
  pthread_mutex_unlock(&m->m_mutex);
  return err;
}


const char *
mbus_error_to_string(mbus_error_t err)
{
  switch (err) {
  case MBUS_ERR_OK:
    return "OK";
  case MBUS_ERR_NOT_IMPLEMENTED:
    return "NOT_IMPLEMENTED";
  case MBUS_ERR_TIMEOUT:
    return "TIMEOUT";
  case MBUS_ERR_OPERATION_FAILED:
    return "OPERATION_FAILED";
  case MBUS_ERR_TX:
    return "TX";
  case MBUS_ERR_RX:
    return "RX";
  case MBUS_ERR_NOT_READY:
    return "NOT_READY";
  case MBUS_ERR_NO_BUFFER:
    return "NO_BUFFER";
  case MBUS_ERR_MTU_EXCEEDED:
    return "MTU_EXCEEDED";
  case MBUS_ERR_INVALID_ID:
    return "INVALID_ID";
  case MBUS_ERR_DMA_ERROR:
    return "DMA_ERROR";
  case MBUS_ERR_BUS_ERROR:
    return "BUS_ERROR";
  case MBUS_ERR_ARBITRATION_LOST:
    return "ARBITRATION_LOST";
  case MBUS_ERR_BAD_STATE:
    return "BAD_STATE";
  case MBUS_ERR_INVALID_ADDRESS:
    return "INVALID_ADDRESS";
  case MBUS_ERR_NO_DEVICE:
    return "NO_DEVICE";
  case MBUS_ERR_MISMATCH:
    return "MISMATCH";
  case MBUS_ERR_NOT_FOUND:
    return "NOT_FOUND";
  case MBUS_ERR_CHECKSUM_ERROR:
    return "CHECKSUM_ERROR";
  case MBUS_ERR_MALFORMED:
    return "MALFORMED";
  case MBUS_ERR_INVALID_RPC_ID:
    return "INVALID_RPC_ID";
  case MBUS_ERR_INVALID_RPC_ARGS:
    return "INVALID_RPC_ARGS";
  case MBUS_ERR_NO_FLASH_SPACE:
    return "NO_FLASH_SPACE";
  case MBUS_ERR_INVALID_ARGS:
    return "INVALID_ARGS";
  case MBUS_ERR_INVALID_LENGTH:
    return "INVALID_LENGTH";
  case MBUS_ERR_NOT_IDLE:
    return "NOT_IDLE";
  case MBUS_ERR_BAD_CONFIG:
    return "BAD_CONFIG";
  case MBUS_ERR_FLASH_HW_ERROR:
    return "FLASH_HW_ERROR";
  case MBUS_ERR_FLASH_TIMEOUT:
    return "FLASH_TIMEOUT";
  case MBUS_ERR_NO_MEMORY:
    return "NO_MEMORY";
  case MBUS_ERR_READ_PROTECTED:
    return "READ_PROTECTED";
  case MBUS_ERR_WRITE_PROTECTED:
    return "WRITE_PROTECTED";
  case MBUS_ERR_AGAIN:
    return "AGAIN";
  case MBUS_ERR_NOT_CONNECTED:
    return "NOT_CONNECTED";
  case MBUS_ERR_BAD_PKT_SIZE:
    return "BAD_PKT_SIZE";
  }
  return "???";
}

mbus_error_t
mbus_dsig_emit_locked(mbus_t *m, uint16_t signal, const void *data,
                      size_t len)
{
  const size_t pktlen = 2 + len;

  uint8_t pkt[pktlen];
  pkt[0] = 0x20 | (signal >> 8);
  pkt[1] = signal;
  memcpy(pkt + 2, data, len);
  return m->m_send(m, pkt, pktlen, NULL);
}


mbus_error_t
mbus_dsig_emit(mbus_t *m, uint16_t signal, const void *data,
               size_t len)
{
  pthread_mutex_lock(&m->m_mutex);
  mbus_error_t err = mbus_dsig_emit_locked(m, signal, data, len);
  pthread_mutex_unlock(&m->m_mutex);
  return err;
}



struct mbus_dsig_driver {
  LIST_ENTRY(mbus_dsig_driver) mdd_link;
  uint16_t mdd_signal;
  void *mdd_data;
  size_t mdd_length;
  int64_t mdd_period;
  mbus_timer_t mdd_timer;
};


struct mbus_dsig_sub {
  LIST_ENTRY(mbus_dsig_sub) mds_link;
  uint16_t mds_signal;
  void (*mds_cb)(void *opaque, const uint8_t *data, size_t len);
  void *mds_opaque;
  mbus_timer_t mds_timer;
  int64_t mds_ttl;
};


static void *
timer_thread(void *aux)
{
  mbus_t *m = aux;

  pthread_mutex_lock(&m->m_mutex);

  while(1) {
    mbus_timer_t *mt = LIST_FIRST(&m->m_timers);
    if(mt == NULL) {
      pthread_cond_wait(&m->m_timer_cond, &m->m_mutex);
      continue;
    }

    int64_t now = mbus_get_ts();

    if(mt->mt_expire > now) {
      int64_t next_wakeup = mt->mt_expire;
      struct timespec ts = {.tv_sec = next_wakeup / 1000000LL,
                            .tv_nsec = (next_wakeup % 1000000LL) * 1000};
      pthread_cond_timedwait(&m->m_timer_cond, &m->m_mutex, &ts);
      continue;
    }

    LIST_REMOVE(mt, mt_link);
    mt->mt_expire = 0;
    mt->mt_cb(m, mt->mt_opaque, now);
  }
  return NULL;
}

static int
timer_cmp(const mbus_timer_t *a, const mbus_timer_t *b)
{
  return a->mt_expire > b->mt_expire;
}

void
mbus_timer_disarm(mbus_timer_t *mt)
{
  if(mt->mt_expire) {
    LIST_REMOVE(mt, mt_link);
    mt->mt_expire = 0;
  }
}

#define LIST_INSERT_SORTED(head, elm, field, cmpfunc) do {	\
        if(LIST_EMPTY(head)) {					\
           LIST_INSERT_HEAD(head, elm, field);			\
        } else {						\
           typeof(elm) _tmp;					\
           LIST_FOREACH(_tmp,head,field) {			\
              if(cmpfunc(elm,_tmp) <= 0) {			\
                LIST_INSERT_BEFORE(_tmp,elm,field);		\
                break;						\
              }							\
              if(!LIST_NEXT(_tmp,field)) {			\
                 LIST_INSERT_AFTER(_tmp,elm,field);		\
                 break;						\
              }							\
           }							\
        }							\
} while(0)

void
mbus_timer_arm(mbus_t *m, mbus_timer_t *mt, int64_t expire)
{
  mbus_timer_disarm(mt);
  mt->mt_expire = expire;
  LIST_INSERT_SORTED(&m->m_timers, mt, mt_link, timer_cmp);
  if(mt == LIST_FIRST(&m->m_timers))
    pthread_cond_signal(&m->m_timer_cond);
}




static void
dsig_drive_cb(mbus_t *m, void *opaque, int64_t expire)
{
  mbus_dsig_driver_t *mdd = opaque;

  mbus_dsig_emit_locked(m, mdd->mdd_signal, mdd->mdd_data, mdd->mdd_length);
  if(mdd->mdd_data)
    mbus_timer_arm(m, &mdd->mdd_timer, mbus_get_ts() + mdd->mdd_period);
}


mbus_dsig_driver_t *
mbus_dsig_drive(mbus_t *m, uint16_t signal, int period_ms)
{
  mbus_dsig_driver_t *mdd = calloc(1, sizeof(mbus_dsig_driver_t));
  mdd->mdd_signal = signal;
  mdd->mdd_period = period_ms * 1000;
  mdd->mdd_data = NULL;
  mdd->mdd_length = 0;
  mdd->mdd_timer.mt_cb = dsig_drive_cb;
  mdd->mdd_timer.mt_opaque = mdd;
  pthread_mutex_lock(&m->m_mutex);
  LIST_INSERT_HEAD(&m->m_dsig_drivers, mdd, mdd_link);
  pthread_mutex_unlock(&m->m_mutex);
  return mdd;
}


void
mbus_dsig_set(mbus_t *m,
              mbus_dsig_driver_t *mdd,
              const void *data, size_t len)
{
  pthread_mutex_lock(&m->m_mutex);

  if(mdd->mdd_data == NULL ||
     len != mdd->mdd_length ||
     memcmp(mdd->mdd_data, data, len)) {

    free(mdd->mdd_data);
    mdd->mdd_data = malloc(len);
    mdd->mdd_length = len;
    memcpy(mdd->mdd_data, data, len);

    mbus_timer_arm(m, &mdd->mdd_timer, mbus_get_ts());
  }
  pthread_mutex_unlock(&m->m_mutex);
}


void
mbus_dsig_clear(mbus_t *m, mbus_dsig_driver_t *mdd)
{
  pthread_mutex_lock(&m->m_mutex);
  if(mdd->mdd_length) {
    free(mdd->mdd_data);
    mdd->mdd_data = NULL;
    mdd->mdd_length = 0;
    mbus_timer_arm(m, &mdd->mdd_timer, mbus_get_ts());
   }
  pthread_mutex_unlock(&m->m_mutex);
}


static void
dsig_sub_cb(mbus_t *m, void *opaque, int64_t expire)
{
  mbus_dsig_sub_t *mds = opaque;
  mds->mds_cb(mds->mds_opaque, NULL, 0);
}


mbus_dsig_sub_t *
mbus_dsig_sub(mbus_t *m,
              uint16_t signal,
              void (*cb)(void *opaque, const uint8_t *data, size_t len),
              void *opaque,
              int ttl_ms)

{
  mbus_dsig_sub_t *mds = calloc(1, sizeof(mbus_dsig_sub_t));
  mds->mds_signal = signal;
  mds->mds_cb = cb;
  mds->mds_opaque = opaque;
  mds->mds_ttl = ttl_ms * 1000;
  mds->mds_timer.mt_cb = dsig_sub_cb;
  mds->mds_timer.mt_opaque = mds;

  pthread_mutex_lock(&m->m_mutex);
  LIST_INSERT_HEAD(&m->m_dsig_subs, mds, mds_link);
  int64_t now = mbus_get_ts();
  mbus_timer_arm(m, &mds->mds_timer, now + mds->mds_ttl);
  pthread_mutex_unlock(&m->m_mutex);
  return mds;
}



static void
dsig_handle(mbus_t *m, uint16_t signal, const uint8_t *pkt, size_t len)
{
  mbus_dsig_sub_t *mds;
  if(len < 2)
    return;

  int64_t now = mbus_get_ts();

  LIST_FOREACH(mds, &m->m_dsig_subs, mds_link) {
    if(mds->mds_signal != signal)
      continue;

    mds->mds_cb(mds->mds_opaque, pkt, len);

    mbus_timer_arm(m, &mds->mds_timer, now + mds->mds_ttl);
  }
}



static mbus_error_t
dummy_send(mbus_t *m, const void *data,
           size_t len, const struct timespec *deadline)
{
  return 0;
}


typedef struct mbus_ping {
  mbus_flow_t mp_flow;
  int mp_got_reply;
  pthread_cond_t mp_cond;
} mbus_ping_t;



static void
mbus_pong(mbus_t *m, mbus_flow_t *mf,
          const uint8_t *pkt, size_t len)
{
  mbus_ping_t *mp = (mbus_ping_t *)mf;
  mp->mp_got_reply = 1;
  pthread_cond_signal(&mp->mp_cond);
}



static mbus_error_t
mbus_ping_one(mbus_t *m, uint8_t remote_addr)
{
  mbus_ping_t mp = {};

  mp.mp_flow.mf_remote_addr = remote_addr;
  mp.mp_flow.mf_input = mbus_pong;

  pthread_condattr_t attr;
  pthread_condattr_init(&attr);
#ifdef __linux__
  pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
  pthread_cond_init(&mp.mp_cond, &attr);
  pthread_condattr_destroy(&attr);

  mbus_flow_create(m, &mp.mp_flow);

  uint8_t pkt[4];
  mbus_flow_write_header(pkt, m, &mp.mp_flow, 1);
  pkt[3] = 0; // MBUS_PING;

  struct timespec deadline = mbus_deadline_from_timeout(1000);
  m->m_send(m, pkt, sizeof(pkt), &deadline);

  struct timespec ts = mbus_deadline_from_timeout(500);

  mbus_error_t err = 0;

  while(!mp.mp_got_reply) {
    if(pthread_cond_timedwait(&mp.mp_cond, &m->m_mutex, &ts) == ETIMEDOUT) {
      err = MBUS_ERR_TIMEOUT;
      break;
    }
  }
  mbus_flow_remove(&mp.mp_flow);
  return err;
}


mbus_error_t
mbus_ping(mbus_t *m, uint8_t remote_addr)
{
  pthread_mutex_lock(&m->m_mutex);
  mbus_error_t err = mbus_ping_one(m, remote_addr);
  pthread_mutex_unlock(&m->m_mutex);
  return err;
}


static mbus_t *
mbus_create_dummy(void)
{
  mbus_t *m = calloc(1, sizeof(mbus_t));
  m->m_send =  dummy_send;
  mbus_init_common(m, NULL, NULL);
  return m;
}


mbus_flow_t *
mbus_flow_find(mbus_t *m, uint8_t remote_addr, uint16_t flow)
{
  mbus_flow_t *mf;
  LIST_FOREACH(mf, &m->m_flows, mf_link) {
    if(mf->mf_remote_addr == remote_addr && mf->mf_flow == flow)
      return mf;
  }
  return NULL;
}

void
mbus_flow_create(mbus_t *m, mbus_flow_t *mf)
{
  for(int i = 0; i < 1024; i++) {
    const uint16_t flow_id = rand() & 0x3ff;

    if(mbus_flow_find(m, mf->mf_remote_addr, flow_id) == NULL) {
      // Available
      mf->mf_flow = flow_id;
      LIST_INSERT_HEAD(&m->m_flows, mf, mf_link);
      return;
    }
  }
  fprintf(stderr, "No flow-id available\n");
  abort();
}


void
mbus_flow_remove(mbus_flow_t *mf)
{
  LIST_REMOVE(mf, mf_link);
}


void
mbus_flow_write_header(uint8_t pkt[3],
                       const mbus_t *m, const mbus_flow_t *mf, int init)
{
  pkt[0] = mf->mf_remote_addr;
  pkt[1] = (init ? 0x80 : 0) | ((mf->mf_flow >> 3) & 0x60) | m->m_our_addr;
  pkt[2] = mf->mf_flow;
}



mbus_con_t *
mbus_connect(mbus_t *m, uint8_t remote_addr, const char *service)
{
  pthread_mutex_lock(&m->m_mutex);
  mbus_con_t *mc = m->m_connect_locked(m, remote_addr, service);
  pthread_mutex_unlock(&m->m_mutex);
  return mc;
}

mbus_error_t
mbus_send(mbus_con_t *c, const void *data, size_t len)
{
  mbus_t *m = c->m;
  pthread_mutex_lock(&m->m_mutex);
  mbus_error_t err = c->send_locked(c->backend, data, len);
  pthread_mutex_unlock(&m->m_mutex);
  return err;

}

int
mbus_recv(mbus_con_t *c, void **ptr)
{
  mbus_t *m = c->m;
  pthread_mutex_lock(&m->m_mutex);
  int r = c->recv_locked(c->backend, ptr);
  pthread_mutex_unlock(&m->m_mutex);
  return r;
}


void
mbus_shutdown(mbus_con_t *c)
{
  mbus_t *m = c->m;
  pthread_mutex_lock(&m->m_mutex);
  c->shutdown_locked(c->backend);
  pthread_mutex_unlock(&m->m_mutex);
}

void
mbus_close(mbus_con_t *c, int wait)
{
  mbus_t *m = c->m;
  pthread_mutex_lock(&m->m_mutex);
  c->close_locked(c->backend, wait);
  pthread_mutex_unlock(&m->m_mutex);
}
