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
  const size_t slen = strlen(str0) + 1;
  char *str = alloca(slen);
  strcpy(str, str0);

  char *argv[10];
  int argc = str_tokenize(str, argv, 10, ':');

  if(argc == 3 && !strcmp(argv[0], "tcp")) {
    return mbus_create_tcp(argv[1], // Hostname
                           atoi(argv[2]), // Port
                           local_addr, log_cb, aux);
  } else if(argc >= 2 && !strcmp(argv[0], "serial")) {
    return mbus_create_serial(argv[1], // Device
                              argc > 2 ? atoi(argv[2]) : 230400, // Baudrate
                              local_addr,
                              argc > 3 ? !strcmp(argv[3], "fd") : 0,
                              log_cb, aux);
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

static void dsig_handle(mbus_t *m, const uint8_t *pkt, size_t len,
                        uint8_t src_addr);

static void mbus_ota_xfer(mbus_t *m, const uint8_t *pkt, size_t len,
                          uint8_t src_addr);


pcs_iface_t *
mbus_get_pcs_iface(mbus_t *m)
{
  return m->m_pcs;
}




static int64_t
pcs_thread_wait_helper(pthread_cond_t *c,
                       pthread_mutex_t *m,
                       int64_t deadline)
{
  struct timespec ts = usec_to_timespec(deadline);
  pthread_cond_timedwait(c, m, &ts);
  return mbus_get_ts();
}


static void *
pcs_thread(void *arg)
{
  mbus_t *m = arg;
  uint8_t txbuf[64];


  while(1) {
    pcs_poll_result_t ppr = pcs_wait(m->m_pcs, txbuf, sizeof(txbuf),
                                     mbus_get_ts(), pcs_thread_wait_helper);

    pthread_mutex_lock(&m->m_mutex);
    m->m_send(m, ppr.addr, txbuf, ppr.len, NULL);
    pthread_mutex_unlock(&m->m_mutex);
  }
  return NULL;
}


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

  pthread_mutex_init(&m->m_mutex, NULL);

  pthread_condattr_t attr;
  pthread_condattr_init(&attr);
#ifdef __linux__
  pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
  pthread_cond_init(&m->m_dsig_driver_cond, &attr);
  pthread_condattr_destroy(&attr);

  pthread_create(&m->m_timer_thread, NULL, timer_thread, m);

  m->m_pcs = pcs_iface_create(m, 64, NULL);

  pthread_create(&m->m_pcs_thread, NULL, pcs_thread, m);

}

void
mbus_destroy(mbus_t *m)
{
  m->m_destroy(m);
}


mbus_rpc_t *
mbus_get_pending(mbus_t *m, const uint8_t* pkt, size_t len,
                 uint8_t addr)
{
  if(len < 1)
    return NULL;

  uint8_t txid = pkt[0];

  mbus_rpc_t* mr;
  LIST_FOREACH(mr, &m->m_rpcs, mr_link) {
    if(mr->mr_txid == txid && mr->mr_remote_addr == addr)
      return mr;
  }
  return NULL;
}


static void
mr_completed(mbus_rpc_t* mr)
{
  mr->mr_completed = 1;
  pthread_cond_signal(&mr->mr_cond);
}


void
mbus_cancel_rpc(mbus_t *m)
{
  mbus_rpc_t* mr;
  LIST_FOREACH(mr, &m->m_rpcs, mr_link) {
    mr->mr_error = MBUS_ERR_TIMEOUT;
    mr_completed(mr);
  }
}


void
mbus_pkt_trace(const mbus_t *m, const char *prefix,
               const uint8_t *pkt, size_t len)
{
  if(!m->m_debug_level)
    return;

  const uint8_t src_addr = (pkt[0] >> 4) & 0x0f;
  const uint8_t dst_addr = pkt[0] & 0x0f;

  if(m->m_debug_level >= 2) {

    if(pkt[1] & 0x80 && len >= 8) {
      mbus_log(m,
               "%s: 0x%x -> 0x%x PCS: CH:0x%02x %c%c%c%c%c%c F:0x%02x ACK:0x%04x SEQ:0x%04x %d",
               prefix,
               src_addr, dst_addr,
               pkt[1],
               pkt[2] & 0x1  ? 'S' : ' ',
               pkt[2] & 0x2  ? '2' : ' ',
               pkt[2] & 0x4  ? 'E' : ' ',
               pkt[2] & 0x8  ? 'L' : ' ',
               pkt[2] & 0x10 ? 'P' : ' ',
               pkt[2] & 0x20 ? 'I' : ' ',
               pkt[3],
               pkt[5] | (pkt[4] << 8),
               pkt[7] | (pkt[6] << 8),
               len - 8);
    } else {
      mbus_log(m, "%s: 0x%x -> 0x%x", prefix, src_addr, dst_addr);
    }
    if(m->m_debug_level >= 3) {
      mbus_hexdump(m, prefix, pkt, len);
    }
  }
}


void
mbus_rx_handle_pkt(mbus_t *m, const uint8_t *pkt, size_t len, int check_crc)
{
  if(check_crc) {
    if(len < 4 || ~mbus_crc32(0, pkt, len)) {
      mbus_pkt_trace(m, "RX.CRC", pkt, len);
      return;
    }
    len -= 4;
  }

  if(len < 2) {
    return;
  }

  mbus_pkt_trace(m, "RX", pkt, len);

  const uint8_t src_addr = (pkt[0] >> 4) & 0x0f;
  const uint8_t dst_addr = pkt[0] & 0x0f;

  m->host_active[src_addr] = 2;

  if(dst_addr != m->m_our_addr && dst_addr != 7)
    return;

  if(m->m_gateway && mbus_gateway_intercept(m, pkt, len)) {
    return;
  }

  if(pkt[1] & 0x80 && dst_addr == m->m_our_addr) {
    // PCS
    pcs_input(m->m_pcs, pkt + 1, len - 1, mbus_get_ts(), src_addr);
    return;
  }

  uint8_t opcode = pkt[1] & 0x0f;

  /* Remove header */;
  pkt += 2;
  len -= 2;

  mbus_rpc_t* mr;

  switch (opcode) {

  case MBUS_OP_RPC_RESOLVE_REPLY:
    mr = mbus_get_pending(m, pkt, len, src_addr);
    if(mr == NULL)
      return;
    pkt++;
    len--;

    if(len == 0) {
      mr->mr_error = MBUS_ERR_NOT_FOUND;
    } else if(len != sizeof(uint32_t)) {
      mr->mr_error = MBUS_ERR_MALFORMED;
    } else {
      memcpy(mr->mr_reply, pkt, sizeof(uint32_t));
      mr->mr_reply_len = sizeof(uint32_t);
      mr->mr_error = 0;
    }
    mr_completed(mr);
    break;

  case MBUS_OP_RPC_REPLY:
    mr = mbus_get_pending(m, pkt, len, src_addr);
    if(mr == NULL)
      return;
    pkt++;
    len--;

    if(len > sizeof(mr->mr_reply)) {
      mr->mr_error = MBUS_ERR_MTU_EXCEEDED;
    } else {
      memcpy(mr->mr_reply, pkt, len);
      mr->mr_reply_len = len;
      mr->mr_error = 0;
    }
    mr_completed(mr);
    break;

  case MBUS_OP_RPC_ERR:
    mr = mbus_get_pending(m, pkt, len, src_addr);
    if(mr == NULL)
      return;
    pkt++;
    len--;

    if(len == sizeof(uint32_t)) {
      memcpy(&mr->mr_error, pkt, sizeof(uint32_t));
    } else {
      mr->mr_error = MBUS_ERR_MALFORMED;
    }
    mr_completed(mr);
    break;

  case MBUS_OP_DSIG_EMIT:
    dsig_handle(m, pkt, len, src_addr);
    break;

  case MBUS_OP_OTA_XFER:
    mbus_ota_xfer(m, pkt, len, src_addr);
    break;

  default:
    break;
  }
}


static void
mbus_rpc_init(mbus_rpc_t* mr, mbus_t *m, uint8_t addr)
{
  memset(mr, 0, sizeof(mbus_rpc_t));

  pthread_condattr_t attr;
  pthread_condattr_init(&attr);
#ifdef __linux__
  pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
  pthread_cond_init(&mr->mr_cond, &attr);
  pthread_condattr_destroy(&attr);

  mr->mr_txid = ++m->m_txid_gen[addr & 0xf];
  mr->mr_remote_addr = addr;
}


static void
mbus_rpc_wait(mbus_rpc_t* mr, mbus_t *m,
              const struct timespec* deadline)
{
  LIST_INSERT_HEAD(&m->m_rpcs, mr, mr_link);
  while (!mr->mr_completed) {
    if(pthread_cond_timedwait(&mr->mr_cond, &m->m_mutex, deadline) ==
       ETIMEDOUT) {
      mr->mr_error = MBUS_ERR_TIMEOUT;
      break;
    }
  }
  LIST_REMOVE(mr, mr_link);
}


static mbus_error_t
mbus_resolve_id(mbus_t *m, uint8_t addr, const char *name,
                uint32_t* idp,
                const struct timespec* deadline,
                int overwrite)
{
  mbus_method_t *mm;
  LIST_FOREACH(mm, &m->m_methods, mm_link) {
    if(mm->mm_addr == addr && !strcmp(mm->mm_name, name)) {
      if(overwrite)
        break;
      *idp = mm->mm_id;
      return 0;
    }
  }

  mbus_rpc_t mr;
  mbus_rpc_init(&mr, m, addr);

  const size_t namelen = strlen(name);
  const size_t reqlen = 1 + 1 + namelen;
  uint8_t req[reqlen];
  req[0] = MBUS_OP_RPC_RESOLVE;
  req[1] = mr.mr_txid;
  memcpy(req + 2, name, namelen);
  mbus_error_t err = m->m_send(m, addr, req, reqlen, deadline);
  if(err)
    return err;

  mbus_rpc_wait(&mr, m, deadline);

  if(mr.mr_error)
    return mr.mr_error;

  memcpy(idp, mr.mr_reply, sizeof(uint32_t));

  if(mm == NULL) {
    mm = malloc(sizeof(mbus_method_t) + namelen + 1);
    LIST_INSERT_HEAD(&m->m_methods, mm, mm_link);
    strcpy(mm->mm_name, name);
    mm->mm_addr = addr;
  }
  mm->mm_id = *idp;
  return 0;
}


static mbus_error_t
mbus_invoke_id(mbus_t *m, uint8_t addr, uint32_t method_id,
               const void *req, size_t req_size,
               void *reply, size_t* reply_size,
               const struct timespec* deadline)
{
  mbus_rpc_t mr;
  mbus_rpc_init(&mr, m, addr);

  const size_t pktlen = 1 + 1 + 4 + req_size;
  uint8_t pkt[pktlen];
  pkt[0] = MBUS_OP_RPC_INVOKE;
  pkt[1] = mr.mr_txid;
  memcpy(pkt + 2, &method_id, sizeof(uint32_t));
  memcpy(pkt + 6, req, req_size);
  mbus_error_t err = m->m_send(m, addr, pkt, pktlen, deadline);
  if(err)
    return err;

  mbus_rpc_wait(&mr, m, deadline);

  if(mr.mr_error)
    return mr.mr_error;

  if(reply && reply_size) {
    if(*reply_size >= mr.mr_reply_len) {
      *reply_size = mr.mr_reply_len;
      memcpy(reply, mr.mr_reply, mr.mr_reply_len);
    } else {
      return MBUS_ERR_NO_BUFFER;
    }
  }
  return 0;
}


mbus_error_t
mbus_invoke_locked(mbus_t *m, uint8_t addr,
                   const char *name, const void *req,
                   size_t req_size, void *reply,
                   size_t* reply_size,
                   const struct timespec* deadline)
{
  uint32_t method_id;

  for(int i = 0; i < 2; i++) {
    mbus_error_t err = mbus_resolve_id(m, addr, name, &method_id, deadline,
                                       i == 1);
    if(err)
      return err;

    err = mbus_invoke_id(m, addr, method_id, req, req_size, reply, reply_size,
                         deadline);
    if(err == MBUS_ERR_INVALID_RPC_ID)
      continue;
    return err;
  }
  return MBUS_ERR_INVALID_RPC_ID;
}




mbus_error_t
mbus_invoke(mbus_t *m, uint8_t addr, const char *name,
            const void *req, size_t req_size, void *reply,
            size_t* reply_size, int timeout_ms)
{
  struct timespec deadline = mbus_deadline_from_timeout(timeout_ms);
  pthread_mutex_lock(&m->m_mutex);
  mbus_error_t err = mbus_invoke_locked(m, addr, name, req, req_size, reply,
                                        reply_size, &deadline);
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

  }
  return "???";
}

mbus_error_t
mbus_dsig_emit_locked(mbus_t *m, uint8_t signal, const void *data,
                      size_t len, uint8_t ttl)
{
  const size_t reqlen = 3 + len;

  uint8_t req[reqlen];
  req[0] = MBUS_OP_DSIG_EMIT;
  req[1] = signal;
  req[2] = ttl;
  memcpy(req + 3, data, len);
  return m->m_send(m, 0x7, req, reqlen, NULL);
}


mbus_error_t
mbus_dsig_emit(mbus_t *m, uint8_t signal, const void *data,
               size_t len, uint8_t ttl)
{
  pthread_mutex_lock(&m->m_mutex);
  mbus_error_t err = mbus_dsig_emit_locked(m, signal, data, len, ttl);
  pthread_mutex_unlock(&m->m_mutex);
  return err;
}



struct mbus_dsig_driver {
  LIST_ENTRY(mbus_dsig_driver) mdd_link;
  uint8_t mdd_signal;
  void *mdd_data;
  size_t mdd_length;
  uint8_t mdd_ttl;
  int64_t mdd_next_emit;
};


struct mbus_dsig_sub {
  LIST_ENTRY(mbus_dsig_sub) mds_link;
  uint8_t mds_signal;
  uint8_t mds_src;
  void (*mds_cb)(void *opaque, const uint8_t *data, size_t len);
  void *mds_opaque;
  int64_t mds_expire;
};


static void *
timer_thread(void *aux)
{
  mbus_t *m = aux;
  mbus_dsig_driver_t *mdd;
  mbus_dsig_sub_t *mds;
  pthread_mutex_lock(&m->m_mutex);

  while(1) {
    int64_t now = mbus_get_ts();
    int64_t next_wakeup = now + 1000000;

    if(now >= m->next_host_active_clear) {
      m->next_host_active_clear = now + 1000000;
      for(int i = 0; i < sizeof(m->host_active); i++) {
        if(m->host_active[i])
          m->host_active[i]--;
      }
    }

    LIST_FOREACH(mdd, &m->m_dsig_drivers, mdd_link) {
      if(mdd->mdd_next_emit == 0)
        continue;
      if(mdd->mdd_next_emit <= now) {
        mbus_dsig_emit_locked(m, mdd->mdd_signal,
                              mdd->mdd_data, mdd->mdd_length, mdd->mdd_ttl);

        // Local echo
        LIST_FOREACH(mds, &m->m_dsig_subs, mds_link) {
          if(mds->mds_signal == mdd->mdd_signal &&
             m->m_our_addr >= mds->mds_src) {
            mds->mds_src = m->m_our_addr;
            mds->mds_cb(mds->mds_opaque, mdd->mdd_data, mdd->mdd_length);
            mds->mds_expire = now + mdd->mdd_ttl * 100000;
          }
        }

        if(mdd->mdd_length) {
          mdd->mdd_next_emit = now + (1 + mdd->mdd_ttl) * 30000;
        } else {
          mdd->mdd_next_emit = 0;
          continue;
        }
      }
      next_wakeup = MIN(mdd->mdd_next_emit + 5000, next_wakeup);
    }

    LIST_FOREACH(mds, &m->m_dsig_subs, mds_link) {
      if(mds->mds_expire <= now) {
        mds->mds_src = 0;
        mds->mds_cb(mds->mds_opaque, NULL, 0);
        mds->mds_expire = INT64_MAX;
      } else if(mds->mds_expire != INT64_MAX) {
        next_wakeup = MIN(mds->mds_expire + 1000, next_wakeup);
      }
    }

    if(next_wakeup == INT64_MAX) {
      pthread_cond_wait(&m->m_dsig_driver_cond, &m->m_mutex);
    } else {
      struct timespec ts = {.tv_sec = next_wakeup / 1000000LL,
                            .tv_nsec = (next_wakeup % 1000000LL) * 1000};
      pthread_cond_timedwait(&m->m_dsig_driver_cond, &m->m_mutex, &ts);
    }
  }
  pthread_mutex_unlock(&m->m_mutex);
  return NULL;
}


mbus_dsig_driver_t *
mbus_dsig_drive(mbus_t *m, uint8_t signal, uint8_t ttl)
{
  mbus_dsig_driver_t *mdd = calloc(1, sizeof(mbus_dsig_driver_t));
  mdd->mdd_signal = signal;
  mdd->mdd_next_emit = 0;
  mdd->mdd_ttl = ttl;
  mdd->mdd_data = NULL;
  mdd->mdd_length = 0;
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
    mdd->mdd_next_emit = 1;
    memcpy(mdd->mdd_data, data, len);
    pthread_cond_signal(&m->m_dsig_driver_cond);
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
    mdd->mdd_next_emit = 1;
    pthread_cond_signal(&m->m_dsig_driver_cond);
  }
  pthread_mutex_unlock(&m->m_mutex);
}


mbus_dsig_sub_t *
mbus_dsig_sub(mbus_t *m,
              uint8_t signal,
              void (*cb)(void *opaque, const uint8_t *data, size_t len),
              void *opaque)
{
  mbus_dsig_sub_t *mds = calloc(1, sizeof(mbus_dsig_sub_t));
  mds->mds_signal = signal;
  mds->mds_cb = cb;
  mds->mds_opaque = opaque;
  mds->mds_expire = INT64_MAX;
  pthread_mutex_lock(&m->m_mutex);
  LIST_INSERT_HEAD(&m->m_dsig_subs, mds, mds_link);
  pthread_mutex_unlock(&m->m_mutex);
  return mds;
}


static void
dsig_handle(mbus_t *m, const uint8_t *pkt, size_t len, uint8_t remote_addr)
{
  mbus_dsig_sub_t *mds;
  if(len < 2)
    return;

  uint8_t signal = pkt[0];
  uint8_t ttl = pkt[1];

  pkt += 2;
  len -= 2;

  int64_t now = mbus_get_ts();

  LIST_FOREACH(mds, &m->m_dsig_subs, mds_link) {
    if(mds->mds_signal != signal)
      continue;

    if(remote_addr >= mds->mds_src) {
      mds->mds_src = remote_addr;
      mds->mds_cb(mds->mds_opaque, pkt, len);
      mds->mds_expire = now + ttl * 100000;
      pthread_cond_signal(&m->m_dsig_driver_cond);
    }
  }
}


static void
mbus_ota_xfer(mbus_t *m, const uint8_t *pkt, size_t len, uint8_t src_addr)
{
  if(m->m_ota_image == NULL)
    return;

  const uint32_t block = pkt[0] | (pkt[1] << 8) | (pkt[2] << 16);
  if(block == 0xffffff) {
    // Done
    m->m_ota_xfer_error = len > 3 ? -((mbus_error_t)pkt[3]) : 0;
    m->m_ota_completed = 1;
    pthread_cond_signal(&m->m_ota_cond);
    return;
  }

  uint8_t out[4 + 16];
  out[0] = MBUS_OP_OTA_XFER;
  out[1] = block;
  out[2] = block >> 8;
  out[3] = block >> 16;

  memcpy(out + 4, m->m_ota_image + block * 16, 16);

  m->m_send(m, src_addr, out, sizeof(out), NULL);
}


static mbus_error_t
dummy_send(mbus_t *m, uint8_t addr, const void *data,
           size_t len, const struct timespec *deadline)
{
  return 0;
}


static mbus_t *
mbus_create_dummy(void)
{
  mbus_t *m = calloc(1, sizeof(mbus_t));
  m->m_send =  dummy_send;
  mbus_init_common(m, NULL, NULL);
  return m;
}


uint16_t
mbus_get_active_hosts(mbus_t *m)
{
  uint16_t r = 0;
  for(int i = 0; i < sizeof(m->host_active); i++) {
    if(m->host_active[i])
      r |= (1 << i);
  }
  return r;
}
