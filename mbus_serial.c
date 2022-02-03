#define _GNU_SOURCE

#include "mbus.h"
#include "mbus_i.h"

#include <sys/ioctl.h>

#include <unistd.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <termios.h>

//#include <linux/serial.h>

static void __attribute__((unused))
hexdump(const char *pfx, const void* data_, int len)
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
    printf("%s: %s\n", pfx, buf);
  }
}



TAILQ_HEAD(mbus_packet_queue, mbus_packet);

typedef struct {
  mbus_t m;
  pthread_t ms_tid;
  int ms_fd;

  struct termios ms_tio;

  int ms_pipe[2];

  int ms_state;
  struct mbus_packet_queue ms_mpq;
  pthread_mutex_t ms_mpq_mutex;

  uint8_t ms_sync;
  uint8_t ms_rxlen;
  uint8_t ms_rxbuf[256];

} mbus_serial_t;



typedef struct mbus_packet {
  TAILQ_ENTRY(mbus_packet) mp_link;
  size_t mp_size;
  uint8_t mp_data[0];
} mbus_packet_t;

#define MBUS_STATE_IDLE     0
#define MBUS_STATE_TX       1
#define MBUS_STATE_RX       2


static void
set_nonblocking(int fd, int on)
{
  int flags = fcntl(fd, F_GETFL);
  if(on) {
    flags |= O_NONBLOCK;
  } else {
    flags &= ~O_NONBLOCK;
  }
  fcntl(fd, F_SETFL, flags);
}


int
setupdev(mbus_serial_t *ms, int baudrate)
{
  int bflags = 0;
  switch(baudrate) {
  case 2400:
    bflags |= B2400;
    break;
  case 9600:
    bflags |= B9600;
    break;
  case 19200:
    bflags |= B19200;
    break;
  case 38400:
    bflags |= B38400;
    break;
  case 57600:
    bflags |= B57600;
    break;
  case 115200:
    bflags |= B115200;
    break;
  case 230400:
    bflags |= B230400;
    break;
#ifdef B921600
  case 921600:
    bflags |= B921600;
    break;
#endif
  default:
    fprintf(stderr, "Baudrate %d not supported\n", baudrate);
    return -1;
  }

  if(tcgetattr(ms->ms_fd, &ms->ms_tio)) {
    perror("tcgetattr");
    exit(1);
  }

  cfsetospeed(&ms->ms_tio, bflags);
  cfsetispeed(&ms->ms_tio, bflags);

  ms->ms_tio.c_cflag &= ~(PARENB | CSTOPB | CSIZE);
  ms->ms_tio.c_iflag |= CS8;
  ms->ms_tio.c_iflag |= CRTSCTS;
  ms->ms_tio.c_iflag |= CLOCAL | CREAD;
  ms->ms_tio.c_cc[VMIN] = 0;
  ms->ms_tio.c_cc[VTIME] = 0;

  cfmakeraw(&ms->ms_tio);

  if(tcsetattr(ms->ms_fd, TCSANOW, &ms->ms_tio)) {
    perror("tcsetattr");
    return -1;
  }

#if 0
  struct serial_struct serial;
  if(ioctl(ms->ms_fd, TIOCGSERIAL, &serial)) {
    perror("TIOCGSERIAL");
    return -1;
  }
  serial.flags |= ASYNC_LOW_LATENCY;
  if(ioctl(ms->ms_fd, TIOCSSERIAL, &serial)) {
    perror("TIOCSSERIAL");
    return -1;
  }
#endif

  set_nonblocking(ms->ms_fd, 1);
  return 0;
}

static void
wakeup(mbus_serial_t *ms, char code)
{
  if(write(ms->ms_pipe[1], &code, 1)) {}
}

static int __attribute__((unused))
get_delta_time(void)
{
  int r = 0;
  int64_t now = mbus_get_ts();
  static int64_t prev;
  if(prev == 0)
    r = 0;
  else
    r = now - prev;
  prev = now;
  return r;
}



static void
mbus_set_state(mbus_serial_t *ms, int state, const char *reason)
{
  ms->ms_state = state;
#if 0
  printf("%-10d: %-5s %s\n",
         get_delta_time(),
         state == MBUS_STATE_IDLE ? "IDLE" :
         state == MBUS_STATE_TX   ? "TX" :
         state == MBUS_STATE_GAP  ? "GAP" :
         state == MBUS_STATE_RX   ? "RX" : "???",
         reason);
#endif
}


static mbus_packet_t *
encode_packet(const uint8_t *data, size_t len, const mbus_t *m, uint8_t addr)
{
  uint8_t buf[1 + len + 4];
  buf[0] = (m->m_our_addr << 4) | addr;
  memcpy(buf + 1, data, len);
  uint32_t crc = ~mbus_crc32(0, buf, 1 + len);
  memcpy(buf + 1 + len, &crc, 4);

  data = buf;
  len += 1 + 4;

  size_t plen = 2;
  for(size_t i = 0; i < len; i++) {
    plen += 1 + (data[i] == 0x7e || data[i] == 0x7d);
  }

  mbus_packet_t *mp = malloc(sizeof(mbus_packet_t) + plen);
  mp->mp_size = plen;

  uint8_t *out = mp->mp_data;
  size_t op = 0;

  out[op++] = 0x7e;
  for(size_t i = 0; i < len; i++) {
    uint8_t d = data[i];
    if(d == 0x7e || d == 0x7d) {
      out[op++] = 0x7d;
      out[op++] = d ^ 0x20;
    } else {
      out[op++] = d;
    }
  }
  out[op++] = 0x7e;
  return mp;
}


static mbus_error_t
mbus_serial_send_hd(mbus_t *m, uint8_t addr, const void *data,
                    size_t len, const struct timespec *deadline)
{
  mbus_packet_t *mp = encode_packet(data, len, m, addr);

  mbus_serial_t *ms = (mbus_serial_t *)m;
  pthread_mutex_lock(&ms->ms_mpq_mutex);
  TAILQ_INSERT_TAIL(&ms->ms_mpq, mp, mp_link);
  pthread_mutex_unlock(&ms->ms_mpq_mutex);
  wakeup(ms, 't');
  return 0;
}


static void
mbus_serial_destroy(mbus_t *m)
{
  abort();
}



int
mbus_bus_idle(mbus_serial_t *ms)
{
  struct pollfd pfd[2];

  pfd[0].fd = ms->ms_fd;
  pfd[0].events = POLLIN;
  pfd[1].fd = ms->ms_pipe[0];
  pfd[1].events = POLLIN;

  int r = poll(pfd, 2, -1);
  if(r == -1) {
    perror("poll");
    return -1;
  }
  if(pfd[0].revents & POLLIN) {
    mbus_set_state(ms, MBUS_STATE_RX, "idle: rx");
  } else if(pfd[1].revents & POLLIN) {
    uint8_t cmd;
    if(read(ms->ms_pipe[0], &cmd, 1) == 1) {
      if(cmd == 't')
        mbus_set_state(ms, MBUS_STATE_TX, "idle: tx");
      else
        return -1;
    }
  }
  return 0;
}


static void
set_txe(mbus_serial_t *ms, int on)
{
  ioctl(ms->ms_fd, on ? TIOCMBIS : TIOCMBIC, (int []){TIOCM_RTS});
}



int
mbus_bus_tx(mbus_serial_t *ms)
{
  ms->ms_sync = 0;

  pthread_mutex_lock(&ms->ms_mpq_mutex);
  mbus_packet_t *mp = TAILQ_FIRST(&ms->ms_mpq);
  pthread_mutex_unlock(&ms->ms_mpq_mutex);
  if(mp == NULL) {
    mbus_set_state(ms, MBUS_STATE_IDLE, "tx: NoPkt");
    return 0;
  }

  set_txe(ms, 1);

  if(write(ms->ms_fd, mp->mp_data, mp->mp_size) != mp->mp_size) {
    mbus_set_state(ms, MBUS_STATE_RX, "tx: write-fail");
    return 0;
  }
  uint8_t bounce[mp->mp_size];
  size_t echo_rx_size = 0;

  while(echo_rx_size != mp->mp_size) {

    struct pollfd pfd[1];
    pfd[0].fd = ms->ms_fd;
    pfd[0].events = POLLIN;
    int r = poll(pfd, 1, 20);
    if(r != 1) {
      set_txe(ms, 0);
      mbus_set_state(ms, MBUS_STATE_RX, "tx: Read timeout");
      return 0;
    }

    r = read(ms->ms_fd, bounce + echo_rx_size, mp->mp_size - echo_rx_size);
    if(r < 0) {
      set_txe(ms, 0);
      mbus_set_state(ms, MBUS_STATE_RX, "tx: Read error");
      return 0;
    }

    if(memcmp(bounce + echo_rx_size,
              mp->mp_data + echo_rx_size, r)) {
      set_txe(ms, 0);
      mbus_set_state(ms, MBUS_STATE_RX, "tx: Noise/Collision");
      return 0;
    }
    echo_rx_size += r;
  }

  set_txe(ms, 0);
  pthread_mutex_lock(&ms->ms_mpq_mutex);
  TAILQ_REMOVE(&ms->ms_mpq, mp, mp_link);
  pthread_mutex_unlock(&ms->ms_mpq_mutex);
  free(mp);
  mbus_set_state(ms, MBUS_STATE_RX, "tx: Done");
  return 0;
}


static void
hdlc_decode(mbus_serial_t *ms)
{
  size_t o = 0;
  uint8_t *b = ms->ms_rxbuf;
  for(size_t i = 0; i < ms->ms_rxlen; i++) {
    if(b[i] == 0x7d && i + 1 != ms->ms_rxlen) {
      i++;
      b[o++] = b[i] ^ 0x20;
    } else {
      b[o++] = b[i];
    }
  }
  ms->ms_rxlen = o;
}



int
mbus_bus_rx(mbus_serial_t *ms)
{
  struct pollfd pfd[1];

  pfd[0].fd = ms->ms_fd;
  pfd[0].events = POLLIN;
  int r = poll(pfd, 1, 18 + rand() % 10);
  if(r == -1) {
    perror("poll");
    return -1;
  }

  if(r == 0) {
    return mbus_bus_tx(ms);
  }
  uint8_t c;
  r = read(ms->ms_fd, &c, 1);
  if(r == -1) {
    perror("read");
    return -1;
  }
  if(c == 0x7e) {
    if(ms->ms_rxlen) {
      hdlc_decode(ms);
      pthread_mutex_lock(&ms->m.m_mutex);
      mbus_rx_handle_pkt(&ms->m, ms->ms_rxbuf, ms->ms_rxlen, 1);
      pthread_mutex_unlock(&ms->m.m_mutex);
    }

    ms->ms_rxlen = 0;
    ms->ms_sync = 1;
    return 0;
  }

  if(!ms->ms_sync)
    return 0;

  ms->ms_rxbuf[ms->ms_rxlen] = c;
  ms->ms_rxlen++;
  return 0;
}


static void *
mbus_thread(void *arg)
{
  mbus_serial_t *ms = arg;
  set_txe(ms, 0);

  while(1) {

    int r = 0;
    switch(ms->ms_state) {
    case MBUS_STATE_IDLE:
      r = mbus_bus_idle(ms);
      break;
    case MBUS_STATE_TX:
      r = mbus_bus_tx(ms);
      break;
    case MBUS_STATE_RX:
      r = mbus_bus_rx(ms);
      break;
    }
    if(r)
      break;
  }
  return NULL;
}

static mbus_error_t
mbus_serial_send_fd(mbus_t *m, uint8_t addr, const void *data,
                    size_t len, const struct timespec *deadline)
{
  mbus_serial_t *ms = (mbus_serial_t *)m;
  mbus_packet_t *mp = encode_packet(data, len, m, addr);
  mbus_error_t err = 0;
  if(write(ms->ms_fd, mp->mp_data, mp->mp_size) != mp->mp_size) {
    err = MBUS_ERR_TX;
  }
  free(mp);
  return err;
}


mbus_t *
mbus_create_serial(const char *device, int baudrate,
                   uint8_t local_addr, int full_duplex)
{
  int fd = open(device, O_RDWR | O_NOCTTY);
  if(fd == -1) {
    fprintf(stderr, "Unable to open %s -- %s\n", device, strerror(errno));
    return NULL;
  }

  mbus_serial_t *ms = calloc(1, sizeof(mbus_serial_t));
  ms->ms_fd = fd;

  if(setupdev(ms, baudrate) < 0) {
    close(fd);
    free(ms);
    return NULL;
  }

#ifdef __linux__
  if(pipe2(ms->ms_pipe, O_CLOEXEC)) {
    perror("pipe");
    close(fd);
    free(ms);
    return NULL;
  }
#else
  if(pipe(ms->ms_pipe)) {
    perror("pipe");
    close(fd);
    free(ms);
    return NULL;
  }
#endif

  TAILQ_INIT(&ms->ms_mpq);

  ms->m.m_our_addr = local_addr;
  ms->m.m_send = full_duplex ? mbus_serial_send_fd : mbus_serial_send_hd;
  ms->m.m_destroy = mbus_serial_destroy;

  mbus_init_common(&ms->m);

  pthread_create(&ms->ms_tid, NULL, mbus_thread, ms);

  return &ms->m;
}
