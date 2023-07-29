#include "mbus_i.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>




typedef struct mbus_tcp {
  mbus_t m;
  pthread_t mt_tid;
  int mt_fd;
  struct sockaddr_in mt_remoteaddr;

} mbus_tcp_t;

static mbus_error_t
mbus_tcp_send(mbus_t *m, const void *data,
              size_t len, const struct timespec *deadline)
{
  mbus_tcp_t *mt = (mbus_tcp_t *)m;
  int plen = 1 + len;
  uint8_t pkt[plen];

  pkt[0] = len;
  memcpy(pkt + 1, data, len);

  mbus_error_t err = 0;
  if(write(mt->mt_fd, pkt, plen) != plen) {
    err = MBUS_ERR_TX;
  }
  return err;
}


static void *
tcp_rx_thread(void *arg)
{
  mbus_tcp_t *mt = arg;

  uint8_t plen;
  uint8_t pkt[256];

  while(1) {
    if(recv(mt->mt_fd, &plen, 1, MSG_WAITALL) != 1)
      break;

    if(recv(mt->mt_fd, pkt, plen, MSG_WAITALL) != plen)
      break;

    pthread_mutex_lock(&mt->m.m_mutex);
    mbus_rx_handle_pkt(&mt->m, pkt, plen, 0);
    pthread_mutex_unlock(&mt->m.m_mutex);
  }
  return NULL;
}




typedef struct {
  int be_fd;
  mbus_t *be_m;
} mbus_tcp_conn_backend_t;


static mbus_error_t
mbus_tcp_conn_send_locked(void *backend, const void *data, size_t len)
{
  mbus_tcp_conn_backend_t *be = backend;
  mbus_t *m = be->be_m;
  int fd = be->be_fd;

  pthread_mutex_unlock(&m->m_mutex);

  uint8_t pkt[1 + len];
  pkt[0] = len;
  memcpy(pkt + 1, data, len);
  len++;
  int res = write(fd, pkt, len);
  pthread_mutex_lock(&m->m_mutex);
  if(res != len) {
    return MBUS_ERR_TX;
  }
  return 0;
}

static int
mbus_tcp_conn_recv_locked(void *backend, void **ptr)
{
  mbus_tcp_conn_backend_t *be = backend;
  mbus_t *m = be->be_m;
  int fd = be->be_fd;

  int rval = 0;

  uint8_t plen;
  uint8_t pkt[256];

  pthread_mutex_unlock(&m->m_mutex);

  *ptr = NULL;
  if(recv(fd, &plen, 1, MSG_WAITALL) == 1 &&
     recv(fd, pkt, plen, MSG_WAITALL) == plen) {

    void *d = malloc(plen);
    memcpy(d, pkt, plen);
    *ptr = d;
    rval = plen;
  }

  pthread_mutex_lock(&m->m_mutex);
  return rval;
}

static void
mbus_tcp_conn_shutdown_locked(void *backend)
{
  mbus_tcp_conn_backend_t *be = backend;
  int fd = be->be_fd;
  shutdown(fd, 2);
}

static void
mbus_tcp_conn_close_locked(void *backend, int wait)
{
  mbus_tcp_conn_backend_t *be = backend;
  int fd = be->be_fd;
  close(fd);
  free(be);
}

static mbus_con_t *
mbus_conn_connect(mbus_t *m, uint8_t remote_addr, const char *service)
{
  mbus_tcp_t *mt = (mbus_tcp_t *)m;

  int fd = socket(AF_INET, SOCK_STREAM, 0);

  if(connect(fd, (struct sockaddr *)&mt->mt_remoteaddr, sizeof(mt->mt_remoteaddr)) < 0) {
    perror("connect");
    return NULL;
  }

  int smol = 2048;
  int r = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &smol, sizeof(smol));
  if(r < 0)
    perror("SO_SNDBUF");

  const size_t servicelen = strlen(service);
  const size_t hdrlen = 1 + 1 + 1 + servicelen;
  uint8_t hdr[hdrlen];

  hdr[0] = 2; // Connection mode
  hdr[1] = 1 + servicelen; // Packet length
  hdr[2] = remote_addr;
  memcpy(hdr + 3, service, servicelen);

  if(write(fd, hdr, hdrlen) != hdrlen) {
    fprintf(stderr, "Failed to send initial header\n");
    close(fd);
    return NULL;
  }

  mbus_tcp_conn_backend_t *be = calloc(1, sizeof(mbus_tcp_conn_backend_t));

  be->be_fd = fd;
  be->be_m = m;
  mbus_con_t *mc = calloc(1, sizeof(mbus_con_t));
  mc->backend = be;
  mc->m = m;
  mc->send_locked = mbus_tcp_conn_send_locked;
  mc->recv_locked = mbus_tcp_conn_recv_locked;
  mc->shutdown_locked = mbus_tcp_conn_shutdown_locked;
  mc->close_locked = mbus_tcp_conn_close_locked;

  return mc;
}



mbus_t *
mbus_create_tcp(const char *host, int port, uint8_t local_addr,
                mbus_log_cb_t *log_cb, void *aux)
{
  struct sockaddr_in remoteaddr = {
    .sin_family = AF_INET,
    .sin_port = htons(port),
    .sin_addr.s_addr = inet_addr(host),
  };

  int fd = socket(AF_INET, SOCK_STREAM, 0);

  if(connect(fd, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr)) < 0) {
    perror("connect");
    return NULL;
  }

  uint8_t hdr = 1;
  if(write(fd, &hdr, 1) != 1) {
    fprintf(stderr, "Failed to send initial header\n");
    close(fd);
    return NULL;
  }

  mbus_tcp_t *mt = calloc(1, sizeof(mbus_tcp_t));
  mt->mt_fd = fd;
  mt->mt_remoteaddr = remoteaddr;

  mt->m.m_our_addr = local_addr;
  mt->m.m_send = mbus_tcp_send;
  mt->m.m_connect_locked = mbus_conn_connect;
  mbus_init_common(&mt->m, log_cb, aux);


  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  pthread_create(&mt->mt_tid, &attr, tcp_rx_thread, mt);

  return &mt->m;
}
