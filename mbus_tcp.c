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

  mbus_tcp_t *mt = calloc(1, sizeof(mbus_tcp_t));
  mt->mt_fd = fd;

  mt->m.m_our_addr = local_addr;
  mt->m.m_send = mbus_tcp_send;

  mbus_init_common(&mt->m, log_cb, aux);


  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  pthread_create(&mt->mt_tid, &attr, tcp_rx_thread, mt);

  return &mt->m;
}
