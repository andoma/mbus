#include "mbus_i.h"

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>


struct sockaddr_l2 {
  sa_family_t l2_family;
  uint16_t l2_psm;
  uint8_t l2_bdaddr[6];
  uint16_t l2_vid;
  uint8_t l2_bdaddr_type;
};

#define BDADDR_BREDR		0x00
#define BDADDR_LE_PUBLIC	0x01
#define BDADDR_LE_RANDOM	0x02



typedef struct mbus_ble {
  mbus_t m;
  pthread_t tid;
  int fd;

  struct sockaddr_l2 remote;
  pthread_cond_t fd_cond;
} mbus_ble_t;


static int
hexnibble(const char **s)
{
  while(1) {
    char c = **s;
    if(c == 0)
      return -1;

    *s = *s + 1;
    switch(c) {
    case '0' ... '9':
      return c - '0';
    case 'a' ... 'f':
      return c - 'a' + 10;
    case 'A' ... 'F':
      return c - 'A' + 10;
    }
  }
}



static mbus_error_t
mbus_ble_send(mbus_t *m, const void *data,
              size_t len, const struct timespec *deadline)
{
  mbus_ble_t *mb = (mbus_ble_t *)m;

  uint8_t payload[len + 4];
  memcpy(payload, data, len);

  uint32_t crc = ~mbus_crc32(0, payload, len);
  memcpy(payload + len, &crc, 4);


  if(mb->fd == -1) {
    if(deadline == NULL)
      return MBUS_ERR_NOT_CONNECTED;

    while(mb->fd == -1) {
      if(pthread_cond_timedwait(&mb->fd_cond, &m->m_mutex, deadline) == ETIMEDOUT) {
        return MBUS_ERR_NOT_CONNECTED;
      }
    }
  }

  mbus_pkt_trace(m, "TX", payload, len + 4, 2);

  if(write(mb->fd, payload, len + 4) != len + 4) {
    fprintf(stderr, "Warning: write failed -- %s\n", strerror(errno));
  }
  return 0;
}


static void *
ble_rx_thread(void *arg)
{
  mbus_ble_t *mb = (mbus_ble_t *)arg;

  uint8_t pkt[256];

  while(1) {
    int fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, 0);
    if(fd == -1) {
      perror("socket");
      exit(1);
    }

    struct sockaddr_l2 addr = {0};

    addr.l2_family = AF_BLUETOOTH;
    addr.l2_bdaddr_type = BDADDR_LE_RANDOM;
    if(bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
      perror("bind");
      exit(1);
    }

    mbus_log(&mb->m,
             "Connecting to %02x:%02x:%02x:%02x:%02x:%02x:%d",
             mb->remote.l2_bdaddr[5],
             mb->remote.l2_bdaddr[4],
             mb->remote.l2_bdaddr[3],
             mb->remote.l2_bdaddr[2],
             mb->remote.l2_bdaddr[1],
             mb->remote.l2_bdaddr[0],
             mb->remote.l2_psm);

    if(connect(fd, (struct sockaddr *) &mb->remote, sizeof(mb->remote)) == -1) {
      mbus_log(&mb->m,
               "Failed to connect: %s", strerror(errno));
      close(fd);
      sleep(1);
      continue;
    }

    pthread_mutex_lock(&mb->m.m_mutex);
    mb->fd = fd;
    pthread_cond_signal(&mb->fd_cond);

    while(1) {
      pthread_mutex_unlock(&mb->m.m_mutex);
      int plen = read(mb->fd, pkt, sizeof(pkt));
      pthread_mutex_lock(&mb->m.m_mutex);
      if(plen == -1) {
        fprintf(stderr, "BLE Read error %s\n", strerror(errno));
        break;
      }

      mbus_rx_handle_pkt(&mb->m, pkt, plen, 1);
    }

    close(mb->fd);
    mb->fd = -1;
    pthread_mutex_unlock(&mb->m.m_mutex);
  }
  return NULL;
}



mbus_t *
mbus_create_ble(const char *host, uint8_t local_addr,
                mbus_log_cb_t *log_cb, void *aux)
{
  mbus_ble_t *mb = calloc(1, sizeof(mbus_ble_t));


  mb->remote.l2_bdaddr_type = BDADDR_LE_RANDOM;
  mb->remote.l2_psm = 0x83;
  mb->remote.l2_family = AF_BLUETOOTH;

  for(int i = 5 ; i >= 0; i--) {
    int h = hexnibble(&host);
    int l = hexnibble(&host);
    if(h == -1 || l == -1) {
      fprintf(stderr, "Malformed address\n");
      exit(1);
    }
    mb->remote.l2_bdaddr[i] = (h << 4) | l;
  }


  pthread_condattr_t cattr;
  pthread_condattr_init(&cattr);
#ifdef __linux__
  pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
#endif
  pthread_cond_init(&mb->fd_cond, &cattr);
  pthread_condattr_destroy(&cattr);
  mb->fd = -1;

  mb->m.m_our_addr = local_addr;
  mb->m.m_send = mbus_ble_send;
  mb->m.m_connect_locked = mbus_gdpkt_connect_locked;

  mbus_init_common(&mb->m, log_cb, aux);

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  pthread_create(&mb->tid, &attr, ble_rx_thread, mb);

  return &mb->m;
}
