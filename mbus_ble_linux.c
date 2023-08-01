#include "mbus_i.h"

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>


typedef struct mbus_ble {
  mbus_t m;
  pthread_t tid;
  int fd;

} mbus_ble_t;


static mbus_error_t
mbus_ble_send(mbus_t *m, const void *data,
              size_t len, const struct timespec *deadline)
{
  mbus_ble_t *mb = (mbus_ble_t *)m;

  uint8_t payload[len + 4];
  memcpy(payload, data, len);

  uint32_t crc = ~mbus_crc32(0, payload, len);
  memcpy(payload + len, &crc, 4);

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
    int plen = read(mb->fd, pkt, sizeof(pkt));
    if(plen == -1) {
      fprintf(stderr, "BLE Read error %s\n", strerror(errno));
      break;
    }

    pthread_mutex_lock(&mb->m.m_mutex);
    mbus_rx_handle_pkt(&mb->m, pkt, plen, 1);
    pthread_mutex_unlock(&mb->m.m_mutex);
  }
  return NULL;
}

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



mbus_t *
mbus_create_ble(const char *host, uint8_t local_addr,
                mbus_log_cb_t *log_cb, void *aux)
{
  int fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, 0);
  if(fd == -1) {
    perror("socket");
    exit(1);
  }

  struct sockaddr_l2 addr = {0};

  addr.l2_family = AF_BLUETOOTH;
  if(bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
    perror("bind");
    exit(1);
  }

  for(int i = 5 ; i >= 0; i--) {
    int h = hexnibble(&host);
    int l = hexnibble(&host);
    if(h == -1 || l == -1) {
      fprintf(stderr, "Malformed address\n");
      exit(1);
    }
    addr.l2_bdaddr[i] = (h << 4) | l;
  }

  addr.l2_bdaddr_type = BDADDR_LE_RANDOM;
  addr.l2_psm = 0x83;

  fprintf(stderr, "Connecting to %02x:%02x:%02x:%02x:%02x:%02x:%d\n",
          addr.l2_bdaddr[5],
          addr.l2_bdaddr[4],
          addr.l2_bdaddr[3],
          addr.l2_bdaddr[2],
          addr.l2_bdaddr[1],
          addr.l2_bdaddr[0],
          addr.l2_psm);

  if(connect(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
    perror("connect");
    exit(1);
  }

  mbus_ble_t *mb = calloc(1, sizeof(mbus_ble_t));
  mb->fd = fd;

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
