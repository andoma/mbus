#include "mbus.h"
#include "mbus_i.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <libusb.h>

typedef struct {
  mbus_t m;
  pthread_t mu_tid;
  libusb_device_handle *mu_handle;
  libusb_context *mu_ctx;
  uint16_t mu_vid;
  uint16_t mu_pid;
  char *mu_serial;
  pthread_cond_t mu_handle_cond;

  void (*mu_status_cb)(void *aux, mbus_status_t status);
  void *mu_aux;

} mbus_usb_t;


static int
mbus_xmit(libusb_device_handle *h, int endpoint, const uint8_t* data,
          size_t len, uint8_t dst_addr, uint8_t src_addr)
{
  uint8_t payload[1 + len + 4];
  payload[0] = (src_addr << 4) | dst_addr;
  memcpy(payload + 1, data, len);

  uint32_t crc = ~mbus_crc32(0, payload, 1 + len);
  memcpy(payload + 1 + len, &crc, 4);

  int actual_length;
  return libusb_bulk_transfer(h, endpoint, payload, 1 + len + 4,
                              &actual_length, 5000);
}


static mbus_error_t
mbus_usb_send(mbus_t *m, uint8_t addr, const void *data,
              size_t len, const struct timespec* deadline)
{
  mbus_usb_t *mu = (mbus_usb_t *)m;
  struct libusb_device_handle *dh;

  while ((dh = mu->mu_handle) == NULL) {
    if(pthread_cond_timedwait(&mu->mu_handle_cond, &m->m_mutex, deadline) ==
       ETIMEDOUT) {
      return MBUS_ERR_NO_DEVICE;
    }
  }
  if(mbus_xmit(mu->mu_handle, 0x1, data, len, addr, m->m_our_addr)) {
    return MBUS_ERR_TX;
  }

  return 0;
}


static libusb_device_handle *
mbus_usb_open(mbus_usb_t *mu)
{
  struct libusb_device** devs;
  struct libusb_device* dev;
  struct libusb_device_handle* dev_handle = NULL;
  size_t i = 0;
  int r;

  if(libusb_get_device_list(mu->mu_ctx, &devs) < 0)
    return NULL;

  while ((dev = devs[i++]) != NULL) {
    struct libusb_device_descriptor desc;
    r = libusb_get_device_descriptor(dev, &desc);
    if(r < 0)
      break;

    if(mu->mu_vid && mu->mu_pid) {
      if(desc.idVendor != mu->mu_vid || desc.idProduct != mu->mu_pid)
        continue;
    }

    r = libusb_open(dev, &dev_handle);
    if(r < 0)
      continue;

    if(!mu->mu_serial)
      return dev_handle;

    char sn[64];
    int len = libusb_get_string_descriptor_ascii(dev_handle,
                                                 desc.iSerialNumber,
                                                 (uint8_t*)sn,
                                                 sizeof(sn) - 1);
    if(len < 0)
      continue;

    sn[len] = 0;
    if(!strcmp(sn, mu->mu_serial))
      return dev_handle;

    libusb_close(dev_handle);
  }
  libusb_free_device_list(devs, 1);
  return NULL;
}




static void *
mbus_thread(void *arg)
{
  mbus_usb_t *mu = arg;

  while (1) {
    if(libusb_init(&mu->mu_ctx)) {
      sleep(1);
      continue;
    }

    struct libusb_device_handle* dh = mbus_usb_open(mu);
    if(dh != NULL) {
      libusb_claim_interface(dh, 0);

      pthread_mutex_lock(&mu->m.m_mutex);
      mu->mu_handle = dh;
      pthread_cond_broadcast(&mu->mu_handle_cond);
      pthread_mutex_unlock(&mu->m.m_mutex);

      if(mu->mu_status_cb != NULL)
        mu->mu_status_cb(mu->mu_aux, MBUS_CONNECTED);

      while (1) {
        uint8_t pkt[128];
        int actual_length = 0;
        int r = libusb_bulk_transfer(dh, 0x81, pkt, sizeof(pkt),
                                     &actual_length, 0);
        if(r)
          break;

        pthread_mutex_lock(&mu->m.m_mutex);
        mbus_rx_handle_pkt(&mu->m, pkt, actual_length, 1);
        pthread_mutex_unlock(&mu->m.m_mutex);
      }

      pthread_mutex_lock(&mu->m.m_mutex);
      mu->mu_handle = NULL;
      mbus_cancel_rpc(&mu->m);
      pthread_mutex_unlock(&mu->m.m_mutex);

      if(mu->mu_status_cb != NULL)
        mu->mu_status_cb(mu->mu_aux, MBUS_DISCONNECTED);
    }
    usleep(100000);
    libusb_exit(mu->mu_ctx);
  }
  return NULL;
}


static void
mbus_usb_destroy(mbus_t *m)
{
  abort();
}



mbus_t *
mbus_create_usb(uint16_t vid, uint16_t pid, const char *serial,
                uint8_t local_addr,
                void (*status_cb)(void *aux, mbus_status_t status),
                void *aux)
{
  mbus_usb_t *mu = calloc(1, sizeof(mbus_usb_t));
  mu->mu_status_cb = status_cb;
  mu->mu_aux = aux;
  mu->m.m_our_addr = local_addr;

  pthread_condattr_t attr;
  pthread_condattr_init(&attr);
#ifdef __linux__
  pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
  pthread_cond_init(&mu->mu_handle_cond, &attr);
  pthread_condattr_destroy(&attr);

  mu->mu_vid = vid;
  mu->mu_pid = pid;
  mu->mu_serial = serial ? strdup(serial) : NULL;

  mu->m.m_send = mbus_usb_send;
  mu->m.m_destroy = mbus_usb_destroy;

  pthread_create(&mu->mu_tid, NULL, mbus_thread, mu);
  return &mu->m;
}
