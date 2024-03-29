#include "mbus.h"
#include "mbus_i.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <libusb.h>

typedef struct {
  mbus_t m;
  pthread_t mu_tid;
  libusb_device_handle *mu_handle;
  uint16_t mu_vid;
  uint16_t mu_pid;

  int mu_interface;
  int mu_IN_endpoint;
  int mu_OUT_endpoint;

  int mu_mbus_vendor_subclass;

  char *mu_serial;
  pthread_cond_t mu_handle_cond;

} mbus_usb_t;


static int
mbus_xmit(libusb_device_handle *h, int endpoint, const uint8_t* data,
          size_t len, mbus_t *m)
{
  uint8_t payload[len + 4];
  memcpy(payload, data, len);

  uint32_t crc = ~mbus_crc32(0, payload, len);
  memcpy(payload + len, &crc, 4);

  int actual_length;

  mbus_pkt_trace(m, "TX", payload, len + 4, 2);

  return libusb_bulk_transfer(h, endpoint, payload, len + 4,
                              &actual_length, 5000);
}


static mbus_error_t
mbus_usb_send(mbus_t *m, const void *data,
              size_t len, const struct timespec* deadline)
{
  mbus_usb_t *mu = (mbus_usb_t *)m;
  struct libusb_device_handle *dh;


  while ((dh = mu->mu_handle) == NULL) {
    if(deadline == NULL ||
       pthread_cond_timedwait(&mu->mu_handle_cond, &m->m_mutex, deadline) ==
       ETIMEDOUT) {
      return MBUS_ERR_NO_DEVICE;
    }
  }

  if(mbus_xmit(mu->mu_handle, mu->mu_OUT_endpoint, data, len, m)) {
    return MBUS_ERR_TX;
  }

  return 0;
}


static libusb_device_handle *
mbus_usb_open(mbus_usb_t *mu, libusb_context *ctx)
{
  struct libusb_device** devs;
  struct libusb_device* dev;
  struct libusb_device_handle* dev_handle = NULL;
  size_t i = 0;
  int r;

  if(libusb_get_device_list(ctx, &devs) < 0)
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

    struct libusb_config_descriptor *cfg_desc;
    r = libusb_get_active_config_descriptor(dev, &cfg_desc);
    if(r < 0)
      continue;

    mu->mu_interface = -1;

    for(int i = 0 ; i < cfg_desc->bNumInterfaces; i++) {
      for(int j = 0 ; j < cfg_desc->interface[i].num_altsetting; j++) {

        if(cfg_desc->interface[i].altsetting[j].bInterfaceClass == 255 &&
           cfg_desc->interface[i].altsetting[j].bInterfaceSubClass == mu->mu_mbus_vendor_subclass) {

          mu->mu_IN_endpoint = -1;
          mu->mu_OUT_endpoint = -1;

          for(int k = 0 ; k < cfg_desc->interface[i].altsetting[j].bNumEndpoints; k++) {
            if(cfg_desc->interface[i].altsetting[j].endpoint[k].bEndpointAddress & 0x80) {
              mu->mu_IN_endpoint = cfg_desc->interface[i].altsetting[j].endpoint[k].bEndpointAddress;
            }
            if(!(cfg_desc->interface[i].altsetting[j].endpoint[k].bEndpointAddress & 0x80)) {
              mu->mu_OUT_endpoint = cfg_desc->interface[i].altsetting[j].endpoint[k].bEndpointAddress;
            }
          }
          if(mu->mu_IN_endpoint != -1 && mu->mu_OUT_endpoint != -1)
            mu->mu_interface = cfg_desc->interface[i].altsetting[j].bInterfaceNumber;
          break;
        }
      }
      if(mu->mu_interface != -1)
        break;
    }
    libusb_free_config_descriptor(cfg_desc);

    if(mu->mu_interface == -1)
      continue;

    r = libusb_open(dev, &dev_handle);
    if(r < 0) {
      mbus_log(&mu->m, "Failed to open USB device [%04x:%04x]: %s",
               desc.idVendor, desc.idProduct, libusb_error_name(r));
      continue;
    }
    if(!mu->mu_serial) {
      libusb_free_device_list(devs, 1);
      return dev_handle;
    }

    char sn[64];
    int len = libusb_get_string_descriptor_ascii(dev_handle,
                                                 desc.iSerialNumber,
                                                 (uint8_t*)sn,
                                                 sizeof(sn) - 1);
    if(len < 0)
      continue;

    sn[len] = 0;
    if(!strcmp(sn, mu->mu_serial)) {
      libusb_free_device_list(devs, 1);
      return dev_handle;
    }

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
    libusb_context *ctx;
    if(libusb_init(&ctx)) {
      sleep(1);
      continue;
    }

    struct libusb_device_handle* dh = mbus_usb_open(mu, ctx);
    if(dh != NULL) {
      mbus_log(&mu->m, "Opened USB-Interface:%d IN:0x%02x OUT:0x%02x",
               mu->mu_interface, mu->mu_IN_endpoint, mu->mu_OUT_endpoint);
      libusb_claim_interface(dh, mu->mu_interface);

      pthread_mutex_lock(&mu->m.m_mutex);
      mu->mu_handle = dh;
      pthread_cond_broadcast(&mu->mu_handle_cond);
      pthread_mutex_unlock(&mu->m.m_mutex);

      if(mu->m.m_status_cb != NULL)
        mu->m.m_status_cb(mu->m.m_aux, MBUS_CONNECTED);

      while (1) {
        uint8_t pkt[64];
        int actual_length = 0;

        int r = libusb_bulk_transfer(dh, mu->mu_IN_endpoint, pkt, sizeof(pkt),
                                     &actual_length, 0);
        if(r) {
          if(r == LIBUSB_ERROR_PIPE)
            continue; // Remote stalled
          mbus_log(&mu->m, "USB bulk transfer error:%s",
                   libusb_error_name(r));
          break;
        }

        pthread_mutex_lock(&mu->m.m_mutex);
        mbus_rx_handle_pkt(&mu->m, pkt, actual_length, 1);
        pthread_mutex_unlock(&mu->m.m_mutex);
      }

      pthread_mutex_lock(&mu->m.m_mutex);
      mu->mu_handle = NULL;
      pthread_mutex_unlock(&mu->m.m_mutex);

      if(mu->m.m_status_cb != NULL)
        mu->m.m_status_cb(mu->m.m_aux, MBUS_DISCONNECTED);
      libusb_release_interface(dh, mu->mu_interface);
      libusb_close(dh);
    }
    usleep(100000);
    libusb_exit(ctx);
  }
  return NULL;
}


static void
mbus_usb_destroy(mbus_t *m)
{
  abort();
}


mbus_t *
mbus_create_usb(uint16_t vid, uint16_t pid, int vendor_subclass,
                const char *serial,
                uint8_t local_addr,
                mbus_log_cb_t *log_cb,
                mbus_status_cb_t *status_cb,
                void *aux)
{
  mbus_usb_t *mu = calloc(1, sizeof(mbus_usb_t));
  mu->m.m_our_addr = local_addr;
  mu->mu_mbus_vendor_subclass = vendor_subclass;
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

  mbus_init_common(&mu->m, log_cb, status_cb, aux);

  pthread_create(&mu->mu_tid, NULL, mbus_thread, mu);
  return &mu->m;
}
