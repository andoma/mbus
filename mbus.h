#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>


typedef enum {
    MBUS_ERR_OK = 0,
    MBUS_ERR_NOT_IMPLEMENTED = -1,
    MBUS_ERR_TIMEOUT = -2,
    MBUS_ERR_OPERATION_FAILED = -3,
    MBUS_ERR_TX = -4,
    MBUS_ERR_RX = -5,
    MBUS_ERR_NOT_READY = -6,
    MBUS_ERR_NO_BUFFER = -7,
    MBUS_ERR_MTU_EXCEEDED = -8,
    MBUS_ERR_INVALID_ID = -9,
    MBUS_ERR_DMA_ERROR = -10,
    MBUS_ERR_BUS_ERROR = -11,
    MBUS_ERR_ARBITRATION_LOST = -12,
    MBUS_ERR_BAD_STATE = -13,
    MBUS_ERR_INVALID_ADDRESS = -14,
    MBUS_ERR_NO_DEVICE = -15,
    MBUS_ERR_MISMATCH = -16,
    MBUS_ERR_NOT_FOUND = -17,
    MBUS_ERR_CHECKSUM_ERROR = -18,
    MBUS_ERR_MALFORMED = -19,
    MBUS_ERR_INVALID_RPC_ID = -20,
    MBUS_ERR_INVALID_RPC_ARGS      = -21,
    MBUS_ERR_NO_FLASH_SPACE        = -22,
    MBUS_ERR_INVALID_ARGS          = -23,
    MBUS_ERR_INVALID_LENGTH        = -24,
    MBUS_ERR_NOT_IDLE              = -25,
    MBUS_ERR_BAD_CONFIG            = -26,
    MBUS_ERR_FLASH_HW_ERROR        = -27,
    MBUS_ERR_FLASH_TIMEOUT         = -28,
    MBUS_ERR_NO_MEMORY             = -29,
    MBUS_ERR_READ_PROTECTED        = -30,
    MBUS_ERR_WRITE_PROTECTED       = -31,
    MBUS_ERR_AGAIN                 = -32,
    MBUS_ERR_NOT_CONNECTED         = -33,
    MBUS_ERR_BAD_PKT_SIZE          = -34,
} mbus_error_t;

typedef enum {
  MBUS_UNKNOWN_STATUS = 0,
  MBUS_CONNECTED = 1,
  MBUS_DISCONNECTED = 2,
  MBUS_SCANNING = 3,
} mbus_status_t;

typedef struct mbus mbus_t;

typedef void (mbus_log_cb_t)(void *aux, const char *msg);

typedef void (mbus_status_cb_t)(void *aux, mbus_status_t s);

int64_t mbus_get_ts(void);

void mbus_set_debug_level(mbus_t *m, int level);

mbus_t *mbus_create_usb(uint16_t vid, uint16_t pid, int vendor_subclass,
                        const char *serial, uint8_t local_addr,
                        mbus_log_cb_t *log_cb,
                        mbus_status_cb_t status_cb,
                        void *aux);

mbus_t *mbus_create_serial(const char *device, int baudrate,
                           uint8_t local_addr, int full_duplex,
                           mbus_log_cb_t *log_cb,
                           mbus_status_cb_t status_cb,
                           void *aux);

mbus_t *mbus_create_tcp(const char *host, int port, uint8_t local_addr,
                        mbus_log_cb_t *log_cb,
                        mbus_status_cb_t status_cb,
                        void *aux);

mbus_t *mbus_create_ble(const char *host, uint8_t local_addr,
                        mbus_log_cb_t *log_cb,
                        mbus_status_cb_t status_cb,
                        void *aux);

mbus_t *mbus_create_from_constr(const char *str, uint8_t local_addr,
                                mbus_log_cb_t *log_cb,
                                mbus_status_cb_t status_cb,
                                void *aux);

mbus_error_t mbus_invoke(mbus_t *m, uint8_t addr, const char *name,
                         const void *req, size_t req_size, void *reply,
                         size_t *reply_size, int timeout_ms);

uint8_t mbus_get_local_addr(mbus_t *m);

void mbus_destroy(mbus_t *mbus);

const char *mbus_error_to_string(mbus_error_t err);

// -- DSIG ----------------------------------------------------------

typedef struct mbus_dsig_sub mbus_dsig_sub_t;

mbus_dsig_sub_t *mbus_dsig_sub(mbus_t *m,
                               uint16_t signal,
                               void (*cb)(void *opaque, const uint8_t *data,
                                          size_t len),
                               void *opaque,
                               int ttl_ms);

mbus_error_t  mbus_dsig_emit(mbus_t *m, uint16_t signal, const void *data,
                             size_t len);

typedef struct mbus_dsig_driver mbus_dsig_driver_t;

mbus_dsig_driver_t *mbus_dsig_drive(mbus_t *m, uint16_t signal, int ttl_ms);

void mbus_dsig_set(mbus_t *m,
                   mbus_dsig_driver_t *mdd,
                   const void *data, size_t len);

void mbus_dsig_clear(mbus_t *m, mbus_dsig_driver_t *mdd);

// -- Connections --------------------------------------------------

typedef struct mbus_con mbus_con_t;

mbus_con_t *mbus_connect(mbus_t *m, uint8_t remote_addr, const char *service);

mbus_error_t mbus_send(mbus_con_t *c, const void *data, size_t len);

int mbus_recv(mbus_con_t *c, void **ptr);

void mbus_shutdown(mbus_con_t *c);

void mbus_close(mbus_con_t *c, int wait);

// -- Misc support --------------------------------------------

mbus_error_t mbus_ping(mbus_t *m, uint8_t remote_addr);

mbus_error_t mbus_ota(mbus_t *m, uint8_t target_addr, const char *path,
                      int force_upgrade);

mbus_error_t mbus_remote_get(mbus_t *m, uint8_t target_addr,
                             const char *remote_path, const char *local_path);

#ifdef __cplusplus
}
#endif
