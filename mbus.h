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

#define MBUS_OP_PING 0
#define MBUS_OP_PONG 1
#define MBUS_OP_PUB_META 2
#define MBUS_OP_PUB_DATA 3

#define MBUS_OP_DSIG_EMIT  7
// [u8 signal] [u8 ttl] [data ...]

#define MBUS_OP_RPC_RESOLVE 8
// [u8 txid] [name ...]

#define MBUS_OP_RPC_RESOLVE_REPLY 9
// [u8 txid] ([u32 method id] | [])

#define MBUS_OP_RPC_INVOKE 10
// [u8 txid] [u32 method id] [var in-data]

#define MBUS_OP_RPC_ERR 11
// [u8 txid] [s32 errcode]

#define MBUS_OP_RPC_REPLY 12
// [u8 txid] [var out-data]

#define MBUS_OP_OTA_XFER 13

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
  MBUS_CONNECTED = 1,
  MBUS_DISCONNECTED = 2,
} mbus_status_t;

typedef struct mbus mbus_t;

typedef void (mbus_log_cb_t)(void *aux, const char *msg);

int64_t mbus_get_ts(void);

void mbus_set_debug_level(mbus_t *m, int level);

mbus_t *mbus_create_usb(uint16_t vid, uint16_t pid, int vendor_subclass,
                        const char *serial, uint8_t local_addr,
                        mbus_log_cb_t *log_cb,
                        void (*status_cb)(void *aux, mbus_status_t status),
                        void *aux);

mbus_t *mbus_create_serial(const char *device, int baudrate,
                           uint8_t local_addr, int full_duplex,
                           mbus_log_cb_t *log_cb, void *aux);

mbus_t *mbus_create_tcp(const char *host, int port, uint8_t local_addr,
                        mbus_log_cb_t *log_cb, void *aux);


mbus_t *mbus_create_from_constr(const char *str, uint8_t local_addr,
                                mbus_log_cb_t *log_cb, void *aux);

mbus_error_t mbus_invoke(mbus_t *m, uint8_t addr, const char *name,
                         const void *req, size_t req_size, void *reply,
                         size_t *reply_size, int timeout_ms);

uint8_t mbus_get_local_addr(mbus_t *m);

const char *mbus_error_to_string(mbus_error_t err);

typedef struct mbus_dsig_sub mbus_dsig_sub_t;

mbus_dsig_sub_t *mbus_dsig_sub(mbus_t *m,
                               uint16_t signal,
                               void (*cb)(void *opaque, const uint8_t *data,
                                          size_t len),
                               void *opaque,
                               int64_t ttl);

mbus_error_t  mbus_dsig_emit(mbus_t *m, uint16_t signal, const void *data,
                             size_t len);

typedef struct mbus_dsig_driver mbus_dsig_driver_t;

mbus_dsig_driver_t *mbus_dsig_drive(mbus_t *m, uint8_t signal, uint8_t ttl);

void mbus_dsig_set(mbus_t *m,
                   mbus_dsig_driver_t *mdd,
                   const void *data, size_t len);

void mbus_dsig_clear(mbus_t *m, mbus_dsig_driver_t *mdd);



typedef struct mbus_seqpkt_con mbus_seqpkt_con_t;

mbus_seqpkt_con_t *mbus_seqpkt_connect(mbus_t *m,
                                       uint8_t remote_addr,
                                       const char *service);

mbus_error_t mbus_seqpkt_send(mbus_seqpkt_con_t *msc, const void *data,
                              size_t len);

int mbus_seqpkt_recv(mbus_seqpkt_con_t *msc, void **ptr);

void mbus_seqpkt_shutdown(mbus_seqpkt_con_t *msc);

void mbus_seqpkt_close(mbus_seqpkt_con_t *msc, int wait);

void mbus_destroy(mbus_t *mbus);

uint32_t mbus_get_active_hosts(mbus_t *m);

mbus_error_t mbus_ping(mbus_t *m, uint8_t remote_addr);

mbus_error_t mbus_ota(mbus_t *m, uint8_t target_addr, const char *path,
                      int force_upgrade);

#ifdef __cplusplus
}
#endif
