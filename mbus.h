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

#include "pcs/pcs.h"

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
    ERR_INVALID_RPC_ARGS      = -21,
    ERR_NO_FLASH_SPACE        = -22,
} mbus_error_t;

typedef enum {
  MBUS_CONNECTED = 1,
  MBUS_DISCONNECTED = 2,
} mbus_status_t;

typedef struct mbus mbus_t;

int64_t mbus_get_ts(void);

mbus_t *mbus_create_usb(uint16_t vid, uint16_t pid, const char *serial,
                        uint8_t local_addr,
                        void (*status_cb)(void *aux, mbus_status_t status),
                        void *aux);

mbus_t *mbus_create_serial(const char *device, int baudrate,
                           uint8_t local_addr, int full_duplex);

mbus_t *mbus_create_tcp(const char *addr, uint8_t local_addr);

mbus_error_t mbus_invoke(mbus_t *m, uint8_t addr, const char *name,
                         const void *req, size_t req_size, void *reply,
                         size_t *reply_size, int timeout_ms);

const char *mbus_error_to_string(mbus_error_t err);

typedef struct mbus_dsig_sub mbus_dsig_sub_t;

mbus_dsig_sub_t *mbus_dsig_sub(mbus_t *m,
                               uint8_t signal,
                               void (*cb)(void *opaque, const uint8_t *data,
                                          size_t len),
                               void *opaque);

mbus_error_t  mbus_dsig_emit(mbus_t *m, uint8_t signal, const void *data,
                             size_t len, uint8_t ttl);

typedef struct mbus_dsig_driver mbus_dsig_driver_t;

mbus_dsig_driver_t *mbus_dsig_drive(mbus_t *m, uint8_t signal, uint8_t ttl);

void mbus_dsig_set(mbus_t *m,
                   mbus_dsig_driver_t *mdd,
                   const void *data, size_t len);

void mbus_dsig_clear(mbus_t *m, mbus_dsig_driver_t *mdd);

pcs_iface_t *mbus_get_pcs_iface(mbus_t *m);

void mbus_destroy(mbus_t *mbus);



#ifdef __cplusplus
}
#endif
