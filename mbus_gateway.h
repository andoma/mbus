#pragma once

#include "mbus_i.h"

mbus_error_t mbus_gateway(mbus_t *m, int port);

int mbus_gateway_intercept(mbus_t *m, const uint8_t *pkt, size_t len);
