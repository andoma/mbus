#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

struct mbus;

mbus_error_t mbus_gateway(struct mbus *m, int port, int background);

#ifdef __cplusplus
}
#endif
