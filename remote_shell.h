#include "mbus.h"

mbus_error_t mbus_remote_shell(mbus_t *m, uint8_t target_addr,
                               const char *service);

mbus_error_t mbus_remote_log(mbus_t *m, uint8_t target_addr);


