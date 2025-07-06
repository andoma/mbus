#include "mbus_i.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

mbus_error_t
mbus_remote_get(mbus_t *m, uint8_t target_addr, const char *remote_path,
                const char *local_path)

{
  mbus_con_t *mc = mbus_connect(m, target_addr, "getfile");

  mbus_send(mc, remote_path, strlen(remote_path));

  void *data;
  int len = mbus_recv(mc, &data);
  if(len != 8) {
    mbus_log(m, "getfile: Failed to receive file status");
    return MBUS_ERR_OPERATION_FAILED;
  }

  uint32_t *u32 = data;

  if(u32[0] != 0) {
    mbus_log(m, "getfile: Remote error: %d", u32[0]);
    free(data);
    mbus_close(mc, 0);
    return MBUS_ERR_OPERATION_FAILED;
  }

  uint32_t size = u32[1];
  mbus_log(m, "getfile: File size: %d", size);
  free(data);

  int fd = open(local_path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
  if(fd == -1) {
    mbus_log(m, "getfile: Unable to open local file %s -- %m", local_path);
    mbus_close(mc, 0);
    return MBUS_ERR_OPERATION_FAILED;
  }

  int total = 0;
  data = NULL;
  while(total < size) {
    len = mbus_recv(mc, &data);
    if(len <= 0) {
      free(data);
      break;
    }
    int written = write(fd, data, len);
    free(data);
    data = NULL;

    if(written != len) {
      mbus_log(m, "getfile: local write failed");
      break;
    }
    total += written;
  }

  if(total != size) {
    mbus_log(m, "getfile: Not all bytes received. Got %u expected %u",
             total, size);
  }

  mbus_close(mc, 0);
  return 0;
}
