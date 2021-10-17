#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "mbus.h"

int
main(int argc, char **argv)
{
  int opt;
  const char *device = NULL;
  int local_addr = 15;

  while ((opt = getopt(argc, argv, "d:")) != -1) {
    switch(opt) {
    case 'd':
      device = optarg;
      break;
    }
  }
  mbus_t *m;
  if(device != NULL) {
    m = mbus_create_serial(device, 115200, local_addr);
  } else {
    fprintf(stderr, "No transport specified\n");
    return -1;
  }
  printf("mbus:%p\n", m);

  pause();
}
