#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "mbus.h"


int
main(int argc, char **argv)
{
  int opt;
  const char *device = NULL;
  int local_addr = 15;
  int full_duplex = 0;
  int target_addr = 1;

  while ((opt = getopt(argc, argv, "d:ft:")) != -1) {
    switch(opt) {
    case 'd':
      device = optarg;
      break;
    case 'f':
      full_duplex = 1;
      break;
    case 't':
      target_addr = atoi(optarg);
      break;
    }
  }
  mbus_t *m;
  if(device != NULL) {
    m = mbus_create_serial(device, 115200, local_addr, full_duplex);
  } else {
    fprintf(stderr, "No transport specified\n");
    return -1;
  }


  argc -= optind;
  argv += optind;

  if(argc == 0) {
    fprintf(stderr, "No command given\n");
    return 0;
  }

  mbus_error_t err;
  if(!strcmp(argv[0], "ping")) {
    err = mbus_invoke(m, target_addr, "ping", NULL, 0, NULL, 0, 1000);
  } else {
    fprintf(stderr, "Unknown command %s\n", argv[0]);
    return 1;
  }

  if(err)
    fprintf(stderr, "%s\n", mbus_error_to_string(err));

  return !!err;
}
