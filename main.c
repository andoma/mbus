#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "mbus.h"
#include "mbus_gateway.h"
#include "remote_shell.h"

int
main(int argc, char **argv)
{
  int opt;
  const char *connect_to = NULL;
  int local_addr = 15;
  int target_addr = 1;
  int debug_level = 0;
  srand(time(NULL) & getpid());

  while ((opt = getopt(argc, argv, "c:t:l:d:")) != -1) {
    switch(opt) {
    case 'l':
      local_addr = atoi(argv[1]);
      break;
    case 'c':
      connect_to = optarg;
      break;
    case 't':
      target_addr = atoi(optarg);
      break;
    case 'd':
      debug_level = atoi(optarg);
      break;
    }
  }

  if(connect_to == NULL) {
    fprintf(stderr, "No -c option given\n");
    exit(1);
  }
  mbus_t *m = mbus_create_from_constr(connect_to, local_addr,
                                      NULL, NULL);
  if(m == NULL) {
    fprintf(stderr, "Failed to create mbus connection\n");
    exit(1);
  }

  mbus_set_debug_level(m, debug_level);

  argc -= optind;
  argv += optind;

  if(argc == 0) {
    fprintf(stderr, "No command given\n");
    return 0;
  }

  mbus_error_t err;
  if(!strcmp(argv[0], "ping")) {
    err = mbus_invoke(m, target_addr, "ping", NULL, 0, NULL, 0, 1000);
  } else if(!strcmp(argv[0], "ping-f")) {
    time_t t0 = time(NULL);
    int pps = 0;
    while(1) {
      err = mbus_invoke(m, target_addr, "ping", NULL, 0, NULL, 0, 1000);
      if(err)
        break;
      pps++;
      const time_t now = time(NULL);
      if(now != t0) {
        printf("%d pps\n", pps);
        pps = 0;
        t0 = now;
      }
    }
  } else if(!strcmp(argv[0], "ota")) {
    err = mbus_ota_elf(m, target_addr, argv[1],
                       argc > 2 && !strcmp(argv[2], "force"));
  } else if(!strcmp(argv[0], "buildid")) {
    uint8_t build_id[20];
    size_t build_id_size = sizeof(build_id);
    err = mbus_invoke(m, target_addr, "buildid", NULL, 0,
                      build_id, &build_id_size, 1000);
    if(!err) {
      printf("Build-id: ");
      for(int i = 0; i < build_id_size; i++) {
        printf("%02x", build_id[i]);
      }
      printf("\n");
    }

  } else if(!strcmp(argv[0], "shell")) {

    err = mbus_remote_shell(m, target_addr);

  } else if(!strcmp(argv[0], "gateway")) {
    if(argc < 2) {
      fprintf(stderr, "Missing argument: port\n");
      return 1;
    }
    err = mbus_gateway(m, atoi(argv[1]), 0);
  } else {
    fprintf(stderr, "Unknown command %s\n", argv[0]);
    return 1;
  }

  if(err)
    fprintf(stderr, "%s\n", mbus_error_to_string(err));
  else
    fprintf(stderr, "OK\n");
  return !!err;
}
