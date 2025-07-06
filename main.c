#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "mbus.h"
#include "mbus_gateway.h"
#include "remote_shell.h"


typedef struct cmd {
  int argc;
  char **argv;
  int target_addr;
  mbus_t *m;
} cmd_t;



void *
dispatch_command(void *arg)
{
  const cmd_t *cmd = arg;
  mbus_error_t err;

  char **argv = cmd->argv;
  int argc = cmd->argc;
  int target_addr = cmd->target_addr;
  mbus_t *m = cmd->m;

  if(!strcmp(argv[0], "ping")) {
    //    err = mbus_invoke(m, target_addr, "ping", NULL, 0, NULL, 0, 1000);
    err = mbus_ping(m, target_addr);
  } else if(!strcmp(argv[0], "ping-f")) {
    time_t t0 = time(NULL);
    int pps = 0;
    int errors = 0;
    while(1) {
      err = mbus_invoke(m, target_addr, "ping", NULL, 0, NULL, 0, 100);
      if(err)
        errors++;
      else
        pps++;
      const time_t now = time(NULL);
      if(now != t0) {
        printf("%d pps %d errors (total)\n", pps, errors);
        pps = 0;
        t0 = now;
      }
    }
  } else if(!strcmp(argv[0], "ota")) {
    err = mbus_ota(m, target_addr, argv[1],
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

    err = mbus_remote_shell(m, target_addr, "shell");

  } else if(!strcmp(argv[0], "get")) {

    if(argc != 3) {
      fprintf(stderr, "usage: get <REMOTE-FILE> <LOCAL-FILE>\n");
      exit(1);
    }

    err = mbus_remote_get(m, target_addr, argv[1], argv[2]);

  } else if(!strcmp(argv[0], "echo")) {

    err = mbus_remote_shell(m, target_addr, "echo");

  } else if(!strcmp(argv[0], "chargen")) {

    err = mbus_remote_shell(m, target_addr, "chargen");

  } else if(!strcmp(argv[0], "discard")) {

    err = mbus_remote_discard(m, target_addr);

  } else if(!strcmp(argv[0], "log")) {

    err = mbus_remote_log(m, target_addr);
  } else if(!strcmp(argv[0], "gateway")) {
    if(argc < 2) {
      fprintf(stderr, "Missing argument: port\n");
      exit(1);
    }
    err = mbus_gateway(m, atoi(argv[1]), 0);

  } else {
    fprintf(stderr, "Unknown command %s\n", argv[0]);
    exit(1);
  }

  if(err)
    fprintf(stderr, "%s\n", mbus_error_to_string(err));
  else
    fprintf(stderr, "OK\n");
  exit(!!err);
}


#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>

#if 0
static void myRunLoopCallback(CFRunLoopObserverRef observer, CFRunLoopActivity activity, void *info)
{
  switch (activity) {
  case kCFRunLoopEntry:
    printf("%s\n", "kCFRunLoopEntry");
    break;
  case kCFRunLoopBeforeTimers:
    printf("%s\n", "kCFRunLoopBeforeTimers");
    break;
  case kCFRunLoopBeforeSources:
    printf("%s\n", "kCFRunLoopBeforeSources");
    break;
  case kCFRunLoopAfterWaiting:
    printf("%s\n", "kCFRunLoopAfterWaiting");
    break;
  case kCFRunLoopExit:
    printf("%s\n", "kCFRunLoopExit");
    break;
  default:
    break;
  }
}
#endif
static void
mainloop(void)
{
#if 0
  CFRunLoopObserverRef beginObserver = CFRunLoopObserverCreate(kCFAllocatorDefault, kCFRunLoopAllActivities, true, LONG_MIN, &myRunLoopCallback, NULL);

  CFRunLoopAddObserver(CFRunLoopGetMain(), beginObserver, kCFRunLoopCommonModes);
#endif

  CFRunLoopRun();
  exit(2);
}
#endif

#ifdef __linux__
static void
mainloop(void)
{
  pause();
}
#endif


int
main(int argc, char **argv)
{
  int opt;
  const char *connect_to = NULL;
  int local_addr = 31;
  int target_addr = 1;
  int debug_level = 0;
  srand(time(NULL) & getpid());

  while ((opt = getopt(argc, argv, "c:t:l:d:")) != -1) {
    switch(opt) {
    case 'l':
      local_addr = atoi(optarg);
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
                                      NULL, NULL, NULL);
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

  cmd_t cmd;
  cmd.argc = argc;
  cmd.argv = argv;
  cmd.m = m;
  cmd.target_addr = target_addr;

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  pthread_t tid;
  pthread_create(&tid, &attr, dispatch_command, &cmd);

  mainloop();
  exit(0);
}
