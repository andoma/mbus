#include "remote_shell.h"

#include <pthread.h>
#include <unistd.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>

static void *
send_thread(void *arg)
{
  pcs_t *pcs = arg;

  char buf[128];

  while(1) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    int r = read(0, buf, sizeof(buf));
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    if(r <= 0)
      break;
    for(int i = 0; i < r; i++) {
      if(buf[i] == 2) {
        pcs_shutdown(pcs);
        return NULL;
      }
    }
    pcs_send(pcs, buf, r);
    pcs_flush(pcs);
  }
  return NULL;
}


mbus_error_t
mbus_remote_shell(mbus_t *m, uint8_t target_addr)
{
  struct termios termio2, termio;

  pcs_iface_t *pi = mbus_get_pcs_iface(m);
  if(!isatty(0)) {
    fprintf(stderr, "stdin is not a tty\n");
    exit(1);
  }

  printf("* Exit with ^B\n");

  pcs_t *pcs = pcs_connect(pi, 0x80, mbus_get_ts(), target_addr);

  if(tcgetattr(0, &termio) == -1) {
    perror("tcgetattr");
    exit(1);
  }
  termio2 = termio;
  termio2.c_lflag &= ~(ECHO | ICANON | ISIG);
  if(tcsetattr(0, TCSANOW, &termio2) == -1) {
    perror("tcsetattr");
    exit(1);
  }

  pthread_t tid;
  pthread_create(&tid, NULL, send_thread, pcs);

  uint8_t buf[512];
  while(1) {
    int r = pcs_read(pcs, buf, sizeof(buf), 1);
    if(r <= 0)
      break;
#if 1
    if(write(1, buf, r) != r)
      break;
#endif
  }

  pthread_cancel(tid);
  pthread_join(tid, NULL);

  tcsetattr(0, TCSANOW, &termio);

  printf("\n* Disconnected\n");
  return 0;
}
