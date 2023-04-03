#include "remote_shell.h"

#include <pthread.h>
#include <unistd.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbus_i.h"

static void *
send_thread(void *arg)
{
  mbus_seqpkt_con_t *msc = arg;
  char buf[128];

  while(1) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    int r = read(0, buf, sizeof(buf));
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    if(r <= 0)
      break;
    for(int i = 0; i < r; i++) {
      if(buf[i] == 2) {
        fprintf(stderr, "^B\n");
        mbus_seqpkt_shutdown(msc);
        return NULL;
      }
    }
    mbus_seqpkt_send(msc, buf, r);
  }
  return NULL;
}


mbus_error_t
mbus_remote_shell(mbus_t *m, uint8_t target_addr, const char *service)
{
  struct termios termio2, termio;
  if(!isatty(0)) {
    fprintf(stderr, "stdin is not a tty\n");
    exit(1);
  }

  printf("* Exit with ^B\n");

  mbus_seqpkt_con_t *msc = mbus_seqpkt_connect(m, target_addr, service);

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
  pthread_create(&tid, NULL, send_thread, msc);

  while(1) {

    void *data;
    ssize_t result = mbus_seqpkt_recv(msc, &data);

    if(result <= 0)
      break;

    int x = write(1, data, result);
    free(data);
    if(x != result)
      break;

  }

  pthread_cancel(tid);
  pthread_join(tid, NULL);

  tcsetattr(0, TCSANOW, &termio);

  mbus_seqpkt_close(msc, 0);

  printf("\n* Disconnected\n");
  return 0;
}


const char level2str[8][7] = {
  "EMERG ",
  "ALERT ",
  "CRIT  ",
  "ERROR ",
  "WARN  ",
  "NOTICE",
  "INFO  ",
  "DEBUG "
};

static int64_t
wallclock(void)
{
  struct timespec tv;
  clock_gettime(CLOCK_REALTIME, &tv);
  return (int64_t)tv.tv_sec * 1000000LL + (tv.tv_nsec / 1000);
}


mbus_error_t
mbus_remote_log(mbus_t *m, uint8_t target_addr)
{
  uint32_t expected_seq = 0;

  while(1) {
    mbus_seqpkt_con_t *msc = mbus_seqpkt_connect(m, target_addr, "log");

    uint32_t current_seq = 0;
    while(1) {
      void *data;
      ssize_t len = mbus_seqpkt_recv(msc, &data);
      if(len <= 0)
        break;

      const uint8_t *buf = data;
      const uint8_t *end = data + len;
      const uint8_t hdr = *buf++;

      if(hdr & 0x40) {
        if(buf + 4 > end) {
          free(data);
          break;
        }

        // Discontinuity
        memcpy(&current_seq, buf, 4);
        buf += 4;
      } else {
        current_seq++;
      }

      uint8_t tslen = (hdr >> 3) & 0x7;
      uint64_t tsdelta = 0;
      for(int i = 0; i < tslen; i++) {
        if(buf >= end) {
          free(data);
          break;
        }
        tsdelta |= *buf << (i * 8);
        buf++;
      }

      if(buf > end) {
        free(data);
        break;
      }
      const uint8_t level = hdr & 0x7;
      const size_t msglen = end - buf;

      if(expected_seq != current_seq) {
        printf(" *** LOG DISCONTINUITY ***  Got sequence %u, expected %u\n",
               current_seq, expected_seq);
      }

      int64_t ts = wallclock() - tsdelta * 1000;

      time_t sec = ts / 1000000LL;
      uint32_t usec = ts % 1000000LL;

      struct tm tm;
      localtime_r(&sec, &tm);

      printf("%02d:%02d:%02d.%03d  %s %.*s\n",
             tm.tm_hour,
             tm.tm_min,
             tm.tm_sec,
             usec / 1000,
             level2str[level], (int)msglen, (const char *)buf);
      expected_seq = current_seq + 1;
      free(data);
    }
    mbus_seqpkt_close(msc, 0);
    printf(" *** LOG DISCONNECT ***\n");
    sleep(1);
  }

  return 0;
}
