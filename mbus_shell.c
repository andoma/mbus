#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>
#include <sys/ioctl.h>


static struct termios termio;

/**
 *
 */
static void
terminal(int hex_mode)
{
  struct termios termio2;
  uint8_t buf[64];

  printf("Exit with ^B\n");

  if(!isatty(0)) {
    fprintf(stderr, "stdin is not a tty\n");
    exit(1);
  }
  if(tcgetattr(0, &termio) == -1) {
    perror("tcgetattr");
    exit(1);
  }
  termio2 = termio;
  termio2.c_lflag &= ~(ECHO | ICANON | ISIG);
  if(1) {
    if(tcsetattr(0, TCSANOW, &termio2) == -1)
      return;
  }

  struct pollfd fds[2];

  fds[0].fd = 0;
  fds[1].fd = fd;
  fds[0].events = POLLIN | POLLHUP;
  fds[1].events = POLLIN | POLLHUP;

  while(1) {
    poll(fds, 2, -1);

    if(fds[0].revents & (POLLERR | POLLHUP))
      break;
    if(fds[1].revents & (POLLERR | POLLHUP))
      break;

    if(fds[0].revents & POLLIN) {
      if(read(0, buf, 1) != 1) {
        perror("read");
        break;
      }
      if(buf[0] == 2)
        break;

      if(write(fd, buf, 1) != 1) {
        perror("write");
        break;
      }

    }

    if(fds[1].revents & POLLIN) {
      int r = read(fd, buf, 1);
      if(r == 0) {
        break;
      }
      if(r < 0) {
        perror("read");
        break;
      }
      if(hex_mode) {
        char hex[8];
        snprintf(hex, sizeof(hex), "%02x '%c'\n", buf[0],
                 buf[0] >= 32 && buf[0] < 128 ? buf[0] : '.');
        if(write(1, hex, 7) != 7) {
          perror("write");
          break;
        }

      } else {
        if(write(1, buf, 1) != 1) {
          perror("write");
          break;
        }
      }
    }
  }


  tcsetattr(0, TCSANOW, &termio);
  printf("Exiting...\n");
  exit(0);
}



int
main(int argc, char **argv)
{
  const char *device = "/dev/ttyUSB0";
  int baudrate = 115200;
  char *hostport = NULL;
  int toggle_dtr = 0;
  int toggle_rts = 0;
  int enable_rts = 0;
  int hex_mode = 0;
  int opt;

  while((opt = getopt(argc, argv, "d:b:RDhHc:r")) != -1) {
    switch(opt) {
    case 'b':
      baudrate = atoi(optarg);
      break;
    case 'd':
      device = optarg;
      break;
    case 'R':
      toggle_rts = 1;
      break;
    case 'r':
      enable_rts = 1;
      break;
    case 'D':
      toggle_dtr = 1;
      break;
    case 'H':
      hex_mode = 1;
      break;
    case 'c':
      hostport = optarg;
      break;
    case 'h':
      usage(argv[0]);
      exit(0);
    default:
      usage(argv[0]);
      exit(1);
    }
  }

  if(hostport != NULL) {

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1) {
      perror("socket");
      exit(1);
    }

    int port = 3000;

    char *portstr = strchr(hostport, ':');
    if(portstr != NULL) {
      port = atoi(portstr + 1);
      *portstr = 0;
    }

    struct sockaddr_in sin = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
      .sin_addr.s_addr = inet_addr(hostport)
    };

    if(connect(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
      perror("connect");
      exit(1);
    }
    terminal(hex_mode);
    return 0;
  }


  fd = open(device, O_RDWR | O_NOCTTY);
  if(fd == -1) {
    perror("open serial port");
    exit(1);
  }

   setupdev(baudrate);

   if(toggle_dtr) {
     // Turn on DTR
     printf("Toggle DTR\n");
     int f = TIOCM_DTR;
     ioctl(fd, TIOCMBIC, &f);
     usleep(1000);
     ioctl(fd, TIOCMBIS, &f);
   }

   if(toggle_rts) {
     // Turn on RTS
     printf("Toggle RTS\n");
     int f = TIOCM_RTS;
     ioctl(fd, TIOCMBIS, &f);
     usleep(1000);
     ioctl(fd, TIOCMBIC, &f);
   }

   if(enable_rts) {
     // Turn on RTS
     printf("Enable RTS\n");
     int f = TIOCM_RTS;
     ioctl(fd, TIOCMBIS, &f);
   } else {
     int f = TIOCM_RTS;
     ioctl(fd, TIOCMBIC, &f);
   }

   terminal(hex_mode);
   return 0;
}
