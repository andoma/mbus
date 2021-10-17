SRCS += mbus.c mbus_usb.c mbus_serial.c mbus_elfloader.c main.c

LDFLAGS += -lusb-1.0 -lpthread

test: Makefile mbus.h ${SRCS}
	gcc -O2 -Wall -Werror -o $@ ${SRCS} ${LDFLAGS}
