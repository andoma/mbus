SRCS += \
	mbus.c \
	mbus_usb.c \
	mbus_serial.c \
	mbus_elfloader.c \
	mbus_gateway.c \
	mbus_tcp.c \
	pcs/pcs.c \
	remote_shell.c \
	main.c

CFLAGS += ${shell pkg-config --cflags libusb-1.0}
LDFLAGS += ${shell pkg-config --libs libusb-1.0}

LDFLAGS += -lpthread

test: Makefile mbus.h ${SRCS}
	gcc -O2 -g -Wall -Werror -o $@ ${CFLAGS} ${SRCS} ${LDFLAGS}
