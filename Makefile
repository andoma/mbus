include mk/$(shell uname -s).mk

SRCS += \
	mbus.c \
	mbus_usb.c \
	mbus_elfloader.c \
	mbus_gateway.c \
	mbus_tcp.c \
	mbus_seqpkt.c \
	mbus_gd.c \
	mbus_ota.c \
	mbus_xfer.c \
	remote_shell.c \
	main.c

CFLAGS += ${shell pkg-config --cflags libusb-1.0 libelf} -DHAVE_BLE
LDFLAGS += ${shell pkg-config --libs libusb-1.0 libelf}

#CFLAGS += -fsanitize=address

LDFLAGS += -lpthread

mbus: Makefile mbus.h mbus_i.h ${SRCS}
	gcc -O2 -g -Wall -Werror -o $@ ${CFLAGS} ${SRCS} ${LDFLAGS}
