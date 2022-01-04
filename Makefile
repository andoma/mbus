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

LDFLAGS += -lusb-1.0 -lpthread

test: Makefile mbus.h ${SRCS}
	gcc -O2 -Wall -Werror -o $@ ${SRCS} ${LDFLAGS}
