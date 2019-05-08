PREFIX = /usr/local
LIB_DIR = ${PREFIX}/lib

all: dlopen 

dlopentest:
	${CC} ${CFLAGS} ${LDFLAGS} -fPIE -fstack-protector -Wall -o $@ $@.c -ldl

dlopen: dlopentest
	./dlopentest "${LIB_DIR}/libnss_aad.so.2"
