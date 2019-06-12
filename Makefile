CC = gcc
INDENT = indent
INSTALL = /usr/bin/install
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

SRC_DIR = .

PREFIX = /usr/local
LIB_DIR = ${PREFIX}/lib

all: libnss_aad

libnss_aad:
	${CC} ${CFLAGS} ${LDFLAGS} -I${SRC_DIR} -fPIC -fno-stack-protector -Wall \
		-shared -Wl,--export-dynamic -o libnss_aad.so.2 -Wl,-soname,libnss_aad.so.2 \
		libnss_aad.c -lcrypt -lcurl -ljansson -lm -lsds -lsodium -lxcrypt

check:
	@CFLAGS="${CFLAGS} -Wextra -Werror -Wno-sign-compare -fsyntax-only" make
	@echo "checking for errors... OK"

debug:
	@LDFLAGS="${LDFLAGS} -ggdb" make

reformat:
	@VERSION_CONTROL=none $(INDENT) libnss_aad.c

install: libnss_aad
	${INSTALL_DATA} libnss_aad.so.2 ${LIB_DIR}

clean: 
	@rm -f libnss_aad.so.2 *.deb
