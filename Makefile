CC = gcc
INSTALL = /usr/bin/install
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

prefix =
exec_prefix = ${prefix}

sysconfdir = /etc

all: libnss_aad

libnss_aad: $(NSS_SRC)
	${CC} ${CFLAGS} ${LDFLAGS} -fPIC -fno-stack-protector -Wall -shared -Wl,--export-dynamic \
		-o libnss_aad.so.2 -Wl,-soname,libnss_aad.so.2 libnss_aad.c sds.c -lcjson -lcurl -lm
check:
	@ CFLAGS="${CFLAGS} -Wextra -Werror" make

clean: 
	rm -f libnss_aad.so.2
