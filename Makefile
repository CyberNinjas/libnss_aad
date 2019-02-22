CC = gcc
INDENT = indent
INSTALL = /usr/bin/install
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

prefix =
exec_prefix = ${prefix}

sysconfdir = /etc

all: libnss_aad

libnss_aad: $(NSS_SRC)
	${CC} ${CFLAGS} ${LDFLAGS} -fPIC -fno-stack-protector -Wall -shared -Wl,--export-dynamic \
		-o libnss_aad.so.2 -Wl,-soname,libnss_aad.so.2 libnss_aad.c -lcjson -lcurl -lm
check:
	@CFLAGS="${CFLAGS} -Wextra -Werror -Wno-sign-compare -fsyntax-only" make
	@echo "checking for errors... OK"

reformat:
	@VERSION_CONTROL=none $(INDENT) libnss_aad.c

clean: 
	rm -f libnss_aad.so.2
