CC = gcc
INDENT = indent
INSTALL = /usr/bin/install
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

SRC_DIR = .

PAM_DEPS = -I${SRC_DIR}/linux-pam
PAM_DEPS += -I${SRC_DIR}/linux-pam/modules/pam_unix
PAM_DEPS += linux-pam/modules/pam_unix/bigcrypt.c
PAM_DEPS += linux-pam/modules/pam_unix/passverify.c

PREFIX = /usr/local
LIB_DIR = ${PREFIX}/lib

all: libnss_aad

depends:
	@git submodule update --init --recursive
	@cd linux-pam && ./autogen.sh && \
		./configure --disable-regenerate-docu
	@patch linux-pam/modules/pam_unix/passverify.c \
		.patches/0001-Remove-static-keyword-from-crypt_make_salt.patch

libnss_aad:
	${CC} ${CFLAGS} ${LDFLAGS} -I${SRC_DIR} -fPIC -fno-stack-protector -Wall \
		-shared -Wl,--export-dynamic -o libnss_aad.so.2 -Wl,-soname,libnss_aad.so.2 \
		libnss_aad.c -lcjson -lcrypt -lcurl -lm -lsds -lsodium ${PAM_DEPS}

check:
	@CFLAGS="${CFLAGS} -Wextra -Werror -Wno-sign-compare -fsyntax-only" make
	@echo "checking for errors... OK"

reformat:
	@VERSION_CONTROL=none $(INDENT) libnss_aad.c

install: libnss_aad
	${INSTALL_DATA} libnss_aad.so.2 ${LIB_DIR}

clean: 
	rm -f libnss_aad.so.2

clean-all: clean
	@make -C linux-pam maintainer-clean
	@cd linux-pam && git reset --h
