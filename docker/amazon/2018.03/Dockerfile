FROM amazonlinux:2018.03

RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm \
    && yum update -y && yum group install -y 'Development Tools' \
    && yum install -y \
        autopoint \
        cmake \
        git \
        indent \
        libcurl-devel \
        jansson-devel \
        pam-devel \
        openssl-devel

WORKDIR /tmp
RUN git clone https://github.com/benmcollins/libjwt && \
    cd libjwt && git checkout tags/v1.10.1 && \
    autoreconf -i && ./configure && make && make install

# See: https://github.com/antirez/sds/issues/97
WORKDIR /tmp
RUN git clone https://github.com/antirez/sds libsds && \
    cd libsds && git checkout tags/2.0.0 && \
    echo "typedef int sdsvoid;" >> sdsalloc.h && \
    gcc -fPIC -fstack-protector -std=c99 -pedantic -Wall \
        -Werror -shared -o libsds.so.2.0.0 -Wl,-soname=libsds.so.2.0.0 \
        sds.c sds.h sdsalloc.h && \
    cp -a libsds.so.2.0.0 /usr/local/lib/ && \
    ln -s /usr/local/lib/libsds.so.2.0.0 /usr/local/lib/libsds.so && \
    ln -s /usr/local/lib/libsds.so.2.0.0 /usr/local/lib/libsds.so.2 && \
    mkdir -p /usr/local/include/sds && cp -a sds.h /usr/local/include/sds/

WORKDIR /tmp
RUN git clone https://github.com/jedisct1/libsodium && \
    cd libsodium && git checkout tags/1.0.17 && \
    ./autogen.sh && ./configure && make && make check && make install

WORKDIR /usr/src/libnss_aad
COPY . /usr/src/libnss_aad
RUN git submodule update --init --recursive && \
    cd linux-pam && git checkout tags/Linux-PAM-1_1_8 && \
    ./autogen.sh && ./configure --disable-regenerate-docu && \
    cd .. && patch linux-pam/modules/pam_unix/passverify.c \
      .patches/0001-Remove-static-keyword-from-crypt_make_salt.patch && \
    LIB_DIR=/lib64 make -e install
