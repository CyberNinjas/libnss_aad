FROM debian:9.7

RUN apt update && apt install -y \
        automake \
        autopoint \
        build-essential \
        cmake \
        git \
        indent \
        libcurl4-openssl-dev \
        libjansson-dev \
        libpam0g-dev \
        libsodium-dev \
        libssl-dev \
        libtool \
        pkg-config

WORKDIR /tmp
RUN git clone https://github.com/benmcollins/libjwt && \
    cd libjwt && git checkout tags/v1.10.1 && \
    autoreconf -i && ./configure && make && make install

WORKDIR /tmp
RUN git clone https://github.com/DaveGamble/cJSON libcjson && \
    cd libcjson && git checkout tags/v1.7.10 && \
    mkdir build && cd build && cmake .. && make && make install

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

WORKDIR /usr/src/libnss_aad
COPY . /usr/src/libnss_aad
RUN make depends && \
    LIB_DIR=/lib/x86_64-linux-gnu make -e install
