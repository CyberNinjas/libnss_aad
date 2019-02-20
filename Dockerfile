FROM debian:9.7 as libjwt

RUN apt update && apt install -y \
        automake \
        build-essential \
        git \
        libjansson-dev \
        libssl-dev \
        libtool \
        pkg-config

WORKDIR /tmp
RUN git clone https://github.com/benmcollins/libjwt && \
    cd libjwt && git checkout tags/v1.10.1 && \
    autoreconf -i && ./configure && make && make install

FROM debian:9.7

WORKDIR /usr/src/libnss_aad
COPY . /usr/src/libnss_aad

COPY --from=libjwt /usr/local/lib /usr/local/lib
COPY --from=libjwt /usr/local/include /usr/local/include

RUN apt update && apt upgrade -y && \
    apt install -y gcc libcurl4-openssl-dev make && make
