FROM ubuntu:18.04

RUN apt update && apt install -y \
        software-properties-common && \
    add-apt-repository -y ppa:lramage/sds && \
    add-apt-repository -y ppa:jnchi/ppa

RUN apt update && apt install -y \
        automake \
        autopoint \
        build-essential \
        cmake \
        curl \
        debhelper \
        devscripts \
        git \
        indent \
        libcurl4-openssl-dev \
        libjansson-dev \
        libjwt-dev \
        libsds-dev \
        libsodium-dev \
        libssl-dev \
        libtool \
        libxcrypt-dev \
        pkg-config \
        quilt

ENV NSSAADVERSION="0.0.3" NSSAADDEBVERSION="0.0.3-1"
WORKDIR /usr/src/libnss_aad
COPY . /usr/src/libnss_aad
RUN tar cvzf "../libnss-aad_${NSSAADVERSION}.orig.tar.gz" --exclude='.git*' . && \
    debuild -us -uc -i'.git' && \
    dpkg -i "../libnss-aad_${NSSAADDEBVERSION}_amd64.deb"
