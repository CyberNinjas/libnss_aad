FROM ubuntu:18.04
ARG VERSION
ARG DEBVER

RUN echo "deb http://http.us.debian.org/debian sid main" \
        >> /etc/apt/sources.list && \
    apt update && apt install -y \
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
        libsodium-dev \
        libssl-dev \
        libtool \
        libxcrypt-dev \
        pkg-config \
        quilt

ENV SDSMIRROR="https://gitlab.com/oxr463/sds/-/jobs/210491217/artifacts/raw" \
    SDSVERSION="2.0.0" SDSDEBVERSION="2.0.0-1"
WORKDIR /tmp
RUN curl -LO "${SDSMIRROR}/libsds${SDSVERSION}_${SDSDEBVERSION}_amd64.deb" && \
    curl -LO "${SDSMIRROR}/libsds-dev_${SDSDEBVERSION}_amd64.deb" && \
    dpkg -i "libsds${SDSVERSION}_${SDSDEBVERSION}_amd64.deb" && \
    dpkg -i "libsds-dev_${SDSDEBVERSION}_amd64.deb"

WORKDIR /usr/src/libnss_aad
COPY . /usr/src/libnss_aad
RUN tar cvzf "../libnss-aad_${VERSION}.orig.tar.gz" --exclude='.git*' . && \
    debuild -us -uc -i'.git' && \
    dpkg -i "../libnss-aad_${VERSION}-${DEBVER}_amd64.deb"
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

WORKDIR /usr/src/libnss_aad
COPY . /usr/src/libnss_aad
RUN tar cvzf "../libnss-aad_${VERSION}.orig.tar.gz" --exclude='.git*' . && \
    debuild -us -uc -i'.git' && \
    dpkg -i "../libnss-aad_${VERSION}-${DEBVER}_amd64.deb"
