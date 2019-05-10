FROM debian:9.7

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
        libcjson-dev \
        libcurl4-openssl-dev \
        libjansson-dev \
        libjwt-dev \
        libsodium-dev \
        libssl-dev \
        libtool \
        libxcrypt-dev \
        pkg-config \
        quilt

ENV SDSMIRROR "https://gitlab.com/oxr463/sds/-/jobs/210491217/artifacts/raw" 
WORKDIR /tmp
RUN curl -LO "${SDSMIRROR}/libsds2.0.0_2.0.0-1_amd64.deb" && \
    curl -LO "${SDSMIRROR}/libsds-dev_2.0.0-1_amd64.deb" && \
    dpkg -i libsds2.0.0_2.0.0-1_amd64.deb && \
    dpkg -i libsds-dev_2.0.0-1_amd64.deb

WORKDIR /usr/src/libnss_aad
COPY . /usr/src/libnss_aad
RUN tar cvzf ../libnss-aad_0.0.2.orig.tar.gz --exclude='.git*' . && \
    debuild -us -uc -i'.git' && \
    dpkg -i ../libnss-aad_0.0.2-1_amd64.deb
