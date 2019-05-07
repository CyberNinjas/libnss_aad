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
        libpam0g-dev \
        libsodium-dev \
        libssl-dev \
        libtool \
        pkg-config \
        quilt

WORKDIR /tmp
RUN curl -Lo sds_2.0.0.orig.tar.gz \
    https://gitlab.com/oxr463/sds/-/archive/debian-2.0.0-1/sds-debian-2.0.0-1.tar.gz \
    && tar -xf sds_2.0.0.orig.tar.gz && \
    mv sds-debian-2.0.0-1 sds-2.0.0 && \
    cd sds-2.0.0 && debuild -us -uc && \
    dpkg -i ../libsds2.0.0_2.0.0-1_amd64.deb && \
    dpkg -i ../libsds-dev_2.0.0-1_amd64.deb

WORKDIR /usr/src/libnss_aad
COPY . /usr/src/libnss_aad
RUN tar cvzf ../libnss-aad_0.0.2.orig.tar.gz --exclude='.git*' . && \
    debuild -us -uc -i'(.git|linux-pam)' && \
    dpkg -i ../libnss-aad_0.0.2-1_amd64.deb
