# Build mod_livetranslate using pre-built FreeSWITCH image
FROM ghcr.io/patrickbaus/freeswitch-docker:1.10.12-3 AS builder

USER root

# Install build dependencies (Alpine-based image)
RUN apk add --no-cache \
    build-base \
    pkgconf \
    speexdsp-dev \
    libwebsockets-dev \
    openssl-dev

# Copy module source
WORKDIR /build/mod_livetranslate
COPY mod_livetranslate.h .
COPY mod_livetranslate.c .
COPY ws_client.h .
COPY ws_client.c .
COPY Makefile .

# Build module
RUN make clean || true && make

# Output stage - use busybox for docker create compatibility
FROM busybox:musl
COPY --from=builder /build/mod_livetranslate/mod_livetranslate.so /
