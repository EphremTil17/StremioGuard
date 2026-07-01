FROM tsaridas/stremio-docker@sha256:92cb1be2da2299bf3ea9bc41730918a57af4de62b4360f34b7bfce4935868d1e

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi
