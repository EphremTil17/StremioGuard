FROM tsaridas/stremio-docker@sha256:1ca6361bd7342171e12e00576b5694eb321b417901f3066e3385f5d51ad50786

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi
