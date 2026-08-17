FROM tsaridas/stremio-docker@sha256:5a73b49e0a09a71b29a30b2e5c746f6a77fad274e0fbbe1fa7be6727f1453624

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi
