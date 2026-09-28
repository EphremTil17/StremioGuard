FROM tsaridas/stremio-docker@sha256:27e6f2a3e31b8ed598524acaa5717b448a30533defef9066dc92443288ba1379

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi
