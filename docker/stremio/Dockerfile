FROM tsaridas/stremio-docker@sha256:e1da3d3702082a107c03e1b428554749e39ac31559a1ff933e2c7b61390f83d9

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi
