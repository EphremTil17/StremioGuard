FROM tsaridas/stremio-docker@sha256:fc38cf30d4228ef4bd58d27e1f6ddbdb4e33e0f0dab969322f8d0a619ec71252

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi
