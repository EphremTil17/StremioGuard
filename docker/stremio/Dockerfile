FROM tsaridas/stremio-docker@sha256:0f33301d0c7fcda21408cbd9923b67393ff2866d3896028bd3d69283a18fdb68

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi
