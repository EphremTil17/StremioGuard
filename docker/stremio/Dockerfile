FROM tsaridas/stremio-docker@sha256:283d35e905a1a0a90db0ec36d667af3203980afb80790feed3e5e2bff5e3e6af

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi
