FROM tsaridas/stremio-docker@sha256:f0de8290286b08e1c98ac875cba5c2ec62c6603f2b81b444ff850f63c2810eda

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi
