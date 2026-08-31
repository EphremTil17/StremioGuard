FROM tsaridas/stremio-docker@sha256:a762350aeab1b5c1d0156855644fdc0b84cdcd9a23b50e24b731c71a00ee4a0a

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi
