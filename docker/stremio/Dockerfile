FROM tsaridas/stremio-docker@sha256:f93826539d0607a662b7cfdeeb56a364abdb6cbc02e32b14f0e3179c7674ac31

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi
