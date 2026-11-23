FROM tsaridas/stremio-docker@sha256:4e14aefecf87c5ecea8a1fb4adac2a57b248a5be8ce3948eea74bdcb6f454a43

ARG STREMIO_APPLY_PATCHES=1

COPY docker/stremio/patch-server.js /tmp/patch-server.js
COPY docker/stremio/gate-raw-streams.js /tmp/gate-raw-streams.js

RUN if [ "${STREMIO_APPLY_PATCHES}" = "1" ]; then \
      node /tmp/patch-server.js; \
    fi

# Security hardening, applied whatever STREMIO_APPLY_PATCHES says; the build
# fails if the image's nginx or server no longer match. `nginx -t` proves the
# patched config loads (with auth configured, as at runtime).
RUN node /tmp/gate-raw-streams.js \
    && printf 'auth_basic "Restricted Content";\nauth_basic_user_file /etc/nginx/.htpasswd;\n' > /etc/nginx/auth.conf \
    && nginx -t \
    && : > /etc/nginx/auth.conf \
    && nginx -t
