FROM tsaridas/stremio-docker@sha256:0f33301d0c7fcda21408cbd9923b67393ff2866d3896028bd3d69283a18fdb68

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
