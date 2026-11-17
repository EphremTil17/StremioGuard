#!/usr/bin/env node

// Security hardening for edge cases: the image's nginx serves raw torrent
// streams (/<infohash>/<file index>) without basic auth, because players
// cannot send credentials, and the server starts a torrent for any infohash
// such a request names. So anyone who could reach the port could make the
// server download any torrent.
//
// With this gate a raw stream is served with valid basic auth, or for a
// torrent that already exists on the server. Torrents are only started
// through authenticated routes (/<infohash>/create, the web UI), so an
// unauthenticated request can only play what a signed-in client started.
//
// Without basic auth configured (no USERNAME/PASSWORD), or with
// STREMIO_OPEN_RAW_STREAMS=1, the check always passes: upstream behaviour.
//
// Unlike patch-server.js, this runs whatever STREMIO_APPLY_PATCHES says, and
// every anchor is required: a missing one fails the build.

const fs = require("fs");

const SERVER = "/srv/stremio-server/server.js";
// default.conf serves HTTP; the entrypoint copies https.conf over it when the
// image's own HTTPS is configured, so both carry the gate.
const NGINX_CONFIGS = ["/etc/nginx/http.d/default.conf", "/etc/nginx/https.conf"];
const CHECK_PATH = "stremioguard-engine-exists";

// The raw route as upstream ships it; the file-index pattern has been both
// `[0-9]+` and `-?[0-9]+` (-1: "largest file"), and is kept as found.
const RAW_LOCATION = new RegExp(
  String.raw`    location ~ "\^/\(\[a-zA-Z0-9\]\{40\}\)/\((-\?)?\[0-9\]\+\)\$" \{\n` +
    String.raw`        # doesn't work with auth\n` +
    String.raw`        # include /etc/nginx/auth\.conf;\n` +
    String.raw`        proxy_pass http://backend;\n` +
    String.raw`    \}`,
  "g",
);

function gatedLocation(negativeIndex) {
  const index = negativeIndex ? "-?[0-9]+" : "[0-9]+";
  return `    # StremioGuard: a raw stream needs basic auth, or a torrent that already
    # exists (players cannot send credentials; torrents start only through
    # authenticated routes). See docker/stremio/gate-raw-streams.js.
    location ~ "^/([a-zA-Z0-9]{40})/(${index})$" {
        set $stremioguard_infohash $1;
        satisfy any;
        include /etc/nginx/auth.conf;
        auth_request /_stremioguard/engine-exists;
        proxy_pass http://backend;
    }

    location = /_stremioguard/engine-exists {
        internal;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_pass http://backend/$stremioguard_infohash/${CHECK_PATH};
    }`;
}

const ROUTE_ANCHOR = 'router.get("/:infoHash/:idx", sendDLNAHeaders, handleTorrent)';
// Registered before /:infoHash/:idx, which would otherwise match it first.
const ROUTE_GATED = `router.get("/:infoHash/${CHECK_PATH}", (function(req, res) {
        var gated = !!(process.env.USERNAME && process.env.PASSWORD) && !/^(?:1|true|yes|on)$/i.test((process.env.STREMIO_OPEN_RAW_STREAMS || "").trim());
        res.writeHead(!gated || existsEngine(req.params.infoHash) ? 204 : 403), res.end();
    })), ${ROUTE_ANCHOR}`;

function replaceOnce(text, from, to, where) {
  const count = text.split(from).length - 1;
  if (count !== 1) {
    throw new Error(`gate-raw-streams: expected one anchor in ${where}, found ${count}`);
  }
  return text.replace(from, () => to);
}

const server = fs.readFileSync(SERVER, "utf8");
if (!server.includes("function existsEngine(infoHash)")) {
  throw new Error("gate-raw-streams: server.js no longer defines existsEngine");
}
fs.writeFileSync(SERVER, replaceOnce(server, ROUTE_ANCHOR, ROUTE_GATED, SERVER));

for (const path of NGINX_CONFIGS) {
  const config = fs.readFileSync(path, "utf8");
  const found = config.match(RAW_LOCATION) || [];
  if (found.length !== 1) {
    throw new Error(`gate-raw-streams: expected one raw stream location in ${path}, found ${found.length}`);
  }
  const negativeIndex = found[0].includes("(-?[0-9]+)");
  fs.writeFileSync(path, config.replace(RAW_LOCATION, () => gatedLocation(negativeIndex)));
}

console.log("[gate-raw-streams] raw stream gate installed");
