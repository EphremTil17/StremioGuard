#!/usr/bin/env node

// Patches against the bundled, minified server.js shipped inside
// tsaridas/stremio-docker. Anchors are literal substrings of webpack output,
// so they are sensitive to upstream rebuilds. The base image is pinned by
// digest in Dockerfile to keep these stable; bumping the digest may require
// re-deriving anchors.
//
// Patches are split into two tiers with different failure semantics:
//
//   ESSENTIAL — required for playback through the external proxy. A missing
//   anchor here is a hard build failure: shipping without these silently
//   breaks mobile playback (mediaURL self-fetch loop, redirect host mismatch).
//
//   COSMETIC — UX polish only (log noise, favicon 404s, casting nag). A
//   missing anchor here logs a warning and continues. Worst case after
//   upstream drift: noisier logs / casting nag returns until anchors are
//   refreshed. Playback is unaffected.

const fs = require("fs");

const path = "/srv/stremio-server/server.js";
let source = fs.readFileSync(path, "utf8");

// --- ESSENTIAL: load-bearing for playback through external proxy ---------
const ESSENTIAL_PATCHES = [
  {
    name: "inject media url normalizer",
    from: "const router = new Router, converters = new Map;",
    to: `const router = new Router, converters = new Map, forwardedValue = value => "string" == typeof value ? value.split(",")[0].trim() : "", requestExternalOrigin = (req, protocol = "") => {
            if (!req || !req.headers) return "";
            const forwardedProto = forwardedValue(req.headers["x-forwarded-proto"]);
            const forwardedHost = forwardedValue(req.headers["x-forwarded-host"]) || req.headers.host || "";
            if (forwardedProto && forwardedHost) return forwardedProto + "://" + forwardedHost;
            return protocol && req.headers.host ? protocol + req.headers.host : "";
        }, normalizeMediaURL = (mediaURL, req, protocol = "") => {
            if ("string" != typeof mediaURL || 0 === mediaURL.length) return mediaURL;
            const internalBase = (process.env.INTERNAL_MEDIA_BASE_URL || "").replace(/\\/$/, "");
            const configuredExternalBase = (process.env.EXTERNAL_BASE_URL || "").replace(/\\/$/, "");
            const requestBase = requestExternalOrigin(req, protocol).replace(/\\/$/, "");
            if (!internalBase) return mediaURL;
            for (const externalBase of [configuredExternalBase, requestBase]) {
                if (externalBase && mediaURL.startsWith(externalBase)) return internalBase + mediaURL.slice(externalBase.length);
            }
            return mediaURL;
        };`,
  },
  {
    name: "normalize converter media url",
    from: "mediaURL: req.query.mediaURL,",
    to: "mediaURL: normalizeMediaURL(req.query.mediaURL, req, protocol),",
  },
  {
    name: "normalize hls probe media url",
    from: "mediaURL: req.query.mediaURL\n                });",
    to: "mediaURL: normalizeMediaURL(req.query.mediaURL, req, protocol)\n                });",
  },
  {
    name: "derive streaming server url from forwarded request origin",
    from: 'var serverUrl = encodeURIComponent(protocol + req.headers.host), sep = webUILocation.includes("?") ? "&" : "?", location = webUILocation + sep + "streamingServer=" + serverUrl;',
    to: 'var configuredServerUrl = (process.env.EXTERNAL_BASE_URL || "").replace(/\\/$/, ""), forwardedProto = "string" == typeof req.headers["x-forwarded-proto"] ? req.headers["x-forwarded-proto"].split(",")[0].trim() : "", forwardedHost = "string" == typeof req.headers["x-forwarded-host"] ? req.headers["x-forwarded-host"].split(",")[0].trim() : "", detectedServerUrl = forwardedProto && forwardedHost ? forwardedProto + "://" + forwardedHost : "", serverUrl = encodeURIComponent(detectedServerUrl || configuredServerUrl || protocol + req.headers.host), sep = webUILocation.includes("?") ? "&" : "?", location = webUILocation + sep + "streamingServer=" + serverUrl;',
  },
];

// --- COSMETIC: UX polish, safe to drop on upstream drift ------------------
const COSMETIC_PATCHES = [
  {
    name: "skip noisy hardware probe",
    from: "hwAccelProfiler(port, onHardwareAcceleration);",
    to: "if (process.env.STREMIO_SKIP_HW_PROBE) { onHardwareAcceleration([]); } else { hwAccelProfiler(port, onHardwareAcceleration); }",
  },
  {
    name: "ignore favicon path lookups",
    from: '        })), enginefs.router.use("/proxy", proxy.getRouter());',
    to: '        })), enginefs.router.get("/favicon.ico", ((req, res) => {\n            res.writeHead(204), res.end();\n        })), enginefs.router.get("/favicons/favicon.ico", ((req, res) => {\n            res.writeHead(204), res.end();\n        })), enginefs.router.use("/proxy", proxy.getRouter());',
  },
  {
    name: "return empty casting list when casting is disabled",
    from: `        })), !process.env.CASTING_DISABLED && "android" !== process.platform) {
            console.log("Enabling casting...");
            var casting = new (__webpack_require__(944))(executables);
            enginefs.router.use("/casting/", casting.middleware);
        }`,
    to: `        })), !process.env.CASTING_DISABLED && "android" !== process.platform) {
            console.log("Enabling casting...");
            var casting = new (__webpack_require__(944))(executables);
            enginefs.router.use("/casting/", casting.middleware);
        }
        process.env.CASTING_DISABLED && enginefs.router.get("/casting", (function(req, res) {
            res.writeHead(200, {
                "Content-Type": "application/json; charset=utf-8"
            }), res.end("[]");
        }));`,
  },
];

function applyPatch(patch, { required }) {
  if (!source.includes(patch.from)) {
    const msg = `Patch anchor not found: ${patch.name}`;
    if (required) {
      throw new Error(msg);
    }
    console.warn(`[patch-server] WARN: ${msg} (cosmetic, skipping)`);
    return;
  }
  source = source.replace(patch.from, patch.to);
}

for (const patch of ESSENTIAL_PATCHES) applyPatch(patch, { required: true });
for (const patch of COSMETIC_PATCHES) applyPatch(patch, { required: false });

fs.writeFileSync(path, source);
