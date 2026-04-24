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
    to: `const router = new Router, converters = new Map, normalizeMediaURL = mediaURL => {
            if ("string" != typeof mediaURL || 0 === mediaURL.length) return mediaURL;
            const internalBase = (process.env.INTERNAL_MEDIA_BASE_URL || "").replace(/\\/$/, "");
            const externalBase = (process.env.EXTERNAL_BASE_URL || "").replace(/\\/$/, "");
            return internalBase && externalBase && mediaURL.startsWith(externalBase) ? internalBase + mediaURL.slice(externalBase.length) : mediaURL;
        };`,
  },
  {
    name: "normalize converter media url",
    from: "mediaURL: req.query.mediaURL,",
    to: "mediaURL: normalizeMediaURL(req.query.mediaURL),",
  },
  {
    name: "normalize hls probe media url",
    from: "mediaURL: req.query.mediaURL\n                });",
    to: "mediaURL: normalizeMediaURL(req.query.mediaURL)\n                });",
  },
  {
    name: "force external streaming server url on redirect",
    from: 'var serverUrl = encodeURIComponent(protocol + req.headers.host), sep = webUILocation.includes("?") ? "&" : "?", location = webUILocation + sep + "streamingServer=" + serverUrl;',
    to: 'var configuredServerUrl = (process.env.EXTERNAL_BASE_URL || "").replace(/\\/$/, ""), serverUrl = encodeURIComponent(configuredServerUrl || protocol + req.headers.host), sep = webUILocation.includes("?") ? "&" : "?", location = webUILocation + sep + "streamingServer=" + serverUrl;',
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
