#!/usr/bin/env node

const fs = require("fs");

const path = "/srv/stremio-server/server.js";
let source = fs.readFileSync(path, "utf8");

const replacements = [
  {
    name: "skip noisy hardware probe",
    from: "hwAccelProfiler(port, onHardwareAcceleration);",
    to: "if (process.env.STREMIO_SKIP_HW_PROBE) { onHardwareAcceleration([]); } else { hwAccelProfiler(port, onHardwareAcceleration); }",
  },
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

for (const replacement of replacements) {
  if (!source.includes(replacement.from)) {
    throw new Error(`Patch anchor not found: ${replacement.name}`);
  }
  source = source.replace(replacement.from, replacement.to);
}

fs.writeFileSync(path, source);
