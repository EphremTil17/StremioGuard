from __future__ import annotations

import json
from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching


def render_configure_template_override(
    repo_dir: Path,
    gateway_addon_base_url: str | None = None,
) -> str:
    template_file = repo_dir / "comet" / "templates" / "index.html"
    if not template_file.exists():
        raise RuntimeError(f"Comet configure template not found at {template_file}.")
    content = template_file.read_text(encoding="utf-8")

    prefix_marker = '          const stremioApiPrefix = {{ (stremioApiPrefix or "") | tojson }};\n'
    gateway_base_literal = json.dumps((gateway_addon_base_url or "").rstrip("/"))
    if "function getCometMountPath()" not in content:
        prefix_line = (
            '          const stremioApiPrefix = {{ (stremioApiPrefix or "") | tojson }};\n'
        )
        prefix_helper = (
            prefix_line
            + """          const cometConfiguredPublicBase = __GATEWAY_ADDON_BASE_URL__;

          function getCometMountPath() {
            const segments = window.location.pathname.split("/").filter(Boolean);
            const configureIndex = segments.lastIndexOf("configure");
            const cometIndex = segments.indexOf("comet");
            if (cometIndex < 0 || configureIndex <= cometIndex + 1) {
              return "";
            }
            return "/" + segments.slice(0, cometIndex + 2).join("/");
          }

          function getCometPublicBase() {
            const cometMountPath = getCometMountPath();
            if (cometMountPath) {
              if (cometConfiguredPublicBase && !cometConfiguredPublicBase.startsWith("/")) {
                return `${new URL(cometConfiguredPublicBase).origin}${cometMountPath}`;
              }
              return `${window.location.origin}${cometMountPath}`;
            }
            if (cometConfiguredPublicBase) {
              if (cometConfiguredPublicBase.startsWith("/")) {
                return `${window.location.origin}${cometConfiguredPublicBase}`;
              }
              return cometConfiguredPublicBase;
            }
            return window.location.origin;
          }

          function getCometInstallBase(host, cometMountPath) {
            if (cometMountPath) {
              if (cometConfiguredPublicBase && !cometConfiguredPublicBase.startsWith("/")) {
                return `${new URL(cometConfiguredPublicBase).host}${cometMountPath}`;
              }
              return `${host}${cometMountPath}`;
            }
            if (!cometConfiguredPublicBase) {
              return host;
            }
            if (cometConfiguredPublicBase.startsWith("/")) {
              return `${host}${cometConfiguredPublicBase}`;
            }
            const url = new URL(cometConfiguredPublicBase);
            return `${url.host}${url.pathname.replace(/\\/$/, "")}`;
          }
"""
        )
        prefix_helper = prefix_helper.replace("__GATEWAY_ADDON_BASE_URL__", gateway_base_literal)
        if prefix_marker not in content:
            raise RuntimeError(
                "Unable to apply managed Comet configure-template patch; upstream "
                "stremioApiPrefix marker has changed."
            )
        content = content.replace(prefix_marker, prefix_helper, 1)

    host_line = "            const host = window.location.host;"
    host_replacement = (
        "            const host = window.location.host;\n"
        "            const cometMountPath = getCometMountPath();\n"
        "            const cometInstallBase = getCometInstallBase(host, cometMountPath);"
    )
    content = replace_first_matching(
        content,
        ((host_line, host_replacement),),
        error=(
            "Unable to apply managed Comet configure-template patch; upstream "
            "host variable marker has changed."
        ),
        expected=1,
    )
    url_replacements: tuple[tuple[str, str, int | None], ...] = (
        (
            "`stremio://${host}${stremioApiPrefix}/manifest.json`",
            "`stremio://${cometInstallBase}${stremioApiPrefix}/manifest.json`",
            1,
        ),
        (
            "`stremio://${host}${stremioApiPrefix}/${settingsString}/manifest.json`",
            "`stremio://${cometInstallBase}${stremioApiPrefix}/${settingsString}/manifest.json`",
            1,
        ),
        (
            "`${window.location.origin}${stremioApiPrefix}/manifest.json`",
            "`${getCometPublicBase()}${stremioApiPrefix}/manifest.json`",
            None,
        ),
        (
            "`${window.location.origin}${stremioApiPrefix}/${settingsString}/manifest.json`",
            "`${getCometPublicBase()}${stremioApiPrefix}/${settingsString}/manifest.json`",
            None,
        ),
    )
    for before, after, expected in url_replacements:
        content = replace_first_matching(
            content,
            ((before, after),),
            error=(
                "Unable to apply managed Comet configure-template patch; upstream "
                f"manifest URL template changed: {before}"
            ),
            expected=expected,
        )
    return content
