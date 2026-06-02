from __future__ import annotations

import json
from pathlib import Path


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
            if (cometIndex < 0 || configureIndex < 0 || cometIndex >= configureIndex) {
              return "";
            }
            return "/" + segments.slice(0, cometIndex + 1).join("/");
          }

          function getCometPublicBase() {
            if (cometConfiguredPublicBase) {
              if (cometConfiguredPublicBase.startsWith("/")) {
                return `${window.location.origin}${cometConfiguredPublicBase}`;
              }
              return cometConfiguredPublicBase;
            }
            return `${window.location.origin}${getCometMountPath()}`;
          }

          function getCometInstallBase(host, cometMountPath) {
            if (!cometConfiguredPublicBase) {
              return `${host}${cometMountPath}`;
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
        "            const cometPublicBase = getCometPublicBase();\n"
        "            const cometInstallBase = getCometInstallBase(host, cometMountPath);"
    )
    if host_replacement not in content:
        content = content.replace(host_line, host_replacement)
    content = content.replace(
        "`stremio://${host}${stremioApiPrefix}/manifest.json`",
        "`stremio://${cometInstallBase}${stremioApiPrefix}/manifest.json`",
    )
    content = content.replace(
        "`stremio://${host}${stremioApiPrefix}/${settingsString}/manifest.json`",
        "`stremio://${cometInstallBase}${stremioApiPrefix}/${settingsString}/manifest.json`",
    )
    content = content.replace(
        "`${window.location.origin}${stremioApiPrefix}/manifest.json`",
        "`${cometPublicBase}${stremioApiPrefix}/manifest.json`",
    )
    content = content.replace(
        "`${window.location.origin}${stremioApiPrefix}/${settingsString}/manifest.json`",
        "`${cometPublicBase}${stremioApiPrefix}/${settingsString}/manifest.json`",
    )
    return content
