"""Bound the work and memory one addon config can cost Comet, and keep its keys
out of Comet's logs (security hardening)."""

from __future__ import annotations

from pathlib import Path

from stremioguard.overrides._patching import replace_first_matching

# A config with every debrid service Comet supports and thirty languages in
# each language list is about 3 KB of base64; the gateway's nginx already
# refuses a request line over 8 KB, so this cap only matters on Comet's own
# port and holds every path to the same limit.
MAX_B64CONFIG_LENGTH = 8192
# Comet supports nine debrid services; each entry is a debrid lookup on every
# search, so a config cannot ask for hundreds of them.
MAX_DEBRID_SERVICES = 10
# Parsed configs kept in memory (upstream keeps 4096). A self-hosted instance
# sees a handful of distinct configs; a miss only costs a re-parse.
CONFIG_CACHE_SIZE = 256

_CACHE_ANCHOR = "@lru_cache(maxsize=4096)\ndef _parse_and_validate_config(b64config: str):\n"
_CACHE_PATCHED = (
    "# StremioGuard: bounded config parsing (security hardening for edge cases).\n"
    f"_SG_MAX_B64CONFIG_LENGTH = {MAX_B64CONFIG_LENGTH}\n"
    f"_SG_MAX_DEBRID_SERVICES = {MAX_DEBRID_SERVICES}\n"
    "\n"
    "\n"
    "def _sg_note_config_secrets(validated_config):\n"
    "    # A config's own debrid keys are masked in Comet's logs like the\n"
    "    # server's (see the logger override); noted on every use, so the\n"
    "    # configs in use stay the most recently seen.\n"
    "    if not isinstance(validated_config, dict):\n"
    "        return\n"
    "    from comet.core.logger import _sg_note_secret_values\n"
    "\n"
    "    values = [\n"
    '        validated_config.get("debridApiKey"),\n'
    '        validated_config.get("debridStreamProxyPassword"),\n'
    "    ]\n"
    '    for key in ("debridServices", "_debridEntries"):\n'
    "        for entry in validated_config.get(key) or ():\n"
    "            if isinstance(entry, dict):\n"
    '                values.append(entry.get("apiKey"))\n'
    "    _sg_note_secret_values(values)\n"
    "\n"
    "\n"
    f"@lru_cache(maxsize={CONFIG_CACHE_SIZE})\n"
    "def _parse_and_validate_config(b64config: str):\n"
)
_SERVICES_ANCHOR = "        validated_config = ConfigModel(**config)\n"
_SERVICES_PATCHED = (
    "        validated_config = ConfigModel(**config)\n"
    "        if len(validated_config.debridServices or ()) > _SG_MAX_DEBRID_SERVICES:\n"
    "            return None\n"
)
_LENGTH_ANCHOR = "    validated_config = _parse_and_validate_config(b64config)\n"
_LENGTH_PATCHED = (
    "    validated_config = (\n"
    "        None\n"
    "        if len(b64config) > _SG_MAX_B64CONFIG_LENGTH\n"
    "        else _parse_and_validate_config(b64config)\n"
    "    )\n"
    "    _sg_note_config_secrets(validated_config)\n"
)


def render_config_limits_override(repo_dir: Path) -> str:
    """Refuse oversized configs before parsing, and keep fewer parsed ones.

    A config over the length cap, or with more debrid services than the cap,
    is invalid: a strict check refuses it and a lenient one falls back to the
    default config, exactly as upstream treats any other invalid config. The
    length check runs before the cache, so an oversized string is never kept.
    Every valid config's debrid keys are handed to the log scrubber, which
    masks them from then on.
    """
    source_file = repo_dir / "comet" / "core" / "config_validation.py"
    if not source_file.exists():
        raise RuntimeError(f"Comet config validation not found at {source_file}.")
    content = source_file.read_text(encoding="utf-8")
    error = "Unable to bound Comet's config parsing; its config validation has changed."
    for edit in (
        (_CACHE_ANCHOR, _CACHE_PATCHED),
        (_SERVICES_ANCHOR, _SERVICES_PATCHED),
        (_LENGTH_ANCHOR, _LENGTH_PATCHED),
    ):
        content = replace_first_matching(content, (edit,), error=error)
    return content
