"""Inserted into Comet's comet/core/logger.py by the logger override.

Every loguru sink Comet configures writes through `_sg_scrubbed_sink`, which
masks the value of each configured secret wherever it appears in the final
text (message, exception text, traceback), whatever logging call produced it.
Python's standard logging, which libraries such as the stream proxy use, is
routed into loguru by `_sg_route_stdlib_logging`, with every URL cut to its
scheme and host first, so no library output reaches stderr around the sinks.
Scraper error lines use `_sg_scraper_origin` and `_sg_describe_error`, which
never print a bare API key and cut every URL to its scheme and host.

This file is source text for Comet, not a StremioGuard module: it must stay
self-contained (standard library only, no `from __future__` import), and it
is read, not imported, when the bundle is rendered.
"""

import logging as _sg_logging
import os as _sg_os
import re as _sg_re
import sys as _sg_sys
import traceback as _sg_traceback
import urllib.parse as _sg_parse

from loguru import logger as _sg_loguru

_SG_MASK = "********"
_SG_SECRET_SUFFIXES = frozenset(
    {"KEY", "KEYS", "APIKEY", "TOKEN", "TOKENS", "PASSWORD", "PASSWORDS", "SECRET", "AUTH"}
)
# Shorter values are left alone: masking them would garble ordinary text.
_SG_MIN_SECRET_LENGTH = 8
_SG_WITHHELD = "[StremioGuard withheld a log line: secret scrubbing failed]\n"
_SG_URL = _sg_re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://([^\s/?#'\"<>()\[\]]*)[^\s'\"<>()\[\]]*")
_sg_secret_forms: tuple[str, ...] = ()
_sg_secrets_final = False


def _sg_add_secret(found, name, value):
    if name.rsplit("_", 1)[-1].upper() not in _SG_SECRET_SUFFIXES:
        return
    items = value if isinstance(value, (list, tuple, set)) else [value]
    for item in items:
        if isinstance(item, str) and item:
            found.add(item)


def _sg_add_url_password(found, url):
    if not isinstance(url, str) or "@" not in url:
        return
    candidate = url if "://" in url else f"x://{url}"
    try:
        password = _sg_parse.urlsplit(candidate).password
    except ValueError:
        return
    if password:
        found.add(password)
        found.add(_sg_parse.unquote(password))


def _sg_current_secrets():
    # Comet's settings module imports this one, so settings are read lazily,
    # and the set is final only once the API token has been resolved.
    global _sg_secret_forms, _sg_secrets_final
    if _sg_secrets_final:
        return _sg_secret_forms
    found = set()
    for name, value in _sg_os.environ.items():
        _sg_add_secret(found, name, value)
    _sg_add_url_password(found, _sg_os.environ.get("DATABASE_URL"))
    models = _sg_sys.modules.get("comet.core.models")
    settings = getattr(models, "settings", None)
    final = False
    if settings is not None:
        for name in type(settings).model_fields:
            _sg_add_secret(found, name, getattr(settings, name, None))
        _sg_add_url_password(found, getattr(settings, "DATABASE_URL", None))
        for replica in getattr(settings, "DATABASE_READ_REPLICA_URLS", None) or ():
            _sg_add_url_password(found, replica)
        final = getattr(models, "STREMIO_API_PREFIX", None) is not None
    forms = set()
    for value in found:
        if len(value) >= _SG_MIN_SECRET_LENGTH:
            forms.update((value, _sg_parse.quote(value, safe=""), _sg_parse.quote_plus(value)))
    _sg_secret_forms = tuple(sorted(forms, key=len, reverse=True))
    _sg_secrets_final = final
    return _sg_secret_forms


def _sg_scrub(text):
    for secret in _sg_current_secrets():
        if secret in text:
            text = text.replace(secret, _SG_MASK)
    return text


def _sg_scrubbed_sink(target):
    write = target.write if hasattr(target, "write") else target
    flush = getattr(target, "flush", None)

    def sink(message):
        try:
            text = _sg_scrub(str(message))
        except Exception:
            text = _SG_WITHHELD
        write(text)
        if flush is not None:
            flush()

    return sink


def _sg_origin_only(match):
    return f"{match.group(1)}://{match.group(2).rsplit('@', 1)[-1]}"


def _sg_scraper_origin(value):
    # Scrapers pass their URL, and some their bare API key: never log a key,
    # and of a URL only its scheme and host (paths and queries carry configs).
    if not isinstance(value, str) or "://" not in value:
        return ""
    try:
        parts = _sg_parse.urlsplit(value.strip())
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return ""
    if not parts.scheme or not host:
        return ""
    return f" ({parts.scheme}://{host}{port})"


def _sg_describe_error(error):
    label = type(error).__name__
    status = getattr(error, "status", None)
    if not isinstance(status, int) or isinstance(status, bool):
        status = getattr(error, "status_code", None)
    if isinstance(status, int) and not isinstance(status, bool):
        label = f"{label} (HTTP {status})"
    try:
        text = str(error)
    except Exception:
        text = ""
    text = _SG_URL.sub(_sg_origin_only, text)
    return f"{label}: {text}" if text else label


_SG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


class _SGStdlibToLoguru(_sg_logging.Handler):
    """Standard-library log records, through Comet's scrubbed loguru sinks.

    Without a handler, a library's warning goes to stderr through
    `logging.lastResort`, around every sink. URLs are cut to scheme and host
    because library messages carry whole upstream URLs (signed links, configs).
    """

    def emit(self, record):
        try:
            text = record.getMessage()
            if record.exc_info:
                text += "\n" + "".join(_sg_traceback.format_exception(*record.exc_info))
            text = _SG_URL.sub(_sg_origin_only, f"{record.name}: {text}")
            level = record.levelname if record.levelname in _SG_LEVELS else "WARNING"
            _sg_loguru.log(level, text)
        except Exception:
            try:  # noqa: SIM105 - no contextlib import in Comet's logger module
                _sg_sys.stderr.write(_SG_WITHHELD)
            except Exception:
                pass


def _sg_route_stdlib_logging():
    root = _sg_logging.getLogger()
    if not any(isinstance(handler, _SGStdlibToLoguru) for handler in root.handlers):
        root.addHandler(_SGStdlibToLoguru())
