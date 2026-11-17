"""Security hardening for Comet's debrid stream proxy (edge cases).

Installed into Comet as `comet/stremioguard_stream_guard.py` and imported by
the patched `comet/api/endpoints/playback.py`. It hardens the
`mediaflow_proxy` library behind `/playback` in three ways:

- **Headers come only from the request itself.** Upstream builds the proxy's
  request and response headers from the query string too (`h_*`, `r_*`,
  `rp_*`, `x_headers`). `safe_proxy_headers` keeps only the client's own
  `Range` and `If-Range` headers; nothing in the URL can add a header on the
  way out or on the way back.
- **The proxy only connects to public addresses.** Its connector refuses any
  resolved address that is not globally routable (loopback, private, link
  local, reserved, multicast, IPv4-mapped forms of those), checked at connect
  time for the first request and every redirect, so a redirect or a DNS answer
  cannot point it at a service inside the VPN namespace.
- **Upstream errors are not echoed to the client.** The client gets the
  status and a fixed message; the details go to the log, which masks secrets
  and cuts URLs to scheme and host.

This file is source for Comet and runs in Comet's own Python; StremioGuard
reads it, never imports it.
"""

import errno
import ipaddress

import aiohttp
import mediaflow_proxy.handlers as _handlers
import mediaflow_proxy.utils.http_client as _http_client
from mediaflow_proxy.configs import settings as _mediaflow_settings
from mediaflow_proxy.const import SUPPORTED_REQUEST_HEADERS
from mediaflow_proxy.utils.http_utils import ProxyRequestHeaders
from starlette.responses import Response


def safe_proxy_headers(request) -> ProxyRequestHeaders:
    """Proxy headers from the client's own request headers only."""
    request_headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() in SUPPORTED_REQUEST_HEADERS and value
    }
    request_headers.setdefault("user-agent", _mediaflow_settings.user_agent)
    return ProxyRequestHeaders(request_headers, {}, [], {})


def is_public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None:
            ip = mapped
    return bool(ip.is_global) and not ip.is_multicast


class PublicOnlyConnector(aiohttp.TCPConnector):
    """A connector that never connects to a non-public address."""

    async def _resolve_host(self, host, port, traces=None):
        infos = await super()._resolve_host(host, port, traces=traces)
        public = [info for info in infos if is_public_address(info.get("host", ""))]
        if not public:
            raise OSError(errno.EACCES, f"Refusing to connect to a non-public address for {host}")
        return public


_original_handle_exceptions = _handlers.handle_exceptions


def redacted_handle_exceptions(exception: Exception) -> Response:
    """The library's handling (and logging), with a body that names no URL."""
    response = _original_handle_exceptions(exception)
    status = response.status_code
    return Response(
        status_code=status, content=f"Upstream error ({status}).", media_type="text/plain"
    )


def install() -> None:
    """Patch the proxy library in place; safe to call more than once."""
    _http_client.TCPConnector = PublicOnlyConnector
    _handlers.handle_exceptions = redacted_handle_exceptions


def installed() -> bool:
    return (
        _http_client.TCPConnector is PublicOnlyConnector
        and _handlers.handle_exceptions is redacted_handle_exceptions
    )


install()
