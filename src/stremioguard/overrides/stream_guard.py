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
- **Each gateway token gets its own stream slots.** Behind the gateway every
  client reaches Comet from the same address, so Comet's per-IP limit on
  concurrent proxied streams was one pool for every user. `admission_key`
  counts a request from the gateway under the token it came with.

This file is source for Comet and runs in Comet's own Python; StremioGuard
reads it, never imports it.
"""

import errno
import ipaddress
import re

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


# The well-known NAT64 prefix (RFC 6052) is globally routable, but the IPv4
# address in its last 32 bits is where a translator would actually connect.
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_public_address(address: str) -> bool:
    """Whether an address is plainly public: globally routable and nothing else.

    IPv6 forms that carry an IPv4 address (mapped, 6to4, NAT64) are judged by
    that IPv4 address. Reserved ranges (the deprecated IPv4-compatible `::/96`
    among them) are refused even where Python counts them as global.
    """
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            ip = embedded
    return bool(ip.is_global) and not (
        ip.is_multicast
        or ip.is_reserved
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
    )


class PublicOnlyConnector(aiohttp.TCPConnector):
    """A connector that never connects to a non-public address."""

    async def _resolve_host(self, host, port, traces=None):
        infos = await super()._resolve_host(host, port, traces=traces)
        public = [info for info in infos if is_public_address(info.get("host", ""))]
        if not public:
            raise OSError(errno.EACCES, f"Refusing to connect to a non-public address for {host}")
        return public


# Set by the gateway (and cleared on every other route) to the ID of the
# token a request came with; the ID is not a credential.
_CLIENT_HEADER = "x-stremioguard-client"
_CLIENT_ID = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")
# The gateway shares Comet's network namespace and connects over loopback; a
# connection to the host's published port arrives from the bridge address,
# so a direct client cannot pick its own key by sending the header.
_GATEWAY_PEERS = frozenset({"127.0.0.1", "::1"})


def admission_key(request, ip: str) -> str:
    """The key Comet counts a client's concurrent proxied streams under."""
    client = getattr(request, "client", None)
    peer = str(getattr(client, "host", "") or "")
    token_id = request.headers.get(_CLIENT_HEADER, "")
    if peer in _GATEWAY_PEERS and _CLIENT_ID.match(token_id):
        return f"token:{token_id}"
    return ip


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
