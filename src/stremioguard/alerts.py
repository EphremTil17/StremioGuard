"""Best-effort operator alerts for events that otherwise only reach a log file.

A lockout, a confirmed leak or a restart loop used to be visible only to
someone who went looking. `STREMIO_ALERT_URL` (in .env) names an HTTP endpoint
that receives a short plain-text POST for each of them. The request follows
ntfy's conventions (`Title`, `Priority`, `Tags` headers), which generic
webhooks simply ignore.

The request leaves from the host's own connection, not through the tunnel:
an alert about a dead VPN cannot depend on the VPN. Point it at a service you
are comfortable seeing this host's address.

Best-effort by contract: delivery is never retried and a failure never
raises, so an unreachable endpoint cannot delay or abort a shutdown.
"""

from __future__ import annotations

import urllib.parse
import urllib.request

from loguru import logger

from stremioguard.httpdeadline import open_with_deadline

ALERT_TIMEOUT_SECONDS = 5.0


def valid_alert_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def send_alert(url: str | None, *, title: str, message: str, urgent: bool = True) -> bool:
    """POST one alert; return whether the endpoint accepted it."""
    if not url:
        return False
    try:
        request = urllib.request.Request(
            url,
            data=message.encode("utf-8"),
            method="POST",
            headers={
                "Title": title.encode("ascii", errors="replace").decode("ascii"),
                "Priority": "urgent" if urgent else "default",
                "Tags": "rotating_light" if urgent else "information_source",
                "Content-Type": "text/plain; charset=utf-8",
                "User-Agent": "stremioguard-alert/1",
            },
        )
        status, _ = open_with_deadline(
            request,
            timeout=ALERT_TIMEOUT_SECONDS,
            max_bytes=0,
        )
        delivered = 200 <= status < 300
    except Exception as error:
        # Never the URL itself: ntfy topics and webhook paths are credentials.
        logger.warning(f"Alert could not be delivered ({type(error).__name__}).")
        return False
    if not delivered:
        logger.warning("Alert endpoint did not accept the alert.")
    return delivered
