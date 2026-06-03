from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class PlaybackProbeResult:
    status_code: int
    classification: str
    location: str | None
    content_type: str | None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def probe_playback_url(url: str) -> PlaybackProbeResult:
    request = urllib.request.Request(
        url,
        headers={"Range": "bytes=0-0", "User-Agent": "stremioguard/1"},
    )
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=10) as response:
            headers = dict(response.headers.items())
            classification = classify_playback_response(
                status_code=response.status,
                headers=headers,
                request_url=url,
            )
            return PlaybackProbeResult(
                status_code=response.status,
                classification=classification,
                location=headers.get("Location"),
                content_type=headers.get("Content-Type"),
            )
    except urllib.error.HTTPError as error:
        headers = dict(error.headers.items())
        classification = classify_playback_response(
            status_code=error.code,
            headers=headers,
            request_url=url,
        )
        return PlaybackProbeResult(
            status_code=error.code,
            classification=classification,
            location=headers.get("Location"),
            content_type=headers.get("Content-Type"),
        )


def classify_playback_response(
    *,
    status_code: int,
    headers: dict[str, str],
    request_url: str,
) -> str:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    location = normalized_headers.get("location")
    if location:
        request_host = urllib.parse.urlparse(request_url).netloc
        location_host = urllib.parse.urlparse(location).netloc
        if location_host and location_host != request_host:
            return "redirected"
        return "same-origin-redirect"
    if status_code in {200, 206}:
        if normalized_headers.get("accept-ranges") or normalized_headers.get("content-range"):
            return "proxied"
        content_type = normalized_headers.get("content-type", "")
        if content_type.startswith("video/") or content_type.startswith("application/octet-stream"):
            return "proxied"
    return "unexpected"
