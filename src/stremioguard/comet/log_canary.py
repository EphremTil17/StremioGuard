"""Log canary: verify that request-path redaction holds at every hop.

Addon URLs carry the gateway token, Comet's PUBLIC_API_TOKEN and the base64
user config (debrid keys), so every hop must keep request paths out of its
logs.
The canary sends a fresh random value, shaped like a gateway token, through
the public URL (HTTPS and plain HTTP, since a reverse proxy's server-level
redirect logs separately from its locations) and directly to Comet, then
counts occurrences in every configured sink.

A sink is PASS only when it was actually read and holds zero hits. A sink that
cannot be read, or a probe that never reached the stack, is UNVERIFIED: an
unobserved sink is not a clean one. The canary itself is never logged; only
its fingerprint is.
"""

from __future__ import annotations

import errno
import glob
import gzip
import hashlib
import os
import re
import secrets
import stat
import string
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol

from stremioguard.config import Runner

CANARY_ALPHABET = string.ascii_letters + string.digits
# Rejected by the gateway (403/404) or redirected to HTTPS by the proxy (3xx):
# either proves the request traversed the hop whose logs we then search.
EXPECTED_PROBE_STATUSES = frozenset({301, 302, 307, 308, 403, 404})


class SinkStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class SinkResult:
    name: str
    status: SinkStatus
    hits: int = 0
    detail: str = ""


@dataclass(frozen=True)
class Probe:
    """One request through a hop. An optional probe may find its hop closed.

    No response at all means no server saw the request, so nothing could have
    logged it; any response must still be an expected one.
    """

    name: str
    send: Callable[[], int | None]
    expected: frozenset[int]
    required: bool = True


@dataclass(frozen=True)
class ProbeResult:
    name: str
    status_code: int | None
    expected: frozenset[int]
    required: bool = True

    @property
    def reached(self) -> bool:
        return self.status_code in self.expected

    @property
    def acceptable(self) -> bool:
        return self.reached or (not self.required and self.status_code is None)


@dataclass
class CanaryReport:
    canary_fingerprint: str
    probes: list[ProbeResult] = field(default_factory=list)
    sinks: list[SinkResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return (
            bool(self.probes)
            and bool(self.sinks)
            and any(probe.reached for probe in self.probes)
            and all(probe.acceptable for probe in self.probes)
            and all(sink.status == SinkStatus.PASS for sink in self.sinks)
        )


class Sink(Protocol):
    name: str

    def count(self, needle: str) -> SinkResult: ...


def new_canary(length: int) -> str:
    return "".join(secrets.choice(CANARY_ALPHABET) for _ in range(length))


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


# A sink file is read from its end: the canary was written seconds ago, so the
# tail of a large log is where it can be. A compressed file is read whole or
# not at all.
FILE_READ_LIMIT_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class FileGlobSink:
    """Plain or gzip-rotated log files matching a glob.

    `modified_since` skips files untouched since the probe window opened, so a
    large archive of old run logs is not rescanned on every start. A match
    that is a symlink or not a regular file is never followed or opened for
    reading: it makes the sink UNVERIFIED, since an unread sink is not a clean
    one. Reads are bounded by `max_bytes` (see FILE_READ_LIMIT_BYTES).
    """

    name: str
    pattern: str
    modified_since: float | None = None
    max_bytes: int = FILE_READ_LIMIT_BYTES

    def count(self, needle: str) -> SinkResult:
        paths = sorted(glob.glob(self.pattern))
        if self.modified_since is not None:
            recent = []
            for path in paths:
                try:
                    if os.lstat(path).st_mtime >= self.modified_since:
                        recent.append(path)
                except OSError:
                    recent.append(path)  # reported as unreadable below
            paths = recent
            if not paths:
                return SinkResult(self.name, SinkStatus.PASS, detail="no file written")
        if not paths:
            return SinkResult(self.name, SinkStatus.UNVERIFIED, detail="no files match")
        hits = 0
        partial = 0
        for path in paths:
            try:
                text, complete = _read_log_file(path, self.max_bytes)
            except _UnreadableSinkFile as error:
                return SinkResult(
                    self.name, SinkStatus.UNVERIFIED, hits, f"{Path(path).name}: {error}"
                )
            if not complete:
                partial += 1
            hits += sum(1 for line in text.splitlines() if needle in line)
        status = SinkStatus.FAIL if hits else SinkStatus.PASS
        detail = f"{len(paths)} file(s)"
        if partial:
            detail += f", last {self.max_bytes // (1024 * 1024)} MiB of {partial}"
        return SinkResult(self.name, status, hits, detail)


class _UnreadableSinkFile(Exception):
    pass


def _read_log_file(path: str, max_bytes: int) -> tuple[str, bool]:
    """Text of a log file (or its last ``max_bytes``), and whether it was read whole."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY
    try:
        fd = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise _UnreadableSinkFile("a symlink, not followed") from None
        reason = error.strerror or type(error).__name__
        raise _UnreadableSinkFile(f"unreadable ({reason})") from None
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise _UnreadableSinkFile("not a regular file")
        try:
            if path.endswith(".gz"):
                with gzip.GzipFile(fileobj=handle) as unzipped:
                    data = unzipped.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise _UnreadableSinkFile(f"larger than {max_bytes} bytes uncompressed")
                return data.decode("utf-8", errors="replace"), True
            if st.st_size > max_bytes:
                handle.seek(st.st_size - max_bytes)
                data = handle.read(max_bytes)
                # Drop the first, probably partial, line.
                data = data.split(b"\n", 1)[1] if b"\n" in data else b""
                return data.decode("utf-8", errors="replace"), False
            return handle.read(max_bytes).decode("utf-8", errors="replace"), True
        except (OSError, EOFError, gzip.BadGzipFile) as error:
            raise _UnreadableSinkFile(
                f"unreadable ({getattr(error, 'strerror', None) or type(error).__name__})"
            ) from None


@dataclass(frozen=True)
class DockerLogSink:
    name: str
    container: str | None
    runner: Runner
    since: str

    def count(self, needle: str) -> SinkResult:
        if not self.container:
            return SinkResult(self.name, SinkStatus.UNVERIFIED, detail="container not found")
        result = self.runner.run(
            ["docker", "logs", "--since", self.since, self.container], check=False
        )
        if result.returncode != 0:
            return SinkResult(self.name, SinkStatus.UNVERIFIED, detail="docker logs failed")
        text = f"{result.stdout or ''}\n{result.stderr or ''}"
        hits = sum(1 for line in text.splitlines() if needle in line)
        return SinkResult(self.name, SinkStatus.FAIL if hits else SinkStatus.PASS, hits)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def http_status(url: str, *, timeout: float = 10.0) -> int | None:
    """Status of one un-redirected GET through the real network path, or None."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "stremioguard-log-canary/1"})
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (urllib.error.URLError, OSError, TimeoutError):
        return None


def public_probes(public_base_url: str, canary: str) -> list[Probe]:
    """The public URL, plus for an HTTPS base the plain-HTTP twin a proxy redirects.

    The twin is optional: when the public HTTP port is closed, no request line
    exists to be logged.
    """
    base = public_base_url.rstrip("/")
    path = f"/comet/{canary}/probe"
    probes = [
        Probe(
            f"public {urllib.parse.urlsplit(base).scheme}",
            lambda: http_status(base + path),
            EXPECTED_PROBE_STATUSES,
        )
    ]
    if base.startswith("https://"):
        plain = "http://" + base[len("https://") :] + path
        probes.append(
            Probe("public http", lambda: http_status(plain), EXPECTED_PROBE_STATUSES, False)
        )
    return probes


def wget_status(runner: Runner, container: str | None, url: str) -> int | None:
    """HTTP status of a BusyBox/GNU wget GET run inside `container`."""
    if not container:
        return None
    result = runner.run(
        ["docker", "exec", container, "wget", "-O", "/dev/null", "--timeout", "10", url],
        check=False,
    )
    if result.returncode == 0:
        return 200
    # BusyBox: "server returned error: HTTP/1.1 404"; GNU: "ERROR 404: Not Found".
    output = f"{result.stderr or ''}{result.stdout or ''}"
    match = re.search(r"(?:HTTP/\S+ |ERROR )(\d{3})", output)
    return int(match.group(1)) if match else None


def run_log_canary(
    canary: str,
    probes: Sequence[Probe],
    sinks: Sequence[Sink],
    *,
    settle_seconds: float = 1.5,
    sleep: Callable[[float], None] = time.sleep,
) -> CanaryReport:
    report = CanaryReport(canary_fingerprint=fingerprint(canary))
    for probe in probes:
        report.probes.append(ProbeResult(probe.name, probe.send(), probe.expected, probe.required))
    sleep(settle_seconds)  # let log writers (json-file, nginx) flush
    report.sinks.extend(sink.count(canary) for sink in sinks)
    return report
