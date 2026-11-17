"""HTTP(S) requests with a wall-clock deadline covering DNS, TLS and body read."""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from contextlib import suppress

JOIN_GRACE_SECONDS = 0.5


class ConnectionTracker:
    """Tracks sockets opened during one attempt so deadline expiry aborts any phase."""

    def __init__(self, deadline: float) -> None:
        self.deadline = deadline
        self._lock = threading.Lock()
        self._cancelled = False
        self._sockets: list[socket.socket] = []

    def remaining(self) -> float:
        with self._lock:
            if self._cancelled:
                raise TimeoutError("probe deadline exceeded")
        rem = self.deadline - time.monotonic()
        if rem <= 0:
            raise TimeoutError("probe deadline exceeded")
        return rem

    def register(self, sock: socket.socket) -> None:
        with self._lock:
            if self._cancelled:
                with suppress(OSError):
                    sock.close()
                raise TimeoutError("probe deadline exceeded")
            self._sockets.append(sock)

    def replace(self, old_sock: socket.socket, new_sock: socket.socket) -> None:
        """Swap a wrapped raw socket for its SSLSocket before handshake I/O begins."""
        with self._lock:
            if old_sock in self._sockets:
                self._sockets.remove(old_sock)
            if self._cancelled:
                with suppress(OSError):
                    new_sock.close()
                raise TimeoutError("probe deadline exceeded")
            self._sockets.append(new_sock)

    def unregister_and_close(self, sock: socket.socket) -> None:
        with self._lock:
            if sock in self._sockets:
                self._sockets.remove(sock)
        with suppress(OSError):
            sock.close()

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            for sock in self._sockets:
                with suppress(OSError):
                    if sock.fileno() != -1:
                        socket.socket.shutdown(sock, socket.SHUT_RDWR)

    def close_all(self) -> None:
        with self._lock:
            sockets = list(self._sockets)
            self._sockets.clear()
        for sock in sockets:
            with suppress(OSError):
                sock.close()

    @property
    def cancelled(self) -> bool:
        with self._lock:
            return self._cancelled


def tracked_create_connection(
    tracker: ConnectionTracker,
    address: tuple[str, int],
    timeout: float | None = None,
    source_address: tuple[str, int] | None = None,
) -> socket.socket:
    host, port = address
    err: OSError | None = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, _, sa = res
        sock: socket.socket | None = None
        try:
            sock = socket.socket(af, socktype, proto)
            rem = tracker.remaining()
            sock.settimeout(rem if timeout is None else min(timeout, rem))
            if source_address:
                sock.bind(source_address)
            tracker.register(sock)
            sock.connect(sa)
            err = None
            return sock
        except OSError as exc:
            err = exc
            if sock is not None:
                tracker.unregister_and_close(sock)
    if err is not None:
        raise err
    raise OSError("getaddrinfo returns an empty list")


class DeadlineHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, tracker: ConnectionTracker) -> None:
        super().__init__()
        self._tracker = tracker

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        tracker = self._tracker

        class _Conn(http.client.HTTPConnection):
            def connect(self) -> None:
                self._create_connection = lambda address, timeout=None, source_address=None: (
                    tracked_create_connection(tracker, address, timeout, source_address)
                )
                super().connect()

        return self.do_open(_Conn, req)


class DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(
        self,
        tracker: ConnectionTracker,
        context: ssl.SSLContext | None = None,
    ) -> None:
        self._ssl_context = context if context is not None else ssl.create_default_context()
        super().__init__(context=self._ssl_context)
        self._tracker = tracker

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        tracker = self._tracker
        ssl_context = self._ssl_context

        class _Conn(http.client.HTTPSConnection):
            def connect(self) -> None:
                self._create_connection = lambda address, timeout=None, source_address=None: (
                    tracked_create_connection(tracker, address, timeout, source_address)
                )
                # Connect TCP (and HTTP tunnel if configured) first, then wrap without
                # handshaking so the SSLSocket is tracked before any TLS I/O runs.
                http.client.HTTPConnection.connect(self)
                raw_sock = self.sock
                assert raw_sock is not None
                server_hostname: str = getattr(self, "_tunnel_host", None) or self.host
                ssl_sock: ssl.SSLSocket | None = None
                try:
                    ssl_sock = ssl_context.wrap_socket(
                        raw_sock,
                        server_hostname=server_hostname,
                        do_handshake_on_connect=False,
                    )
                    self.sock = ssl_sock
                    tracker.replace(raw_sock, ssl_sock)
                    rem = tracker.remaining()
                    current_timeout = ssl_sock.gettimeout()
                    ssl_sock.settimeout(
                        rem if current_timeout is None else min(current_timeout, rem)
                    )
                    ssl_sock.do_handshake()
                except BaseException:
                    tracker.unregister_and_close(raw_sock)
                    if ssl_sock is not None:
                        tracker.unregister_and_close(ssl_sock)
                    raise

        return self.do_open(_Conn, req, context=ssl_context)


def open_with_deadline(
    request: urllib.request.Request,
    *,
    timeout: float,
    max_bytes: int,
) -> tuple[int, bytes]:
    """Execute ``request`` and read up to ``max_bytes`` within ``timeout`` seconds."""
    timeout_seconds = max(0.0, timeout)
    tracker = ConnectionTracker(time.monotonic() + timeout_seconds)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        DeadlineHTTPHandler(tracker),
        DeadlineHTTPSHandler(tracker),
    )
    outcome: list[tuple[int, bytes] | None] = [None]
    error: list[BaseException | None] = [None]
    done = threading.Event()

    def _worker() -> None:
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                status = int(response.status)
                body = response.read(max_bytes)
            if not tracker.cancelled:
                outcome[0] = (status, body)
        except BaseException as exc:
            if not tracker.cancelled:
                if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, TimeoutError):
                    error[0] = exc.reason
                else:
                    error[0] = exc
            elif isinstance(exc, urllib.error.HTTPError):
                with suppress(Exception):
                    exc.close()
        finally:
            tracker.close_all()
            done.set()

    thread = threading.Thread(target=_worker, name="stremioguard-http-deadline", daemon=True)
    thread.start()
    if not done.wait(timeout=timeout_seconds):
        tracker.cancel()
        thread.join(timeout=JOIN_GRACE_SECONDS)
        raise TimeoutError(f"no complete response within {timeout:g}s")
    thread.join(timeout=JOIN_GRACE_SECONDS)
    if error[0] is not None:
        raise error[0]
    assert outcome[0] is not None
    return outcome[0]
