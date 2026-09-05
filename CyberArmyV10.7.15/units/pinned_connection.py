"""Pin an already-validated IP address to the actual TCP connection.

The DNS/IP gate resolves a hostname and rejects it when any resolved address is
private, reserved, or otherwise blocked. By default, however, ``requests`` /
``urllib3`` resolve the hostname *again* when the socket is opened. That second
lookup can return a different address than the one the gate approved (classic
DNS-rebinding / time-of-check-to-time-of-use bypass), defeating the gate.

This module lets the gate pin the exact address it validated so the connection
can only reach that IP. TLS/SNI and certificate verification are unaffected:
they continue to use the original hostname, because urllib3 only uses the
address returned here to open the raw socket.

The pin is stored in thread-local state and applied through a context manager,
so concurrent requests to different hosts never interfere with one another.
"""

import threading
from typing import Optional

from urllib3.util import connection as _urllib3_connection

_MISSING = object()

_install_lock = threading.Lock()
_installed = False
_real_create_connection = None
_local = threading.local()


def _pins() -> dict:
    """Return the calling thread's active host -> IP pin map."""
    pins = getattr(_local, "pins", None)
    if pins is None:
        pins = {}
        _local.pins = pins
    return pins


def _patched_create_connection(address, *args, **kwargs):
    """urllib3 connection factory that honours the current thread's pins."""
    host = address[0]
    pins = _pins()
    pinned = pins.get(host)
    if pinned is None and isinstance(host, str):
        pinned = pins.get(host.lower())
    if pinned:
        address = (pinned,) + tuple(address[1:])
    return _real_create_connection(address, *args, **kwargs)


def install() -> None:
    """Idempotently route urllib3's socket creation through the pin map."""
    global _installed, _real_create_connection
    with _install_lock:
        if _installed:
            return
        _real_create_connection = _urllib3_connection.create_connection
        _urllib3_connection.create_connection = _patched_create_connection
        _installed = True


class pin_host:
    """Pin ``host`` to ``ip`` for the current thread within a ``with`` block.

    A falsy ``ip`` (or ``host``) makes the context a no-op, so callers can pass
    an optional pin without branching. Previous pins for the same host are
    restored on exit to keep nested/redirect flows correct.
    """

    def __init__(self, host: Optional[str], ip: Optional[str]):
        self._host = host.lower() if isinstance(host, str) else host
        self._ip = ip
        self._active = False
        self._previous = _MISSING

    def __enter__(self):
        if self._ip and self._host:
            install()
            pins = _pins()
            self._previous = pins.get(self._host, _MISSING)
            pins[self._host] = self._ip
            self._active = True
        return self

    def __exit__(self, *exc):
        if self._active:
            pins = _pins()
            if self._previous is _MISSING:
                pins.pop(self._host, None)
            else:
                pins[self._host] = self._previous
            self._active = False
        return False
