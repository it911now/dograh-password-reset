"""Work out the client address used for rate limiting, trusting only configured proxies."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping

from .config import Settings


def _ip(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _in(addr, networks) -> bool:
    return any(addr in net for net in networks)


def resolve(scope_client: str, headers: Mapping[str, str], settings: Settings) -> str:
    """CF-Connecting-IP only if TRUST_CLOUDFLARE; else the right-most untrusted
    X-Forwarded-For hop when the peer is a trusted proxy; else the peer itself."""
    lowered = {k.lower(): v for k, v in headers.items()}
    if settings.trust_cloudflare:
        cf = _ip(lowered.get("cf-connecting-ip", ""))
        if cf is not None:
            return str(cf)
    networks = [ipaddress.ip_network(c, strict=False) for c in settings.trusted_proxies]
    peer = _ip(scope_client)
    if networks and peer is not None and _in(peer, networks):
        hops = [h for h in lowered.get("x-forwarded-for", "").split(",") if h.strip()]
        for hop in reversed(hops):
            addr = _ip(hop)
            if addr is None:
                return scope_client  # garbage in the chain: do not guess
            if not _in(addr, networks):
                return str(addr)
    return scope_client
