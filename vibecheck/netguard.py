"""SSRF guard for the hosted URL scanner.

The hosted scanner fetches a URL the user supplies, from our server. Without
a guard that is a server-side request forgery hole: someone could point it at
cloud metadata (169.254.169.254), at localhost, or at a private network
address and use our server as a proxy into places they can't reach.

Every URL — the one the user typed AND every redirect hop — must pass
``check_url`` before we fetch it.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443, None}

# Hostnames that are never legitimate scan targets.
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.goog",
}


def _ip_is_public(ip: ipaddress._BaseAddress) -> bool:
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def resolve_host(host: str) -> List[str]:
    """Resolve a hostname to every IP it points at. Raises OSError on failure."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def check_url(url: str, resolver=resolve_host) -> Tuple[bool, Optional[str]]:
    """Return (ok, reason_if_rejected) for a URL we are about to fetch."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "That doesn't look like a valid URL."

    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, "Only http:// and https:// URLs can be scanned."

    host = parsed.hostname
    if not host:
        return False, "That URL has no hostname."

    if host.lower() in BLOCKED_HOSTNAMES or host.lower().endswith(".localhost"):
        return False, "Local addresses can't be scanned. Use the CLI for local apps."

    try:
        if parsed.port is not None and parsed.port not in ALLOWED_PORTS:
            return False, "Only standard web ports (80, 443, 8080, 8443) can be scanned."
    except ValueError:
        return False, "That URL has an invalid port."

    # A literal IP in the URL is checked directly; a hostname is resolved and
    # every address it points at must be public (a name can resolve to more
    # than one, and only needs one private hit to be dangerous).
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(a) for a in resolver(host)]
        except (OSError, ValueError):
            return False, "That hostname could not be resolved."

    if not addresses:
        return False, "That hostname could not be resolved."

    for ip in addresses:
        if not _ip_is_public(ip):
            return False, "That address is on a private or internal network and can't be scanned."

    return True, None
