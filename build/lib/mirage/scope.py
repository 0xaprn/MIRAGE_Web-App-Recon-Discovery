from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlsplit

class ScopeError(ValueError):
    pass

class Scope:
    """Explicit allow-list. Domain roots include their subdomains; IP ranges are explicit."""
    def __init__(self, target: str):
        self.raw = target.strip()
        if not self.raw:
            raise ScopeError("Target cannot be empty")
        self.domains: set[str] = set()
        self.networks: list[ipaddress._BaseNetwork] = []
        self.urls: list[str] = []
        self._parse(self.raw)
        if not (self.domains or self.networks):
            raise ScopeError(f"Could not interpret target: {target}")

    def _parse(self, value: str) -> None:
        value = value.strip()
        if "://" in value:
            p = urlsplit(value)
            if p.scheme not in ("http", "https") or not p.hostname:
                raise ScopeError("Only valid HTTP and HTTPS URLs are accepted")
            host = p.hostname.rstrip(".").lower()
            self.urls.append(value)
        else:
            host = value.strip().rstrip(".").lower()
        try:
            self.networks.append(ipaddress.ip_network(host, strict=False))
            return
        except ValueError:
            pass
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host):
            raise ScopeError(f"Invalid domain, IP address, CIDR, or URL: {value}")
        self.domains.add(host)

    def allows_host(self, host: str) -> bool:
        host = host.strip("[] .").lower()
        try:
            addr = ipaddress.ip_address(host)
            return any(addr in n for n in self.networks)
        except ValueError:
            return any(host == d or host.endswith("." + d) for d in self.domains)

    def allows_url(self, url: str) -> bool:
        try:
            p = urlsplit(url)
            return p.scheme in ("http", "https") and bool(p.hostname) and self.allows_host(p.hostname)
        except ValueError:
            return False

    @property
    def roots(self) -> list[str]:
        return sorted(self.domains)

    def describe(self) -> dict[str, list[str]]:
        return {"domains": sorted(self.domains), "networks": [str(n) for n in self.networks], "explicit_urls": self.urls}
