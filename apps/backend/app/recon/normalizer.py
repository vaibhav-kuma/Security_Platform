"""Target normalization for canonical identity and deduplication."""

import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass
class NormalizedTarget:
    """Canonical representation of a target."""

    value: str
    target_type: str  # domain, subdomain, ip, cidr, url, api, apk
    canonical_value: str  # normalized form for deduplication
    metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}


class TargetNormalizer:
    """Normalize targets to canonical forms for deduplication and scope matching."""

    def __init__(self) -> None:
        self._domain_cache: dict[str, str] = {}

    def normalize(self, target_value: str, target_type: str | None = None) -> NormalizedTarget:
        """Normalize a target to its canonical form.

        Args:
            target_value: The raw target value
            target_type: Optional explicit target type. If not provided, will be inferred.

        Returns:
            NormalizedTarget with canonical value and metadata
        """
        if target_type is None:
            target_type = self._infer_type(target_value)

        if target_type == "domain":
            return self._normalize_domain(target_value)
        elif target_type == "subdomain":
            return self._normalize_subdomain(target_value)
        elif target_type == "ip":
            return self._normalize_ip(target_value)
        elif target_type == "cidr":
            return self._normalize_cidr(target_value)
        elif target_type == "url":
            return self._normalize_url(target_value)
        elif target_type == "api":
            return self._normalize_api(target_value)
        elif target_type == "apk":
            return self._normalize_apk(target_value)
        else:
            # Default: treat as domain-like
            return self._normalize_domain(target_value)

    def _infer_type(self, target_value: str) -> str:
        """Infer target type from value format."""
        # Check for CIDR
        if "/" in target_value:
            try:
                ipaddress.ip_network(target_value, strict=False)
                return "cidr"
            except ValueError:
                pass

        # Check for IP
        try:
            ipaddress.ip_address(target_value)
            return "ip"
        except ValueError:
            pass

        # Check for URL
        if target_value.startswith(("http://", "https://")):
            return "url"

        # Check for APK package
        if target_value.count(".") >= 2:
            parts = target_value.split(".")
            if all(self._is_valid_identifier(p) or p == "*" for p in parts):
                if parts[-1] in ("com", "org", "net", "io", "app", "dev", "co"):
                    return "domain"
                return "apk"

        # Check for subdomain pattern
        if target_value.startswith("*."):
            return "subdomain"

        # Default to domain
        if "." in target_value:
            return "domain"

        return "domain"

    def _is_valid_identifier(self, s: str) -> bool:
        """Check if string is a valid identifier (alphanumeric + underscore)."""
        return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', s))

    def _normalize_domain(self, target: str) -> NormalizedTarget:
        """Normalize a domain name."""
        target = target.lower().strip(".")
        # Remove any trailing dots
        target = target.rstrip(".")
        return NormalizedTarget(
            value=target,
            target_type="domain",
            canonical_value=target,
            metadata={"fqdn": target}
        )

    def _normalize_subdomain(self, target: str) -> NormalizedTarget:
        """Normalize a subdomain pattern."""
        target = target.lower().strip(".")
        target = target.rstrip(".")
        return NormalizedTarget(
            value=target,
            target_type="subdomain",
            canonical_value=target,
            metadata={"pattern": target}
        )

    def _normalize_ip(self, target: str) -> NormalizedTarget:
        """Normalize an IP address."""
        try:
            ip = ipaddress.ip_address(target)
            canonical = str(ip)
            return NormalizedTarget(
                value=target,
                target_type="ip",
                canonical_value=canonical,
                metadata={
                    "ip_version": ip.version,
                    "is_private": ip.is_private,
                    "is_loopback": ip.is_loopback,
                }
            )
        except ValueError:
            return NormalizedTarget(
                value=target,
                target_type="ip",
                canonical_value=target,
                metadata={}
            )

    def _normalize_cidr(self, target: str) -> NormalizedTarget:
        """Normalize a CIDR network."""
        try:
            network = ipaddress.ip_network(target, strict=False)
            canonical = str(network)
            return NormalizedTarget(
                value=target,
                target_type="cidr",
                canonical_value=canonical,
                metadata={
                    "network_address": str(network.network_address),
                    "prefix_length": network.prefixlen,
                    "num_addresses": network.num_addresses,
                    "ip_version": network.version,
                }
            )
        except ValueError:
            return NormalizedTarget(
                value=target,
                target_type="cidr",
                canonical_value=target,
                metadata={}
            )

    def _normalize_url(self, target: str) -> NormalizedTarget:
        """Normalize a URL."""
        parsed = urlparse(target)
        # Normalize: lowercase scheme and host, remove default ports
        scheme = parsed.scheme.lower()
        host = parsed.netloc.split(":")[0].lower()
        port = parsed.port

        # Remove default ports from canonical form
        if port == 80 and scheme == "http":
            canonical_host = host
        elif port == 443 and scheme == "https":
            canonical_host = host
        else:
            canonical_host = parsed.netloc.lower()

        # Rebuild canonical URL
        canonical = f"{scheme}://{canonical_host}{parsed.path}"
        if parsed.query:
            canonical += f"?{parsed.query}"
        if parsed.fragment:
            canonical += f"#{parsed.fragment}"

        return NormalizedTarget(
            value=target,
            target_type="url",
            canonical_value=canonical,
            metadata={
                "scheme": scheme,
                "host": host,
                "port": port,
                "path": parsed.path,
                "query": parsed.query,
            }
        )

    def _normalize_api(self, target: str) -> NormalizedTarget:
        """Normalize an API endpoint (same as URL)."""
        return self._normalize_url(target)

    def _normalize_apk(self, target: str) -> NormalizedTarget:
        """Normalize an APK package name."""
        target = target.lower().strip()
        return NormalizedTarget(
            value=target,
            target_type="apk",
            canonical_value=target,
            metadata={"package_name": target}
        )

    def get_dedup_key(self, normalized: NormalizedTarget) -> str:
        """Get deduplication key for a normalized target."""
        return f"{normalized.target_type}:{normalized.canonical_value}"

    def are_equivalent(self, target1: NormalizedTarget, target2: NormalizedTarget) -> bool:
        """Check if two normalized targets are equivalent."""
        return self.get_dedup_key(target1) == self.get_dedup_key(target2)
