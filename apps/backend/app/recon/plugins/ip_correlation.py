"""IP correlation recon plugin - finds related assets for an IP address."""

import ipaddress
import socket

from app.recon.base import (
    ReconContext,
    ReconPlugin,
    ReconPluginConfig,
    ReconResult,
    register_plugin,
)


class IPCorrelationPlugin(ReconPlugin):
    """IP correlation plugin - finds domains, certificates, and other assets related to an IP."""

    @property
    def config(self) -> ReconPluginConfig:
        return ReconPluginConfig(
            name="ip_correlation",
            version="1.0.0",
            description="Correlate IP addresses with related domains, certificates, and services",
            target_types=["ip", "cidr"],
            requires_network=True,
            timeout_seconds=60,
            rate_limit_per_minute=30,
        )

    def validate(self, context: ReconContext) -> tuple[bool, str | None]:
        """Validate that target is an IP or CIDR."""
        if context.target_type not in ("ip", "cidr"):
            return False, f"Target type {context.target_type} not supported by IP correlation"
        return True, None

    def run(self, context: ReconContext) -> list[ReconResult]:
        """Run IP correlation."""
        results: list[ReconResult] = []
        target = context.target_value

        # Parse the target
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                ips = [str(ip) for ip in network.hosts()]
                # Limit to prevent explosion
                ips = ips[:50]
            else:
                ip = ipaddress.ip_address(target)
                ips = [str(ip)]
        except ValueError:
            return results

        for ip_str in ips:
            # Reverse DNS lookup
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_str)
                hostname = hostname.rstrip(".")
                results.append(ReconResult(
                    asset_kind="domain",
                    value=hostname,
                    attributes={
                        "source": "reverse_dns",
                        "ip_address": ip_str,
                    },
                    relationships=[
                        {
                            "target_value": ip_str,
                            "relationship_type": "resolves_to",
                            "note": f"Reverse DNS for {ip_str}",
                        }
                    ],
                    source=self.config.name,
                    confidence="high",
                ))
            except (socket.herror, socket.gaierror):
                pass

            # Check if IP is private
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_private:
                    results.append(ReconResult(
                        asset_kind="ip_address",
                        value=ip_str,
                        attributes={
                            "is_private": True,
                            "ip_version": ip_obj.version,
                        },
                        source=self.config.name,
                        confidence="high",
                    ))
            except ValueError:
                pass

        return results


# Register plugin
register_plugin(IPCorrelationPlugin())
