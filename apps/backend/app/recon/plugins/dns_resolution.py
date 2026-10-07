"""DNS resolution recon plugin - resolves domains/subdomains to IP addresses."""


import dns.exception
import dns.resolver

from app.recon.base import (
    ReconContext,
    ReconPlugin,
    ReconPluginConfig,
    ReconResult,
    register_plugin,
)


class DNSResolutionPlugin(ReconPlugin):
    """DNS resolution plugin - resolves hostnames to IP addresses."""

    @property
    def config(self) -> ReconPluginConfig:
        return ReconPluginConfig(
            name="dns_resolution",
            version="1.0.0",
            description="Resolve domain/subdomain hostnames to IP addresses (A/AAAA records)",
            target_types=["domain", "subdomain"],
            requires_network=True,
            timeout_seconds=60,
            rate_limit_per_minute=60,
        )

    def validate(self, context: ReconContext) -> tuple[bool, str | None]:
        """Validate that target is a domain/subdomain."""
        if context.target_type not in ("domain", "subdomain"):
            return False, f"Target type {context.target_type} not supported by DNS resolution"
        return True, None

    def run(self, context: ReconContext) -> list[ReconResult]:
        """Run DNS resolution."""
        results: list[ReconResult] = []
        hostname = context.target_value

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        # Resolve A records
        try:
            answers = resolver.resolve(hostname, "A")
            for rdata in answers:
                ip = str(rdata)
                results.append(ReconResult(
                    asset_kind="ip_address",
                    value=ip,
                    attributes={
                        "record_type": "A",
                        "hostname": hostname,
                        "ip_version": 4,
                    },
                    relationships=[
                        {
                            "target_value": hostname,
                            "relationship_type": "resolves_to",
                            "note": f"A record for {hostname}",
                        }
                    ],
                    source=self.config.name,
                    confidence="high",
                ))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass

        # Resolve AAAA records
        try:
            answers = resolver.resolve(hostname, "AAAA")
            for rdata in answers:
                ip = str(rdata)
                results.append(ReconResult(
                    asset_kind="ip_address",
                    value=ip,
                    attributes={
                        "record_type": "AAAA",
                        "hostname": hostname,
                        "ip_version": 6,
                    },
                    relationships=[
                        {
                            "target_value": hostname,
                            "relationship_type": "resolves_to",
                            "note": f"AAAA record for {hostname}",
                        }
                    ],
                    source=self.config.name,
                    confidence="high",
                ))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass

        return results


# Register plugin
register_plugin(DNSResolutionPlugin())
