"""DNS discovery recon plugin."""


import dns.exception
import dns.resolver

from app.recon.base import (
    ReconContext,
    ReconPlugin,
    ReconPluginConfig,
    ReconResult,
    register_plugin,
)


class DNSDiscoveryPlugin(ReconPlugin):
    """DNS discovery plugin - discovers DNS records for a domain."""

    @property
    def config(self) -> ReconPluginConfig:
        return ReconPluginConfig(
            name="dns_discovery",
            version="1.0.0",
            description="Discover DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA) for a domain",
            target_types=["domain", "subdomain"],
            requires_network=True,
            timeout_seconds=60,
            rate_limit_per_minute=30,
        )

    def validate(self, context: ReconContext) -> tuple[bool, str | None]:
        """Validate that target is a domain/subdomain."""
        if context.target_type not in ("domain", "subdomain"):
            return False, f"Target type {context.target_type} not supported by DNS discovery"
        return True, None

    def run(self, context: ReconContext) -> list[ReconResult]:
        """Run DNS discovery."""
        results: list[ReconResult] = []
        domain = context.target_value

        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                for rdata in answers:
                    value = str(rdata).rstrip(".")
                    if record_type in ("A", "AAAA"):
                        # IP address - create IP asset
                        results.append(ReconResult(
                            asset_kind="ip_address",
                            value=value,
                            attributes={
                                "record_type": record_type,
                                "domain": domain,
                            },
                            relationships=[
                                {
                                    "target_value": domain,
                                    "relationship_type": "resolves_to",
                                    "note": f"DNS {record_type} record",
                                }
                            ],
                            source=self.config.name,
                            confidence="high",
                        ))
                    elif record_type == "CNAME":
                        # CNAME - create subdomain asset
                        results.append(ReconResult(
                            asset_kind="subdomain",
                            value=value,
                            attributes={
                                "record_type": "CNAME",
                                "canonical_name": value,
                                "source_domain": domain,
                            },
                            relationships=[
                                {
                                    "target_value": domain,
                                    "relationship_type": "resolves_to",
                                    "note": f"CNAME from {domain}",
                                }
                            ],
                            source=self.config.name,
                            confidence="high",
                        ))
                    elif record_type == "MX":
                        # MX record
                        results.append(ReconResult(
                            asset_kind="domain",
                            value=value.split()[-1].rstrip("."),  # Extract hostname from MX
                            attributes={
                                "record_type": "MX",
                                "priority": rdata.preference,
                                "exchange": str(rdata.exchange).rstrip("."),
                                "source_domain": domain,
                            },
                            relationships=[
                                {
                                    "target_value": domain,
                                    "relationship_type": "serves",
                                    "note": f"MX record for {domain}",
                                }
                            ],
                            source=self.config.name,
                            confidence="high",
                        ))
                    elif record_type == "NS":
                        # NS record
                        results.append(ReconResult(
                            asset_kind="domain",
                            value=str(rdata.target).rstrip("."),
                            attributes={
                                "record_type": "NS",
                                "nameserver": str(rdata.target).rstrip("."),
                                "source_domain": domain,
                            },
                            relationships=[
                                {
                                    "target_value": domain,
                                    "relationship_type": "serves",
                                    "note": f"NS record for {domain}",
                                }
                            ],
                            source=self.config.name,
                            confidence="high",
                        ))
                    elif record_type == "TXT":
                        # TXT record
                        results.append(ReconResult(
                            asset_kind="other",
                            value=f"{domain}:TXT:{rdata.strings[0].decode() if rdata.strings else ''}",
                            attributes={
                                "record_type": "TXT",
                                "text": rdata.strings[0].decode() if rdata.strings else "",
                                "source_domain": domain,
                            },
                            relationships=[
                                {
                                    "target_value": domain,
                                    "relationship_type": "derived_from",
                                    "note": f"TXT record for {domain}",
                                }
                            ],
                            source=self.config.name,
                            confidence="medium",
                        ))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                continue

        return results


# Register plugin
register_plugin(DNSDiscoveryPlugin())
