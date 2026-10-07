"""Subdomain discovery recon plugin."""


import dns.exception
import dns.resolver

from app.recon.base import (
    ReconContext,
    ReconPlugin,
    ReconPluginConfig,
    ReconResult,
    register_plugin,
)


class SubdomainDiscoveryPlugin(ReconPlugin):
    """Subdomain discovery plugin - enumerates subdomains using multiple techniques."""

    @property
    def config(self) -> ReconPluginConfig:
        return ReconPluginConfig(
            name="subdomain_discovery",
            version="1.0.0",
            description="Discover subdomains using DNS brute force, certificate transparency, and other sources",
            target_types=["domain"],
            requires_network=True,
            timeout_seconds=300,
            rate_limit_per_minute=20,
        )

    def validate(self, context: ReconContext) -> tuple[bool, str | None]:
        """Validate that target is a domain."""
        if context.target_type != "domain":
            return False, f"Target type {context.target_type} not supported by subdomain discovery"
        return True, None

    def run(self, context: ReconContext) -> list[ReconResult]:
        """Run subdomain discovery."""
        results: list[ReconResult] = []
        domain = context.target_value

        # Technique 1: Certificate Transparency logs (crt.sh)
        ct_subdomains = self._query_certificate_transparency(domain)
        for subdomain in ct_subdomains:
            results.append(ReconResult(
                asset_kind="subdomain",
                value=subdomain,
                attributes={
                    "source": "certificate_transparency",
                    "parent_domain": domain,
                },
                relationships=[
                    {
                        "target_value": domain,
                        "relationship_type": "contains",
                        "note": f"Subdomain of {domain} (via CT logs)",
                    }
                ],
                source=self.config.name,
                confidence="high",
            ))

        # Technique 2: DNS brute force with common subdomains
        common_subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
            "ns3", "ns4", "dns1", "dns2", "dns3", "dns4", "mx1", "mx2", "mx3",
            "vpn", "remote", "admin", "portal", "api", "dev", "staging", "test",
            "demo", "app", "blog", "shop", "store", "support", "help", "docs",
            "wiki", "forum", "chat", "irc", "git", "svn", "hg", "jenkins",
            "ci", "cd", "build", "deploy", "monitor", "grafana", "prometheus",
            "kibana", "elastic", "logstash", "redis", "mysql", "postgres",
            "mongo", "cassandra", "kafka", "rabbitmq", "zookeeper", "consul",
            "vault", "etcd", "traefik", "nginx", "apache", "varnish", "haproxy",
        ]

        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                dns.resolver.resolve(full_domain, "A")
                results.append(ReconResult(
                    asset_kind="subdomain",
                    value=full_domain,
                    attributes={
                        "source": "dns_bruteforce",
                        "parent_domain": domain,
                        "method": "common_wordlist",
                    },
                    relationships=[
                        {
                            "target_value": domain,
                            "relationship_type": "contains",
                            "note": f"Subdomain of {domain} (via DNS brute force)",
                        }
                    ],
                    source=self.config.name,
                    confidence="high",
                ))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                continue

        return results

    def _query_certificate_transparency(self, domain: str) -> list[str]:
        """Query certificate transparency logs for subdomains."""
        subdomains = set()

        try:
            # Use curl to query crt.sh
            import json
            import urllib.request

            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())

            for entry in data:
                name = entry.get("name_value", "")
                # Handle multiple names (newline separated)
                for n in name.split("\n"):
                    n = n.strip().rstrip(".")
                    if n.endswith(f".{domain}") or n == domain:
                        subdomains.add(n)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Error querying CT logs for %s: %s", domain, e)

        return list(subdomains)


# Register plugin
register_plugin(SubdomainDiscoveryPlugin())
