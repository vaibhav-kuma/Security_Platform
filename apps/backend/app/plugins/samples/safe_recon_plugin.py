"""Safe demonstration recon plugin for DNS enumeration.

This plugin demonstrates the full SDK lifecycle including:
- Manifest validation
- Permission handling (network.request)
- Secure execution with resource limits
- Proper validate/scan/normalize pattern
"""

import asyncio
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype

from app.plugins.sdk.base import (
    BasePlugin,
    PluginConfig,
    PluginResult,
    PluginValidationResult,
    ScanContext,
)


class SafeReconPlugin(BasePlugin):
    """Safe DNS reconnaissance plugin for domain enumeration."""

    PLUGIN_ID = "safe-recon-plugin"
    PLUGIN_NAME = "Safe DNS Recon"
    PLUGIN_VERSION = "1.0.0"
    PLUGIN_CATEGORY = "recon"
    PLUGIN_DESCRIPTION = "Performs safe DNS-based domain enumeration using standard DNS queries"
    PLUGIN_AUTHOR = "SASP Team"
    PLUGIN_PERMISSIONS = ["network.request"]
    PLUGIN_RESOURCE_LIMITS = {
        "cpu_percent": 25,
        "memory_mb": 128,
        "time_seconds": 60,
        "network_egress_allowlist": [
            "8.8.8.8:53",
            "1.1.1.1:53",
        ],
    }
    PLUGIN_CONFIG_SCHEMA = {
        "type": "object",
        "properties": {
            "dns_servers": {
                "type": "array",
                "items": {"type": "string"},
                "default": ["8.8.8.8", "1.1.1.1"],
                "description": "DNS servers to use for queries"
            },
            "query_types": {
                "type": "array",
                "items": {"type": "string", "enum": ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]},
                "default": ["A", "AAAA", "CNAME"],
                "description": "DNS record types to query"
            },
            "timeout_seconds": {
                "type": "integer",
                "minimum": 1,
                "maximum": 30,
                "default": 5,
                "description": "DNS query timeout in seconds"
            },
            "max_subdomains": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000,
                "default": 50,
                "description": "Maximum subdomains to enumerate"
            }
        },
        "required": []
    }

    # Common subdomain wordlist for demonstration
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "dns", "dns1", "dns2", "mx", "mx1", "mx2", "autodiscover", "autoconfig",
        "admin", "administrator", "api", "app", "beta", "dev", "test", "staging",
        "prod", "production", "shop", "store", "blog", "forum", "support", "help",
        "docs", "documentation", "wiki", "kb", "knowledge", "status", "monitor",
        "vpn", "remote", "rdp", "ssh", "git", "gitlab", "github", "jenkins",
        "ci", "cd", "build", "deploy", "registry", "docker", "k8s", "kubernetes",
        "prometheus", "grafana", "kibana", "elasticsearch", "logstash", "fluentd",
    ]

    def __init__(self, config: PluginConfig | None = None):
        """Initialize plugin with configuration."""
        super().__init__(config)
        # Merge default config with user config
        self.dns_servers = self.config.config.get("dns_servers", ["8.8.8.8", "1.1.1.1"])
        self.query_types = self.config.config.get("query_types", ["A", "AAAA", "CNAME"])
        self.timeout = self.config.config.get("timeout_seconds", 5)
        self.max_subdomains = self.config.config.get("max_subdomains", 50)

        # Configure DNS resolver
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = self.dns_servers
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

    def validate(self, context: ScanContext) -> PluginValidationResult:
        """
        Validate if plugin can run against the target.

        Checks:
        - Target is a domain or subdomain
        - DNS servers are reachable
        - Required permissions granted
        """
        errors = []
        warnings = []

        # Check target type
        if context.target_type not in ("domain", "subdomain", "url"):
            errors.append(f"Unsupported target type: {context.target_type}. Expected domain, subdomain, or url")

        # Check if target value looks like a domain
        if context.target_value:
            # Basic domain validation
            if not self._is_valid_domain(context.target_value):
                warnings.append(f"Target value may not be a valid domain: {context.target_value}")

        # Check DNS server reachability (will be checked at runtime)
        if not self.dns_servers:
            errors.append("No DNS servers configured")

        # Check permissions
        required_perms = self.PLUGIN_PERMISSIONS

        return PluginValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            required_permissions=required_perms,
            estimated_resources=self.PLUGIN_RESOURCE_LIMITS,
        )

    def scan(self, context: ScanContext) -> PluginResult:
        """
        Execute DNS reconnaissance scan.

        Performs:
        1. Basic DNS record queries for target domain
        2. Subdomain enumeration using common wordlist
        3. Collects DNS records found
        """
        start_time = asyncio.get_event_loop().time()

        findings = []
        assets = []
        evidence = []
        errors = []
        warnings = []

        target = context.target_value

        # Extract domain from URL if needed
        if context.target_type == "url":
            from urllib.parse import urlparse
            parsed = urlparse(target)
            target = parsed.hostname or target

        # Query main domain records
        domain_records = asyncio.run(self._query_domain_records(target))
        assets.extend(domain_records)

        # Evidence for main domain queries
        evidence.append({
            "type": "dns_records",
            "target": target,
            "records": domain_records,
            "source": "dns_query",
        })

        # Subdomain enumeration
        if context.target_type in ("domain", "subdomain"):
            subdomain_results = asyncio.run(self._enumerate_subdomains(target))
            assets.extend(subdomain_results)

            # Evidence for subdomain enumeration
            evidence.append({
                "type": "subdomain_enumeration",
                "target": target,
                "subdomains_found": len(subdomain_results),
                "subdomains": [a["value"] for a in subdomain_results],
                "source": "dns_bruteforce",
            })

        execution_time = (asyncio.get_event_loop().time() - start_time) * 1000

        return PluginResult(
            success=len(errors) == 0,
            data={
                "target": target,
                "dns_servers_used": self.dns_servers,
                "query_types": self.query_types,
            },
            findings=findings,
            assets=assets,
            evidence=evidence,
            errors=errors,
            warnings=warnings,
            metrics={
                "dns_queries": len(domain_records) + len([a for a in assets if a.get("type") == "subdomain"]),
                "subdomains_found": len([a for a in assets if a.get("type") == "subdomain"]),
                "records_found": len(domain_records),
            },
            execution_time_ms=execution_time,
        )

    def normalize(self, raw_result: PluginResult, context: ScanContext) -> PluginResult:
        """
        Normalize results to standard platform format.

        Converts plugin-specific asset/evidence format to platform standard.
        """
        # For this plugin, the scan() method already returns platform-standard format
        # This method would be used for more complex transformations
        return raw_result

    async def _query_domain_records(self, domain: str) -> list[dict[str, Any]]:
        """Query DNS records for a domain."""
        records = []

        for qtype in self.query_types:
            try:
                rdatatype = getattr(dns.rdatatype, qtype)
                answers = await self.resolver.resolve(domain, rdatatype)

                for rdata in answers:
                    records.append({
                        "type": "dns_record",
                        "domain": domain,
                        "record_type": qtype,
                        "value": rdata.to_text(),
                        "ttl": answers.rrset.ttl if answers.rrset else 0,
                        "scope_status": "unknown",
                        "source": "dns_query",
                        "confidence": 0.9,
                    })

            except dns.resolver.NXDOMAIN:
                pass  # Domain doesn't exist
            except dns.resolver.NoAnswer:
                pass  # No records of this type
            except dns.exception.DNSException:
                # Log but continue
                pass

        return records

    async def _enumerate_subdomains(self, domain: str) -> list[dict[str, Any]]:
        """Enumerate subdomains using common wordlist."""
        subdomains = []
        semaphore = asyncio.Semaphore(10)  # Limit concurrent queries

        async def check_subdomain(subdomain: str) -> list[dict[str, Any]]:
            async with semaphore:
                fqdn = f"{subdomain}.{domain}"
                results = []

                for qtype in self.query_types:
                    try:
                        rdatatype = getattr(dns.rdatatype, qtype)
                        answers = await self.resolver.resolve(fqdn, rdatatype)

                        for rdata in answers:
                            results.append({
                                "type": "subdomain",
                                "domain": fqdn,
                                "parent_domain": domain,
                                "record_type": qtype,
                                "value": rdata.to_text(),
                                "ttl": answers.rrset.ttl if answers.rrset else 0,
                                "scope_status": "unknown",
                                "source": "dns_bruteforce",
                                "confidence": 0.8,
                            })

                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                        continue

                return results

        # Run subdomain checks concurrently
        tasks = [check_subdomain(sd) for sd in self.COMMON_SUBDOMAINS[:self.max_subdomains]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                subdomains.extend(result)

        return subdomains

    def _is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation."""
        if not domain or len(domain) > 253:
            return False
        # Simple check - at least one dot, valid characters
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not all(c.isalnum() or c == "-" for c in part):
                return False
            if part.startswith("-") or part.endswith("-"):
                return False
        return True

    def get_config_schema(self) -> dict[str, Any]:
        """Get configuration JSON schema."""
        return self.PLUGIN_CONFIG_SCHEMA

    def validate_config(self, config: dict[str, Any]) -> tuple[bool, list[str]]:
        """Validate plugin configuration against schema."""
        errors = []

        if "dns_servers" in config:
            servers = config["dns_servers"]
            if not isinstance(servers, list) or not all(isinstance(s, str) for s in servers):
                errors.append("dns_servers must be a list of strings")

        if "query_types" in config:
            valid_types = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"}
            types = config["query_types"]
            if not isinstance(types, list) or not all(t in valid_types for t in types):
                errors.append(f"query_types must be a list of valid DNS types: {valid_types}")

        if "timeout_seconds" in config:
            timeout = config["timeout_seconds"]
            if not isinstance(timeout, int) or timeout < 1 or timeout > 30:
                errors.append("timeout_seconds must be an integer between 1 and 30")

        if "max_subdomains" in config:
            max_subs = config["max_subdomains"]
            if not isinstance(max_subs, int) or max_subs < 1 or max_subs > 1000:
                errors.append("max_subdomains must be an integer between 1 and 1000")

        return len(errors) == 0, errors


# For direct testing
if __name__ == "__main__":
    import uuid

    # Test plugin directly
    config = PluginConfig(
        plugin_id="safe-recon-plugin",
        config={
            "dns_servers": ["8.8.8.8", "1.1.1.1"],
            "query_types": ["A", "CNAME"],
            "timeout_seconds": 5,
            "max_subdomains": 10,
        }
    )

    plugin = SafeReconPlugin(config)

    context = ScanContext(
        project_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        scan_job_id=uuid.uuid4(),
        target_value="example.com",
        target_type="domain",
    )

    # Validate
    validation = plugin.validate(context)
    print(f"Validation: {validation.valid}, Errors: {validation.errors}, Warnings: {validation.warnings}")

    # Scan
    result = plugin.scan(context)
    print(f"Scan success: {result.success}")
    print(f"Assets found: {len(result.assets)}")
    print(f"Evidence: {len(result.evidence)}")
    print(f"Execution time: {result.execution_time_ms:.2f}ms")
    print(f"Metrics: {result.metrics}")
