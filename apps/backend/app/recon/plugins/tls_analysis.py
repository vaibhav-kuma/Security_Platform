"""TLS analysis recon plugin."""

import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from app.recon.base import (
    ReconContext,
    ReconPlugin,
    ReconPluginConfig,
    ReconResult,
    register_plugin,
)


class TLSAnalysisPlugin(ReconPlugin):
    """TLS analysis plugin - analyzes TLS certificates and configuration."""

    @property
    def config(self) -> ReconPluginConfig:
        return ReconPluginConfig(
            name="tls_analysis",
            version="1.0.0",
            description="Analyze TLS certificates, cipher suites, and security configuration",
            target_types=["domain", "subdomain", "ip", "url"],
            requires_network=True,
            timeout_seconds=60,
            rate_limit_per_minute=20,
        )

    def validate(self, context: ReconContext) -> tuple[bool, str | None]:
        """Validate that target can be checked for TLS."""
        if context.target_type not in ("domain", "subdomain", "ip", "url"):
            return False, f"Target type {context.target_type} not supported by TLS analysis"
        return True, None

    def run(self, context: ReconContext) -> list[ReconResult]:
        """Run TLS analysis."""
        results: list[ReconResult] = []

        # Extract hostname from target
        hostname = self._extract_hostname(context.target_value, context.target_type)
        if not hostname:
            return results

        # Get certificate
        cert_info = self._get_certificate(hostname)
        if not cert_info:
            return results

        # Create certificate asset
        cert_result = ReconResult(
            asset_kind="certificate",
            value=f"{hostname}:{cert_info['sha256_fingerprint']}",
            attributes={
                "subject": cert_info["subject"],
                "issuer": cert_info["issuer"],
                "serial_number": cert_info["serial_number"],
                "sha256_fingerprint": cert_info["sha256_fingerprint"],
                "not_before": cert_info["not_before"].isoformat() if cert_info["not_before"] else None,
                "not_after": cert_info["not_after"].isoformat() if cert_info["not_after"] else None,
                "subject_alternative_names": cert_info["sans"],
                "version": cert_info["version"],
                "signature_algorithm": cert_info["signature_algorithm"],
                "hostname": hostname,
            },
            relationships=[
                {
                    "target_value": hostname,
                    "relationship_type": "serves",
                    "note": f"TLS certificate for {hostname}",
                }
            ],
            source=self.config.name,
            confidence="high",
        )
        results.append(cert_result)

        # Check certificate validity
        if cert_info["not_after"] and cert_info["not_after"] < datetime.now(UTC):
            results.append(ReconResult(
                asset_kind="other",
                value=f"{hostname}:expired_cert",
                attributes={
                    "type": "expired_certificate",
                    "hostname": hostname,
                    "expired_at": cert_info["not_after"].isoformat() if cert_info["not_after"] else None,
                },
                relationships=[
                    {
                        "target_value": hostname,
                        "relationship_type": "derived_from",
                        "note": f"Expired certificate for {hostname}",
                    }
                ],
                source=self.config.name,
                confidence="high",
            ))

        # Check for weak signature algorithms
        weak_algos = ["md5", "sha1"]
        if any(weak in cert_info["signature_algorithm"].lower() for weak in weak_algos):
            results.append(ReconResult(
                asset_kind="other",
                value=f"{hostname}:weak_signature",
                attributes={
                    "type": "weak_signature_algorithm",
                    "hostname": hostname,
                    "algorithm": cert_info["signature_algorithm"],
                },
                relationships=[
                    {
                        "target_value": hostname,
                        "relationship_type": "derived_from",
                        "note": f"Weak signature algorithm for {hostname}",
                    }
                ],
                source=self.config.name,
                confidence="high",
            ))

        return results

    def _extract_hostname(self, target: str, target_type: str) -> str | None:
        """Extract hostname from target."""
        if target_type == "url":
            from urllib.parse import urlparse
            parsed = urlparse(target)
            return parsed.netloc.split(":")[0]
        elif target_type in ("domain", "subdomain"):
            return target
        elif target_type == "ip":
            return target
        return None

    def _get_certificate(self, hostname: str, port: int = 443) -> dict[str, Any] | None:
        """Get TLS certificate for hostname."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if cert is None:
                        return None
                    cert_dict = ssock.getpeercert()

                    # Parse certificate
                    import hashlib

                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend

                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())

                    # Get SHA256 fingerprint
                    fingerprint = hashlib.sha256(cert).hexdigest()

                    # Get SANs
                    sans = []
                    try:
                        san_ext = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        sans = san_ext.value.get_values_for_type(x509.DNSName)
                    except x509.ExtensionNotFound:
                        pass

                    return {
                        "subject": str(x509_cert.subject),
                        "issuer": str(x509_cert.issuer),
                        "serial_number": str(x509_cert.serial_number),
                        "sha256_fingerprint": fingerprint,
                        "not_before": x509_cert.not_valid_before_utc.replace(tzinfo=UTC),
                        "not_after": x509_cert.not_valid_after_utc.replace(tzinfo=UTC),
                        "sans": sans,
                        "version": x509_cert.version.name,
                        "signature_algorithm": x509_cert.signature_hash_algorithm.name if x509_cert.signature_hash_algorithm else "unknown",
                    }
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Error parsing certificate: %s", e)

        return None


# Register plugin
register_plugin(TLSAnalysisPlugin())
