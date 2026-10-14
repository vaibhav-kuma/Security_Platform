"""HTTP/HTTPS detection recon plugin."""

import ssl
import urllib.error
import urllib.request

from app.recon.base import (
    ReconContext,
    ReconPlugin,
    ReconPluginConfig,
    ReconResult,
    register_plugin,
)


class HTTPDetectionPlugin(ReconPlugin):
    """HTTP/HTTPS detection plugin - detects web servers and basic info."""

    @property
    def config(self) -> ReconPluginConfig:
        return ReconPluginConfig(
            name="http_detection",
            version="1.0.0",
            description="Detect HTTP/HTTPS services, server headers, and basic web info",
            target_types=["domain", "subdomain", "ip", "url"],
            requires_network=True,
            timeout_seconds=60,
            rate_limit_per_minute=30,
        )

    def validate(self, context: ReconContext) -> tuple[bool, str | None]:
        """Validate that target can be checked for HTTP."""
        if context.target_type not in ("domain", "subdomain", "ip", "url"):
            return False, f"Target type {context.target_type} not supported by HTTP detection"
        return True, None

    def run(self, context: ReconContext) -> list[ReconResult]:
        """Run HTTP/HTTPS detection."""
        results: list[ReconResult] = []

        # Determine URLs to check
        urls = self._get_urls_to_check(context.target_value, context.target_type)

        for url in urls:
            result = self._check_url(url, context.target_value)
            if result:
                results.append(result)

        return results

    def _get_urls_to_check(self, target: str, target_type: str) -> list[str]:
        """Get list of URLs to check based on target."""
        urls = []

        if target_type == "url":
            urls.append(target)
        elif target_type in ("domain", "subdomain"):
            urls.append(f"https://{target}")
            urls.append(f"http://{target}")
        elif target_type == "ip":
            urls.append(f"https://{target}")
            urls.append(f"http://{target}")

        return urls

    def _check_url(self, url: str, original_target: str) -> ReconResult | None:
        """Check a single URL."""
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"},
            )
            # Disable SSL verification for detection (we'll do proper TLS analysis separately)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=10, context=context) as response:
                headers = dict(response.headers)
                server = headers.get("Server", "")
                content_type = headers.get("Content-Type", "")
                status_code = response.getcode()

                # Determine asset kind
                if "api" in content_type.lower() or "json" in content_type.lower():
                    asset_kind = "endpoint"
                else:
                    asset_kind = "url"

                return ReconResult(
                    asset_kind=asset_kind,
                    value=url,
                    attributes={
                        "status_code": status_code,
                        "server": server,
                        "content_type": content_type,
                        "headers": headers,
                        "original_target": original_target,
                    },
                    relationships=[
                        {
                            "target_value": original_target,
                            "relationship_type": "serves",
                            "note": f"HTTP service on {original_target}",
                        }
                    ],
                    source=self.config.name,
                    confidence="high",
                )
        except urllib.error.HTTPError as e:
            # Even error responses give us info
            headers = dict(e.headers)
            server = headers.get("Server", "")
            return ReconResult(
                asset_kind="url",
                value=url,
                attributes={
                    "status_code": e.code,
                    "server": server,
                    "headers": headers,
                    "original_target": original_target,
                    "error": str(e),
                },
                relationships=[
                    {
                        "target_value": original_target,
                        "relationship_type": "serves",
                        "note": f"HTTP service on {original_target} (error {e.code})",
                    }
                ],
                source=self.config.name,
                confidence="medium",
            )
        except Exception:
            pass  # Expected HTTP errors (404, 500, etc.) are not logged

        return None


# Register plugin
register_plugin(HTTPDetectionPlugin())
