"""Technology fingerprinting recon plugin."""

import re
import ssl
import urllib.error
import urllib.request
from typing import Any

from app.recon.base import (
    ReconContext,
    ReconPlugin,
    ReconPluginConfig,
    ReconResult,
    register_plugin,
)


class TechnologyFingerprintingPlugin(ReconPlugin):
    """Technology fingerprinting plugin - identifies technologies used by web applications."""

    # Technology signatures
    TECH_SIGNATURES: dict[str, dict[str, Any]] = {
        "nginx": {
            "headers": {"server": r"nginx"},
            "body": [],
        },
        "apache": {
            "headers": {"server": r"apache"},
            "body": [],
        },
        "cloudflare": {
            "headers": {"server": r"cloudflare", "cf-ray": r".+"},
            "body": [],
        },
        "aws": {
            "headers": {"server": r"awselb|amazon|aws", "x-amz-cf-id": r".+"},
            "body": [],
        },
        "wordpress": {
            "headers": {},
            "body": [r"wp-content", r"wp-includes", r"wordpress"],
        },
        "drupal": {
            "headers": {"x-drupal-cache": r".+", "x-generator": r"drupal"},
            "body": [r"drupal"],
        },
        "joomla": {
            "headers": {},
            "body": [r"joomla", r"com_content"],
        },
        "react": {
            "headers": {},
            "body": [r"react", r"_reactroot"],
        },
        "vue": {
            "headers": {},
            "body": [r"vue\.js", r"data-v-"],
        },
        "angular": {
            "headers": {},
            "body": [r"ng-", r"angular"],
        },
        "jquery": {
            "headers": {},
            "body": [r"jquery"],
        },
        "bootstrap": {
            "headers": {},
            "body": [r"bootstrap"],
        },
        "php": {
            "headers": {"x-powered-by": r"php"},
            "body": [],
        },
        "asp.net": {
            "headers": {"x-powered-by": r"asp\.net", "x-aspnet-version": r".+"},
            "body": [r"__viewstate", r"__eventvalidation"],
        },
        "express": {
            "headers": {"x-powered-by": r"express"},
            "body": [],
        },
        "django": {
            "headers": {},
            "body": [r"csrfmiddlewaretoken", r"django"],
        },
        "rails": {
            "headers": {"x-powered-by": r"rails", "x-runtime": r".+"},
            "body": [r"rails"],
        },
        "laravel": {
            "headers": {},
            "body": [r"laravel_session", r"XSRF-TOKEN"],
        },
        "spring": {
            "headers": {"x-powered-by": r"spring", "server": r"spring"},
            "body": [r"jsessionid"],
        },
        "node.js": {
            "headers": {"x-powered-by": r"node"},
            "body": [],
        },
        "python": {
            "headers": {"server": r"python", "x-powered-by": r"python"},
            "body": [],
        },
        "go": {
            "headers": {"server": r"go"},
            "body": [],
        },
    }

    @property
    def config(self) -> ReconPluginConfig:
        return ReconPluginConfig(
            name="technology_fingerprinting",
            version="1.0.0",
            description="Identify technologies, frameworks, and servers used by web applications",
            target_types=["domain", "subdomain", "ip", "url"],
            requires_network=True,
            timeout_seconds=60,
            rate_limit_per_minute=20,
        )

    def validate(self, context: ReconContext) -> tuple[bool, str | None]:
        """Validate that target can be fingerprinted."""
        if context.target_type not in ("domain", "subdomain", "ip", "url"):
            return False, f"Target type {context.target_type} not supported by technology fingerprinting"
        return True, None

    def run(self, context: ReconContext) -> list[ReconResult]:
        """Run technology fingerprinting."""
        results: list[ReconResult] = []

        # Determine URLs to check
        urls = self._get_urls_to_check(context.target_value, context.target_type)

        for url in urls:
            tech_results = self._fingerprint_url(url, context.target_value)
            results.extend(tech_results)

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

    def _fingerprint_url(self, url: str, original_target: str) -> list[ReconResult]:
        """Fingerprint a single URL."""
        results: list[ReconResult] = []

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)"},
            )
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=10, context=context) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                body = response.read().decode("utf-8", errors="ignore")
                status_code = response.getcode()

                # Match technology signatures
                detected_techs = self._match_signatures(headers, body)

                for tech_name, tech_info in detected_techs.items():
                    results.append(ReconResult(
                        asset_kind="technology",
                        value=f"{original_target}:{tech_name}",
                        attributes={
                            "technology": tech_name,
                            "category": tech_info["category"],
                            "version": tech_info.get("version"),
                            "confidence": tech_info["confidence"],
                            "evidence": tech_info["evidence"],
                            "url": url,
                            "original_target": original_target,
                            "status_code": status_code,
                        },
                        relationships=[
                            {
                                "target_value": original_target,
                                "relationship_type": "uses",
                                "note": f"Uses {tech_name} ({tech_info['category']})",
                            }
                        ],
                        source=self.config.name,
                        confidence=tech_info["confidence"].lower(),
                    ))

        except urllib.error.HTTPError as e:
            # Even error responses give us headers
            headers = {k.lower(): v for k, v in e.headers.items()}
            detected_techs = self._match_signatures(headers, "")

            for tech_name, tech_info in detected_techs.items():
                results.append(ReconResult(
                    asset_kind="technology",
                    value=f"{original_target}:{tech_name}",
                    attributes={
                        "technology": tech_name,
                        "category": tech_info["category"],
                        "version": tech_info.get("version"),
                        "confidence": tech_info["confidence"],
                        "evidence": tech_info["evidence"],
                        "url": url,
                        "original_target": original_target,
                        "status_code": e.code,
                    },
                    relationships=[
                        {
                            "target_value": original_target,
                            "relationship_type": "uses",
                            "note": f"Uses {tech_name} ({tech_info['category']})",
                        }
                    ],
                    source=self.config.name,
                    confidence=tech_info["confidence"].lower(),
                ))
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Error fingerprinting %s: %s", url, e)

        return results

    def _match_signatures(
        self, headers: dict[str, str], body: str
    ) -> dict[str, dict[str, Any]]:
        """Match technology signatures against headers and body."""
        detected: dict[str, dict[str, Any]] = {}

        for tech_name, signatures in self.TECH_SIGNATURES.items():
            evidence = []
            confidence = "low"
            category = "unknown"
            version = None

            # Check headers
            for header_name, pattern in signatures["headers"].items():
                if header_name in headers:
                    header_value = headers[header_name]
                    if re.search(pattern, header_value, re.IGNORECASE):
                        evidence.append(f"Header {header_name}: {header_value[:100]}")
                        confidence = "high"
                        # Try to extract version
                        version_match = re.search(r"(\d+\.\d+(\.\d+)?)", header_value)
                        if version_match:
                            version = version_match.group(1)

            # Check body
            for pattern in signatures["body"]:
                if re.search(pattern, body, re.IGNORECASE):
                    evidence.append(f"Body pattern: {pattern}")
                    if confidence == "low":
                        confidence = "medium"

            if evidence:
                # Categorize technology
                if tech_name in ("nginx", "apache", "cloudflare", "aws", "aws"):
                    category = "web_server"
                elif tech_name in ("wordpress", "drupal", "joomla"):
                    category = "cms"
                elif tech_name in ("react", "vue", "angular", "jquery", "bootstrap"):
                    category = "frontend_framework"
                elif tech_name in ("php", "asp.net", "express", "django", "rails", "laravel", "spring", "node.js", "python", "go"):
                    category = "backend_framework"

                detected[tech_name] = {
                    "category": category,
                    "version": version,
                    "confidence": confidence,
                    "evidence": evidence,
                }

        return detected


# Register plugin
register_plugin(TechnologyFingerprintingPlugin())
