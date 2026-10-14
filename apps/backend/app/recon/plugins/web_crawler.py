"""
Web Application Attack-Surface Mapping Plugin (Phase 9).

Implements controlled crawling, HTTP profiling, endpoint discovery,
parameter extraction, form analysis, JavaScript endpoint discovery,
technology detection, security-header analysis, cookie analysis,
TLS analysis, CORS observations, redirect analysis, and
application-entry-point mapping for authorized web targets.
"""

import asyncio
import logging
import re
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, ClassVar
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.models.enums import ScopeRuleTargetType
from app.recon.base import (
    ReconContext,
    ReconPlugin,
    ReconPluginConfig,
    ReconResult,
    register_plugin,
)

logger = logging.getLogger(__name__)


# ---- Configuration Models -----------------------------------------------------


@dataclass
class CrawlerConfig:
    """Configuration for web crawler."""

    max_depth: int = 3
    max_pages: int = 100
    max_concurrency: int = 5
    requests_per_second: float = 10.0
    timeout_seconds: float = 30.0
    max_content_size: int = 10 * 1024 * 1024  # 10 MB
    content_types: list[str] = field(
        default_factory=lambda: [
            "text/html",
            "application/xhtml+xml",
            "application/json",
            "text/javascript",
            "application/javascript",
        ]
    )
    respect_robots_txt: bool = True
    follow_redirects: bool = True
    max_redirects: int = 10
    user_agent: str = "SecurityAssessmentBot/1.0 (+https://example.com/bot)"
    enable_js_discovery: bool = True
    enable_form_analysis: bool = True
    enable_source_map: bool = True


# ---- SSRF Protection ----------------------------------------------------------


class SSRFProtector:
    """Protects against SSRF attacks during server-side requests."""

    # RFC 1918 private ranges
    PRIVATE_RANGES: ClassVar[list[tuple[str, str]]] = [
        ("10.0.0.0", "10.255.255.255"),  # 10.0.0.0/8
        ("172.16.0.0", "172.31.255.255"),  # 172.16.0.0/12
        ("192.168.0.0", "192.168.255.255"),  # 192.168.0.0/16
    ]

    # Loopback
    LOOPBACK_RANGES: ClassVar[list[tuple[str, str]]] = [
        ("127.0.0.0", "127.255.255.255"),
        ("::1", "::1"),
    ]

    # Link-local
    LINK_LOCAL_RANGES: ClassVar[list[tuple[str, str]]] = [
        ("169.254.0.0", "169.254.255.255"),
        ("fe80::", "fe80::ffff:ffff:ffff:ffff"),
    ]

    # Cloud metadata endpoints
    CLOUD_METADATA_IPS: ClassVar[list[str]] = [
        "169.254.169.254",  # AWS, GCP, Azure, DigitalOcean
        "169.254.169.253",  # Azure
    ]

    # Cloud metadata hostnames
    CLOUD_METADATA_HOSTS: ClassVar[list[str]] = [
        "metadata.google.internal",
        "metadata.aws.internal",
        "metadata.azure.internal",
        "169.254.169.254",
        "instance-data.ec2.internal",
    ]

    def __init__(self, allowed_scope_domains: list[str] | None = None):
        self.allowed_scope_domains = allowed_scope_domains or []

    def _ip_to_int(self, ip: str) -> int | None:
        """Convert IP address to integer for range comparison."""
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                return sum(int(part) << (8 * (3 - i)) for i, part in enumerate(parts))
        except ValueError:
            pass
        return None

    def _is_ip_in_ranges(self, ip: str, ranges: list[tuple[str, str]]) -> bool:
        """Check if IP is in any of the given ranges."""
        ip_int = self._ip_to_int(ip)
        if ip_int is None:
            return False

        for start, end in ranges:
            start_int = self._ip_to_int(start)
            end_int = self._ip_to_int(end)
            if start_int is not None and end_int is not None:
                if start_int <= ip_int <= end_int:
                    return True
        return False

    def _resolve_host(self, host: str) -> list[str]:
        """Resolve hostname to IPs (synchronously for validation)."""
        import socket

        try:
            return [info[4][0] for info in socket.getaddrinfo(host, None)]
        except (socket.gaierror, OSError):
            return []

    def validate_url(self, url: str, scope_rules: list | None = None) -> tuple[bool, str | None]:
        """
        Validate URL against SSRF protections and scope rules.

        Returns:
            tuple: (is_allowed, error_message)
        """
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Invalid URL: {e}"

        # Must use HTTP/HTTPS
        if parsed.scheme not in ("http", "https"):
            return False, f"Scheme {parsed.scheme} not allowed"

        host = parsed.hostname or ""
        if not host:
            return False, "No hostname in URL"

        # Check if host is in allowed scope domains
        if scope_rules:
            in_scope = False
            for rule in scope_rules:
                if rule.target_type == ScopeRuleTargetType.URL:
                    pattern = rule.pattern
                    # Simple pattern matching for URL scope
                    if pattern.endswith("*"):
                        prefix = pattern[:-1]
                        if url.startswith(prefix):
                            in_scope = True
                            break
                    elif url == pattern:
                        in_scope = True
                        break
                elif rule.target_type == ScopeRuleTargetType.DOMAIN:
                    if host == rule.pattern or host.endswith("." + rule.pattern):
                        in_scope = True
                        break
                elif rule.target_type == ScopeRuleTargetType.SUBDOMAIN_PATTERN:
                    if rule.pattern.startswith("*."):
                        suffix = rule.pattern[1:]
                        if host.endswith(suffix):
                            in_scope = True
                            break
            if not in_scope:
                return False, "URL not in authorized scope"

        # Resolve host to check for private IPs
        ips = self._resolve_host(host)
        for ip in ips:
            # Check private ranges
            if self._is_ip_in_ranges(ip, self.PRIVATE_RANGES):
                return False, f"Private IP address not allowed: {ip}"

            # Check loopback
            if self._is_ip_in_ranges(ip, self.LOOPBACK_RANGES):
                return False, f"Loopback address not allowed: {ip}"

            # Check link-local
            if self._is_ip_in_ranges(ip, self.LINK_LOCAL_RANGES):
                return False, f"Link-local address not allowed: {ip}"

            # Check cloud metadata IPs
            if ip in self.CLOUD_METADATA_IPS:
                return False, f"Cloud metadata endpoint not allowed: {ip}"

        # Check cloud metadata hostnames
        if host in self.CLOUD_METADATA_HOSTS:
            return False, f"Cloud metadata hostname not allowed: {host}"

        return True, None


# ---- URL Normalization & Deduplication ----------------------------------------


class URLNormalizer:
    """Normalizes and deduplicates URLs."""

    def __init__(self):
        self.seen_urls: set[str] = set()
        self.seen_normalized: set[str] = set()

    def normalize(self, url: str, base_url: str | None = None) -> str | None:
        """Normalize URL for deduplication."""
        try:
            # Resolve relative URLs
            if base_url and not urlparse(url).netloc:
                url = urljoin(base_url, url)

            parsed = urlparse(url)

            # Normalize scheme
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                return None

            # Normalize host
            host = (parsed.hostname or "").lower()

            # Remove default ports
            port = parsed.port
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                port = None

            # Normalize path
            path = parsed.path or "/"
            # Remove duplicate slashes
            path = re.sub(r"/+", "/", path)
            # Remove trailing slash unless it's the root
            if len(path) > 1 and path.endswith("/"):
                path = path[:-1]

            # Sort query parameters for consistent normalization
            query = ""
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                sorted_params = sorted(params.items())
                query = "&".join(f"{k}={v[0]}" for k, v in sorted_params)

            # Remove fragment
            fragment = ""

            normalized = urllib.parse.urlunparse(
                (scheme, f"{host}:{port}" if port else host, path, "", query, fragment)
            )

            return normalized

        except Exception:
            return None

    def is_duplicate(self, url: str, base_url: str | None = None) -> bool:
        """Check if URL has been seen before."""
        normalized = self.normalize(url, base_url)
        if normalized is None:
            return True

        if normalized in self.seen_normalized:
            return True

        self.seen_normalized.add(normalized)
        self.seen_urls.add(url)
        return False


# ---- HTTP Client with Security -------------------------------------------------


class SecureHTTPClient:
    """HTTP client with SSRF protection and security headers."""

    def __init__(
        self,
        config: CrawlerConfig,
        ssrf_protector: SSRFProtector,
        scope_rules: list | None = None,
    ):
        self.config = config
        self.ssrf_protector = ssrf_protector
        self.scope_rules = scope_rules or []

        # Create SSL context with secure defaults
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED

        # Create client with limits
        limits = httpx.Limits(
            max_connections=config.max_concurrency,
            max_keepalive_connections=config.max_concurrency,
        )

        self.client = httpx.AsyncClient(
            limits=limits,
            timeout=httpx.Timeout(config.timeout_seconds),
            follow_redirects=config.follow_redirects,
            max_redirects=config.max_redirects,
            headers={"User-Agent": config.user_agent},
        )

    async def get(self, url: str) -> httpx.Response | None:
        """Perform GET request with security checks."""
        # Validate URL
        allowed, error = self.ssrf_protector.validate_url(url, self.scope_rules)
        if not allowed:
            logger.warning(f"URL blocked by security policy: {url} - {error}")
            return None

        try:
            response = await self.client.get(url)
            return response
        except httpx.TimeoutException:
            logger.warning(f"Request timeout: {url}")
            return None
        except httpx.TooManyRedirects:
            logger.warning(f"Too many redirects: {url}")
            return None
        except Exception as e:
            logger.warning(f"Request failed: {url} - {e}")
            return None

    async def head(self, url: str) -> httpx.Response | None:
        """Perform HEAD request with security checks."""
        allowed, _ = self.ssrf_protector.validate_url(url, self.scope_rules)
        if not allowed:
            return None

        try:
            return await self.client.head(url)
        except Exception as e:
            logger.warning(f"HEAD request failed: {url} - {e}")
            return None

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()


# ---- Content Analysis ---------------------------------------------------------


class ContentAnalyzer:
    """Analyzes HTTP responses for security-relevant information."""

    def __init__(self, config: CrawlerConfig):
        self.config = config

    def analyze_headers(self, response: httpx.Response, url: str) -> list[ReconResult]:
        """Extract security-relevant headers."""
        results = []
        headers = response.headers

        # Security headers
        security_headers = {
            "strict-transport-security": "hsts",
            "content-security-policy": "csp",
            "x-frame-options": "xfo",
            "x-content-type-options": "xcto",
            "x-xss-protection": "xxp",
            "referrer-policy": "referrer_policy",
            "permissions-policy": "permissions_policy",
            "cross-origin-opener-policy": "coop",
            "cross-origin-embedder-policy": "coep",
            "cross-origin-resource-policy": "corp",
        }

        for header, name in security_headers.items():
            value = headers.get(header)
            if value:
                results.append(
                    ReconResult(
                        asset_kind="endpoint",
                        value=url,
                        source="web_crawler",
                        attributes={
                            "type": "security_header",
                            "header": name,
                            "value": value,
                        },
                        confidence="high",
                    )
                )
            else:
                # Missing security header
                results.append(
                    ReconResult(
                        asset_kind="endpoint",
                        value=url,
                        source="web_crawler",
                        attributes={
                            "type": "missing_security_header",
                            "header": name,
                        },
                        confidence="medium",
                    )
                )

        # Server header
        server = headers.get("server")
        if server:
            results.append(
                ReconResult(
                    asset_kind="technology",
                    value=f"{url}:server:{server}",
                    source="web_crawler",
                    attributes={
                        "type": "server_header",
                        "value": server,
                        "url": url,
                    },
                    confidence="high",
                )
            )

        # Powered-by
        powered_by = headers.get("x-powered-by")
        if powered_by:
            results.append(
                ReconResult(
                    asset_kind="technology",
                    value=f"{url}:x-powered-by:{powered_by}",
                    source="web_crawler",
                    attributes={
                        "type": "x_powered_by",
                        "value": powered_by,
                        "url": url,
                    },
                    confidence="high",
                )
            )

        return results

    def analyze_cookies(self, response: httpx.Response, url: str) -> list[ReconResult]:
        """Analyze cookies for security attributes."""
        results = []
        set_cookie_headers = response.headers.get_list("set-cookie")

        for cookie_header in set_cookie_headers:
            cookie_name = cookie_header.split("=")[0] if "=" in cookie_header else "unknown"

            attributes = {
                "url": url,
                "cookie_name": cookie_name,
                "raw": cookie_header,
            }

            # Check security flags
            cookie_lower = cookie_header.lower()
            attributes["secure"] = "secure" in cookie_lower
            attributes["httponly"] = "httponly" in cookie_lower
            attributes["samesite"] = "samesite" in cookie_lower

            if "samesite" in cookie_lower:
                # Extract SameSite value
                match = re.search(r"samesite=([^;]+)", cookie_lower)
                if match:
                    attributes["samesite_value"] = match.group(1).strip()

            # Check for missing security flags
            issues = []
            if not attributes["secure"]:
                issues.append("missing_secure")
            if not attributes["httponly"]:
                issues.append("missing_httponly")
            if "samesite" not in cookie_lower:
                issues.append("missing_samesite")

            attributes["issues"] = issues

            results.append(
                ReconResult(
                    asset_kind="endpoint",
                    value=url,
                    source="web_crawler",
                    attributes={
                        "type": "cookie_analysis",
                        **attributes,
                    },
                    confidence="high",
                )
            )

        return results

    def analyze_cors(self, response: httpx.Response, url: str) -> list[ReconResult]:
        """Analyze CORS headers."""
        results = []
        headers = response.headers

        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")
        acam = headers.get("access-control-allow-methods")
        acah = headers.get("access-control-allow-headers")

        if acao or acac or acam or acah:
            results.append(
                ReconResult(
                    asset_kind="endpoint",
                    value=url,
                    source="web_crawler",
                    attributes={
                        "type": "cors",
                        "access_control_allow_origin": acao,
                        "access_control_allow_credentials": acac == "true",
                        "access_control_allow_methods": acam,
                        "access_control_allow_headers": acah,
                        "issues": [],
                    },
                    confidence="high",
                )
            )

            # Check for overly permissive CORS
            if acao == "*" and acac == "true":
                results[-1].attributes["issues"].append("wildcard_with_credentials")

        return results

    def analyze_tls(self, response: httpx.Response, url: str) -> list[ReconResult]:
        """Analyze TLS configuration (requires access to connection info)."""
        # This would require access to the underlying TLS connection
        # httpx doesn't expose this easily, so we return empty for now
        # In production, you'd use a custom transport or separate TLS scanner
        return []

    def analyze_redirects(
        self, response: httpx.Response, url: str, original_url: str
    ) -> list[ReconResult]:
        """Analyze redirect chain."""
        results = []
        if response.history:
            redirect_chain = [str(r.url) for r in response.history]
            redirect_chain.append(str(response.url))

            results.append(
                ReconResult(
                    asset_kind="endpoint",
                    value=original_url,
                    source="web_crawler",
                    attributes={
                        "type": "redirect_chain",
                        "chain": redirect_chain,
                        "final_url": str(response.url),
                        "redirect_count": len(response.history),
                    },
                    confidence="high",
                )
            )

        return results

    def analyze_forms(self, soup: BeautifulSoup, url: str) -> list[ReconResult]:
        """Extract and analyze HTML forms."""
        results = []
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action", "")
            method = (form.get("method", "GET")).upper()
            enctype = form.get("enctype", "application/x-www-form-urlencoded")

            # Resolve action URL
            if action:
                action_url = urljoin(url, action)
            else:
                action_url = url

            # Extract inputs
            inputs = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_data = {
                    "name": input_tag.get("name"),
                    "type": input_tag.get("type", "text"),
                    "required": input_tag.has_attr("required"),
                }
                if input_tag.name == "select":
                    options = [opt.get("value", opt.text) for opt in input_tag.find_all("option")]
                    input_data["options"] = options
                inputs.append(input_data)

            # Check for sensitive fields
            sensitive_fields = []
            for inp in inputs:
                name = (inp.get("name") or "").lower()
                if any(
                    kw in name
                    for kw in [
                    "password",
                    "passwd",
                    "secret",
                    "token",
                    "key",
                    "auth",
                    "credit",
                    "card",
                    "cvv",
                    "ssn",
                ]
                ):
                    sensitive_fields.append(name)

            results.append(
                ReconResult(
                    asset_kind="endpoint",
                    value=action_url,
                    source="web_crawler",
                    attributes={
                        "type": "form",
                        "action": action_url,
                        "method": method,
                        "enctype": enctype,
                        "inputs": inputs,
                        "sensitive_fields": sensitive_fields,
                        "source_url": url,
                    },
                    confidence="high",
                )
            )

        return results

    def analyze_javascript(
        self, soup: BeautifulSoup, url: str, response_text: str
    ) -> list[ReconResult]:
        """Discover endpoints in JavaScript code."""
        results = []
        scripts = soup.find_all("script")

        # Common endpoint patterns in JS
        endpoint_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'\.ajax\(["\']([^"\']+)["\']',
            r'XMLHttpRequest\(\)\.open\(["\']\w+["\'],\s*["\']([^"\']+)["\']',
        ]

        # Also check source maps if enabled
        source_map_urls = re.findall(r'//# sourceMappingURL=([^\s]+)', response_text)
        for sm_url in source_map_urls:
            full_sm_url = urljoin(url, sm_url)
            results.append(
                ReconResult(
                    asset_kind="endpoint",
                    value=full_sm_url,
                    source="web_crawler",
                    attributes={
                        "type": "source_map",
                        "source_url": url,
                    },
                    confidence="medium",
                )
            )

        # Extract endpoints from inline scripts
        for script in scripts:
            if script.string:
                content = script.string
                for pattern in endpoint_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[-1]  # Get the last group
                        endpoint = urljoin(url, match)
                        results.append(
                            ReconResult(
                                asset_kind="endpoint",
                                value=endpoint,
                                source="web_crawler",
                                attributes={
                                    "type": "js_endpoint",
                                    "pattern": pattern,
                                    "source_url": url,
                                },
                                confidence="medium",
                            )
                        )

        return results

    def analyze_links(self, soup: BeautifulSoup, url: str) -> list[str]:
        """Extract all links from page."""
        links = []
        for link in soup.find_all("a", href=True):
            href = link["href"]
            absolute = urljoin(url, href)
            links.append(absolute)
        return links


# ---- Web Crawler Plugin -------------------------------------------------------


class WebCrawlerPlugin(ReconPlugin):
    """Web application attack-surface mapping plugin."""

    def __init__(self):
        self._results_cache: list[ReconResult] = []

    @property
    def config(self) -> ReconPluginConfig:
        return ReconPluginConfig(
            name="web_crawler",
            version="1.0.0",
            description="Web application attack-surface mapping with controlled crawling",
            target_types=["url", "web_application"],
            requires_network=True,
            timeout_seconds=3600,  # 1 hour max
            rate_limit_per_minute=60,
            configuration_schema={
                "type": "object",
                "properties": {
                    "max_depth": {
                        "type": "integer",
                        "default": 3,
                        "minimum": 1,
                        "maximum": 10,
                    },
                    "max_pages": {
                        "type": "integer",
                        "default": 100,
                        "minimum": 1,
                        "maximum": 10000,
                    },
                    "max_concurrency": {
                        "type": "integer",
                        "default": 5,
                        "minimum": 1,
                        "maximum": 50,
                    },
                    "requests_per_second": {
                        "type": "number",
                        "default": 10.0,
                        "minimum": 0.1,
                        "maximum": 100,
                    },
                    "timeout_seconds": {
                        "type": "number",
                        "default": 30.0,
                        "minimum": 5,
                        "maximum": 300,
                    },
                    "max_content_size": {
                        "type": "integer",
                        "default": 10485760,
                    },
                    "respect_robots_txt": {
                        "type": "boolean",
                        "default": True,
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "default": True,
                    },
                    "max_redirects": {
                        "type": "integer",
                        "default": 10,
                        "minimum": 0,
                        "maximum": 50,
                    },
                    "user_agent": {
                        "type": "string",
                        "default": "SecurityAssessmentBot/1.0",
                    },
                    "enable_js_discovery": {
                        "type": "boolean",
                        "default": True,
                    },
                    "enable_form_analysis": {
                        "type": "boolean",
                        "default": True,
                    },
                    "enable_source_map": {
                        "type": "boolean",
                        "default": True,
                    },
                },
            },
        )

    def validate(self, context: ReconContext) -> tuple[bool, str | None]:
        """Validate that target is a URL or web application."""
        if context.target_type not in ("url", "web_application"):
            return False, f"Target type {context.target_type} not supported by web crawler"

        # Validate URL format
        try:
            parsed = urlparse(context.target_value)
            if not parsed.scheme or not parsed.netloc:
                return False, "Invalid target URL"
            if parsed.scheme not in ("http", "https"):
                return False, "Only HTTP/HTTPS targets supported"
        except Exception as e:
            return False, f"Invalid URL: {e}"

        return True, None

    def run(self, context: ReconContext) -> list[ReconResult]:
        """Run the web crawler."""
        # Parse configuration
        crawler_config = CrawlerConfig(
            max_depth=context.configuration.get("max_depth", 3),
            max_pages=context.configuration.get("max_pages", 100),
            max_concurrency=context.configuration.get("max_concurrency", 5),
            requests_per_second=context.configuration.get("requests_per_second", 10.0),
            timeout_seconds=context.configuration.get("timeout_seconds", 30.0),
            max_content_size=context.configuration.get("max_content_size", 10 * 1024 * 1024),
            respect_robots_txt=context.configuration.get("respect_robots_txt", True),
            follow_redirects=context.configuration.get("follow_redirects", True),
            max_redirects=context.configuration.get("max_redirects", 10),
            user_agent=context.configuration.get("user_agent", "SecurityAssessmentBot/1.0"),
            enable_js_discovery=context.configuration.get("enable_js_discovery", True),
            enable_form_analysis=context.configuration.get("enable_form_analysis", True),
            enable_source_map=context.configuration.get("enable_source_map", True),
        )

        # Build scope rules for SSRF protector
        scope_rules = []
        for rule_data in context.scope_rules:

            class RuleProxy:
                def __init__(self, data: dict[str, Any]) -> None:
                    self.effect = data["effect"]
                    self.target_type = data["target_type"]
                    self.pattern = data["pattern"]

            scope_rules.append(RuleProxy(rule_data))

        # Initialize components
        ssrf_protector = SSRFProtector()
        url_normalizer = URLNormalizer()
        analyzer = ContentAnalyzer(crawler_config)
        http_client = SecureHTTPClient(crawler_config, ssrf_protector, scope_rules)

        # Rate limiting
        rate_limit_delay = 1.0 / crawler_config.requests_per_second
        last_request_time = 0.0

        # Crawl state
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        visited: set[str] = set()
        results: list[ReconResult] = []

        # Add initial URL
        normalized_start = url_normalizer.normalize(context.target_value)
        if normalized_start:
            queue.put_nowait((normalized_start, 0))

        async def crawl() -> None:
            nonlocal last_request_time

            while not queue.empty() and len(visited) < crawler_config.max_pages:
                try:
                    current_url, depth = await asyncio.wait_for(queue.get(), timeout=1.0)
                except TimeoutError:
                    break

                if current_url in visited or depth > crawler_config.max_depth:
                    continue

                visited.add(current_url)

                # Rate limiting
                now = time.time()
                elapsed = now - last_request_time
                if elapsed < rate_limit_delay:
                    await asyncio.sleep(rate_limit_delay - elapsed)
                last_request_time = time.time()

                # Make request
                response = await http_client.get(current_url)
                if not response:
                    continue

                # Check content type
                content_type = response.headers.get("content-type", "").split(";")[0].lower()
                if content_type not in crawler_config.content_types:
                    continue

                # Check content size
                if len(response.content) > crawler_config.max_content_size:
                    logger.warning(f"Content too large: {current_url}")
                    continue

                # Analyze response
                page_results = []

                # Header analysis
                page_results.extend(analyzer.analyze_headers(response, current_url))

                # Cookie analysis
                page_results.extend(analyzer.analyze_cookies(response, current_url))

                # CORS analysis
                page_results.extend(analyzer.analyze_cors(response, current_url))

                # Redirect analysis
                page_results.extend(
                    analyzer.analyze_redirects(
                        response, current_url, context.target_value
                    )
                )

                # Parse HTML
                soup = None
                response_text = ""
                if "html" in content_type:
                    try:
                        response_text = response.text
                        soup = BeautifulSoup(response_text, "lxml")
                    except Exception as e:
                        logger.warning(f"Failed to parse HTML: {current_url} - {e}")

                if soup:
                    # Form analysis
                    if crawler_config.enable_form_analysis:
                        page_results.extend(analyzer.analyze_forms(soup, current_url))

                    # JavaScript endpoint discovery
                    if crawler_config.enable_js_discovery:
                        page_results.extend(
                            analyzer.analyze_javascript(soup, current_url, response_text)
                        )

                    # Extract links for crawling
                    if depth < crawler_config.max_depth:
                        links = analyzer.analyze_links(soup, current_url)
                        for link in links:
                            normalized = url_normalizer.normalize(link, current_url)
                            if normalized and normalized not in visited:
                                queue.put_nowait((normalized, depth + 1))

                # Add page results
                for result in page_results:
                    result.scope_status = "unknown"  # Will be evaluated by engine
                    results.append(result)

                # Emit progress event
                self._emit_event(
                    context.scan_id,
                    context.scan_job_id,
                    "crawler.progress",
                    "info",
                    f"Crawled {current_url} (depth {depth}, pages {len(visited)})",
                    {"url": current_url, "depth": depth, "pages_crawled": len(visited)},
                )

        # Run async crawl
        asyncio.run(crawl())

        # Close HTTP client
        asyncio.run(http_client.close())

        return results

    def normalize(self, raw_results: list[Any], context: ReconContext) -> list[ReconResult]:
        """Normalize raw results."""
        return raw_results


# Register plugin
register_plugin(WebCrawlerPlugin())
