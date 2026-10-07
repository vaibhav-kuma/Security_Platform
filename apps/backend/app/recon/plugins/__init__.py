"""Recon plugins package - auto-registers all plugins."""

# Import all plugins to register them
import app.recon.plugins.asset_relationship
import app.recon.plugins.api_security_scanner
import app.recon.plugins.dns_discovery
import app.recon.plugins.dns_resolution
import app.recon.plugins.http_detection
import app.recon.plugins.ip_correlation
import app.recon.plugins.subdomain_discovery
import app.recon.plugins.technology_fingerprinting
import app.recon.plugins.tls_analysis
import app.recon.plugins.web_crawler

# Re-export base classes for convenience
from app.recon.base import (
    ReconContext,
    ReconPlugin,
    ReconPluginConfig,
    ReconPluginRegistry,
    ReconResult,
    get_plugin_registry,
    register_plugin,
    unregister_plugin,
)

__all__ = [
    "ReconContext",
    "ReconPlugin",
    "ReconPluginConfig",
    "ReconPluginRegistry",
    "ReconResult",
    "get_plugin_registry",
    "register_plugin",
    "unregister_plugin",
]
