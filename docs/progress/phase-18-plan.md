# Phase 18 Implementation Plan

## Objective
Build the extensible scanner and methodology plugin ecosystem that allows external developers to add new recon, web, API, mobile, DNS, TLS, technology, configuration, vulnerability, and reporting capabilities without modifying core platform code.

## Architecture Changes

### 1. Plugin SDK Core (`app/plugins/sdk/`)
- **Base Classes**: `ScannerPlugin`, `MethodologyPlugin`, `ReportingPlugin`
- **Interfaces**: `validate()`, `scan()`, `normalize()` methods
- **Plugin Manifest**: Pydantic model for plugin metadata (name, version, category, capabilities, permissions, requirements, config schema)
- **Plugin Registry**: Central registry for plugin discovery, loading, validation
- **Plugin Loader**: Dynamic loading with validation, isolation, version checking

### 2. Permission System (`app/plugins/permissions.py`)
- **Permission Declarations**: `network.request`, `file.read`, `file.write`, `process.execute`, `database.query`, `cache.access`, `secret.read`
- **Permission Validator**: Validates plugin manifest permissions against policy
- **Execution Isolation**: CPU/memory/time limits via cgroups or resource limits
- **Network Policies**: Egress allowlist per plugin
- **Secure Artifact Handling**: Sandboxed file access

### 3. Plugin Models (`app/models/plugins.py`)
- **Plugin**: Installed plugin record (manifest, status, version, checksum)
- **PluginExecution**: Execution log with results, errors, resource usage
- **PluginPermission**: Granted permissions per plugin
- **PluginConfig**: User-defined configuration per plugin per project

### 4. Plugin Lifecycle Management (`app/services/plugins.py`)
- **Installation**: Upload, validate manifest, verify integrity, store
- **Validation**: Schema validation, compatibility checks, dependency resolution
- **Enablement/Disablement**: Toggle plugin active state
- **Execution**: Run with resource limits, timeout, permission enforcement
- **Versioning**: Upgrade/downgrade with migration support
- **Removal**: Clean uninstall with data cleanup option

### 5. API Endpoints (`app/api/v1/plugins.py`)
- `GET /plugins` - List available/installed plugins
- `POST /plugins` - Install plugin (upload manifest + code)
- `GET /plugins/{plugin_id}` - Get plugin details
- `PATCH /plugins/{plugin_id}` - Update plugin config/enable/disable
- `DELETE /plugins/{plugin_id}` - Uninstall plugin
- `POST /plugins/{plugin_id}/execute` - Execute plugin manually
- `GET /plugins/{plugin_id}/executions` - Execution history
- `GET /plugins/categories` - Plugin categories
- `GET /plugins/manifest-schema` - Manifest JSON schema

### 6. Sample Plugin (`app/plugins/samples/`)
- **Safe Recon Plugin**: Demonstrates full SDK lifecycle
- **Manifest**: Complete manifest with permissions
- **Code**: Implements validate/scan/normalize
- **Tests**: Unit tests for plugin behavior

### 7. Plugin Compatibility & Security
- **Manifest Schema Validation**: JSON Schema for plugin manifests
- **Integrity Verification**: SHA256 checksum verification
- **Version Pinning**: Compatible core version ranges
- **Audit Logging**: All plugin lifecycle events logged
- **Compatibility Matrix**: Core version ↔ plugin version compatibility

## Files to Create
- `app/plugins/__init__.py`
- `app/plugins/sdk/__init__.py`
- `app/plugins/sdk/base.py` - Base plugin classes
- `app/plugins/sdk/manifest.py` - Manifest model and validation
- `app/plugins/sdk/registry.py` - Plugin registry
- `app/plugins/sdk/loader.py` - Plugin loader with isolation
- `app/plugins/permissions.py` - Permission system
- `app/plugins/executor.py` - Secure plugin executor
- `app/models/plugins.py` - Database models
- `app/schemas/plugins.py` - API schemas
- `app/services/plugins.py` - Plugin lifecycle service
- `app/api/v1/plugins.py` - API endpoints
- `app/plugins/samples/safe_recon_plugin.py` - Sample plugin
- `app/plugins/samples/manifest.json` - Sample manifest
- `tests/test_plugins.py` - Plugin tests
- `docs/plugins/sdk-guide.md` - Developer documentation

## Files to Modify
- `app/models/__init__.py` - Export plugin models
- `app/schemas/__init__.py` - Export plugin schemas
- `app/services/__init__.py` - Export plugin service
- `app/api/v1/__init__.py` - Register plugin router
- `app/config.py` - Plugin settings
- `alembic migration` - Plugin tables

## Security Controls
- Plugin code runs in isolated environment (separate process/container)
- Permission system enforced at execution time
- Resource limits (CPU, memory, time) enforced
- Network egress controlled per plugin
- No direct filesystem access outside sandbox
- Secrets accessed only via declared permissions
- Plugin integrity verified before execution
- Audit trail for all plugin actions

## Tests
- Unit tests for manifest validation, registry, loader
- Integration tests for plugin install/execute/uninstall
- Security tests for permission enforcement, isolation
- Sample plugin tests
- Negative tests (invalid manifests, permission violations, resource exhaustion)

## Documentation
- SDK guide for third-party developers
- Manifest reference
- Permission reference
- Sample plugin walkthrough
- Security best practices