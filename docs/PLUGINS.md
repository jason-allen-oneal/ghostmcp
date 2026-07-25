# Plugin development

GhostMCP plugins are Python entry points that execute inside the GhostMCP process. They are disabled by default and must be explicitly enabled and allowlisted by both entry-point name and plugin name.

Treat every plugin as trusted code with the same privileges as the GhostMCP service account.

## Runtime enablement

```bash
export GHOSTMCP_ENABLE_PLUGINS=true
export GHOSTMCP_PLUGIN_GROUP=ghostmcp.plugins
export GHOSTMCP_PLUGIN_ALLOWLIST=my-approved-plugin
```

Startup fails if:

- Plugin loading is enabled without a non-empty allowlist.
- An allowlisted entry point is missing.
- The entry point does not instantiate `ghostmcp.plugins.Plugin`.
- The plugin's `name` property is not allowlisted.
- Two plugins have the same name.
- A plugin reports duplicate tool names.
- Two plugins register the same tool or parser name.

This fail-closed behavior is intentional.

## Plugin contract

A plugin subclasses `ghostmcp.plugins.Plugin` and implements:

```python
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ghostmcp.plugins import Plugin


class ExamplePlugin(Plugin):
    @property
    def name(self) -> str:
        return "my-approved-plugin"

    @property
    def version(self) -> str:
        return "0.1.0"

    def register_tools(self, mcp: Any) -> list[str]:
        @mcp.tool()
        def example_status_tool() -> dict[str, str]:
            return {"status": "ok"}

        return ["example_status_tool"]

    def register_parsers(self) -> dict[str, Callable[..., Any]]:
        return {}

    def get_config_schema(self) -> dict[str, Any]:
        return {}

    def validate_config(self, config: dict[str, Any]) -> bool:
        return True
```

The returned tool-name list is used for collision detection and inventory. It must exactly describe the tools registered by the plugin.

## Packaging

Declare the entry point in `pyproject.toml`:

```toml
[project]
name = "ghostmcp-plugin-example"
version = "0.1.0"
dependencies = ["ghostmcp-server>=0.2.0"]

[project.entry-points."ghostmcp.plugins"]
my-approved-plugin = "ghostmcp_plugin_example:ExamplePlugin"
```

The entry-point name, the plugin `name` property, and the allowlist value should match.

Install into the same virtual environment as GhostMCP:

```bash
python -m pip install --require-hashes -r plugin-requirements.lock.txt
```

Pin plugin distributions and transitive dependencies. Avoid installing directly from an unreviewed branch or mutable URL in production.

## Security requirements

A plugin should:

- Use typed parameters instead of arbitrary command strings.
- Reuse GhostMCP scope and engagement policy for every network target.
- Apply tool-level authorization before active or intrusive behavior.
- Avoid `shell=True` and shell interpolation.
- Use argument arrays for subprocesses.
- Set runtime and output limits.
- Redact secrets from logs, errors, commands, and return values.
- Restrict file access to configured roots.
- Emit audit events for guarded operations.
- Return structured data with stable schemas.
- Fail closed when configuration, credentials, or dependencies are missing.

A plugin must not bypass transport authentication, disable global policy, mutate another plugin's registration, or expose arbitrary Python evaluation.

## Configuration

`get_config_schema()` may return a plugin-defined schema for documentation or integration. `validate_config()` should reject unknown or unsafe values.

Recommended conventions:

- Prefix environment variables with `GHOSTMCP_PLUGIN_<NAME>_`.
- Keep secrets out of schema defaults.
- Validate file paths and network targets at startup and again before execution.
- Document every side effect and required capability.

The current core manager does not automatically source or persist plugin configuration. A plugin is responsible for reading its own configuration and validating it before registering dangerous functionality.

## Tool naming

Use globally unique names that end in `_tool`:

```text
vendor_product_inventory_tool
vendor_product_scan_tool
```

Avoid generic names such as `scan_tool`, `run_tool`, or names that resemble core tools. Collision detection prevents duplicate names, but descriptive naming also improves model selection and audit readability.

## Parser naming

Parser names also share one global namespace. Prefix them with the plugin or product name:

```text
vendor_product_json
vendor_product_xml
```

Parsers should accept bounded input, reject malformed data, and avoid entity expansion or unsafe deserialization.

## Testing

At minimum, test:

- Plugin class contract
- Missing and empty allowlists
- Entry-point and plugin-name mismatch
- Duplicate plugin, tool, and parser names
- Scope-policy enforcement
- Tool-level authorization
- Subprocess timeout and output truncation
- Secret redaction
- File-root restrictions
- Registration from an installed wheel in a clean virtual environment

Run the GhostMCP quality gates against the combined environment:

```bash
ruff check .
mypy .
bandit -q -r src
python -m unittest discover -s tests -v
python -m build
```

## Deployment review checklist

Before allowlisting a plugin:

1. Review its source and dependency lock.
2. Verify the package origin and hashes.
3. Confirm entry-point and plugin names.
4. Inventory registered tools and parsers.
5. Review subprocess, network, filesystem, and credential behavior.
6. Confirm scope and authorization tests.
7. Install in a staging environment.
8. Inspect `toolchain_status_tool` and startup logs.
9. Execute a passive test engagement.
10. Record the approved version and reviewer.

Do not use wildcard allowlists.

## Removing a plugin

1. Remove its name from `GHOSTMCP_PLUGIN_ALLOWLIST`.
2. Restart GhostMCP and confirm the tools are absent.
3. Uninstall the package from the environment.
4. Rebuild the dependency lock or container.
5. Remove or archive plugin-specific credentials and configuration.
6. Preserve audit events according to retention policy.
