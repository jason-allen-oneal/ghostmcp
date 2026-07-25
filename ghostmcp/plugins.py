"""Plugin system for GhostMCP - external tool plugins via entrypoints."""

import importlib.metadata
import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class Plugin(ABC):
    """Base class for GhostMCP plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version."""
        pass

    @abstractmethod
    def register_tools(self, mcp) -> list[str]:
        """Register MCP tools. Returns list of registered tool names."""
        pass

    @abstractmethod
    def register_parsers(self) -> dict[str, Callable]:
        """Register output parsers. Returns dict of parser_name -> parser_function."""
        pass

    def get_config_schema(self) -> dict[str, Any]:
        """Return JSON schema for plugin configuration."""
        return {}

    def validate_config(self, config: dict[str, Any]) -> bool:
        """Validate plugin configuration."""
        return True

    def declared_tools(self) -> list[str]:
        """Declare tool names before registration."""
        return []

    def security_metadata(self) -> dict[str, dict[str, Any]]:
        """Return risk, capability, target, and routing metadata per tool."""
        return {}


class PluginManager:
    """Manages GhostMCP plugins."""

    def __init__(self):
        self._plugins: dict[str, Plugin] = {}
        self._tool_to_plugin: dict[str, str] = {}

    def load_plugins(self, entry_point_group: str = "ghostmcp.plugins") -> list[str]:
        """Load plugins from entrypoints."""
        loaded = []
        for entry_point in importlib.metadata.entry_points(group=entry_point_group):
            try:
                plugin_class = entry_point.load()
                plugin = plugin_class()
                self.register_plugin(plugin)
                loaded.append(plugin.name)
                logger.info(f"Loaded plugin: {plugin.name} v{plugin.version}")
            except Exception as e:
                logger.error(f"Failed to load plugin {entry_point.name}: {e}")
        return loaded

    def register_plugin(self, plugin: Plugin) -> None:
        """Register a plugin instance."""
        if plugin.name in self._plugins:
            logger.warning(f"Plugin {plugin.name} already registered, replacing")
        self._plugins[plugin.name] = plugin

        # Register tools
        try:
            # This will be called later with mcp instance
            pass
        except Exception as e:
            logger.error(f"Failed to register tools for {plugin.name}: {e}")

    def register_plugin_tools(
        self,
        mcp,
        instrument_tool: Callable[[str, dict[str, Any], Callable], Callable]
        | None = None,
    ) -> dict[str, list[str]]:
        """Register all plugin tools with MCP server."""
        results: dict[str, list[str]] = {}
        enabled = os.getenv(
            "GHOSTMCP_ENABLE_EXPERIMENTAL_PLUGINS",
            "false",
        ).lower() in {"1", "true", "yes", "on"}
        if not enabled:
            logger.warning("Plugin tool registration is disabled by policy")
            return {name: [] for name in self._plugins}
        if instrument_tool is None:
            raise RuntimeError(
                "Plugin tools require a security instrumentation callback"
            )
        allowed = {
            item.strip()
            for item in os.getenv("GHOSTMCP_ALLOWED_PLUGINS", "").split(",")
            if item.strip()
        }
        for name, plugin in self._plugins.items():
            if name not in allowed:
                logger.error("Plugin is not in GHOSTMCP_ALLOWED_PLUGINS: %s", name)
                results[name] = []
                continue
            try:
                declared = plugin.declared_tools()
                metadata = plugin.security_metadata()
                if not declared or set(metadata) != set(declared):
                    raise ValueError(
                        "Plugin must declare every tool and its security metadata"
                    )
                for tool_name, descriptor in metadata.items():
                    required = {"risk", "capabilities", "target_fields", "route_support"}
                    if not required.issubset(descriptor):
                        raise ValueError(
                            f"Incomplete security metadata for plugin tool: {tool_name}"
                        )
                guarded_mcp = _GuardedMCPProxy(
                    mcp,
                    metadata,
                    instrument_tool,
                )
                tool_names = plugin.register_tools(guarded_mcp)
                if set(tool_names) != set(declared):
                    raise ValueError("Plugin registered undeclared tool names")
                results[name] = tool_names
                for tool_name in tool_names:
                    self._tool_to_plugin[tool_name] = name
            except Exception as e:
                logger.error(f"Failed to register tools for plugin {name}: {e}")
                results[name] = []
        return results

    def get_plugin(self, name: str) -> Plugin | None:
        """Get plugin by name."""
        return self._plugins.get(name)

    def list_plugins(self) -> list[dict[str, Any]]:
        """List all registered plugins."""
        return [
            {
                "name": p.name,
                "version": p.version,
                "tools": [t for t, pn in self._tool_to_plugin.items() if pn == p.name],
            }
            for p in self._plugins.values()
        ]

    def get_parsers(self) -> dict[str, Callable]:
        """Get all registered parsers from plugins."""
        parsers = {}
        for plugin in self._plugins.values():
            try:
                parsers.update(plugin.register_parsers())
            except Exception as e:
                logger.error(f"Failed to get parsers from {plugin.name}: {e}")
        return parsers


# Global plugin manager
_plugin_manager: PluginManager | None = None


def get_plugin_manager() -> PluginManager:
    """Get global plugin manager instance."""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager


def load_all_plugins(entry_point_group: str = "ghostmcp.plugins") -> list[str]:
    """Load all plugins from entrypoints."""
    return get_plugin_manager().load_plugins(entry_point_group)


def register_plugin_tools(
    mcp,
    instrument_tool: Callable[[str, dict[str, Any], Callable], Callable]
    | None = None,
) -> dict[str, list[str]]:
    """Register all plugin tools with MCP server."""
    return get_plugin_manager().register_plugin_tools(mcp, instrument_tool)


class _GuardedMCPProxy:
    def __init__(
        self,
        mcp: Any,
        metadata: dict[str, dict[str, Any]],
        instrument_tool: Callable[[str, dict[str, Any], Callable], Callable],
    ) -> None:
        self._mcp = mcp
        self._metadata = metadata
        self._instrument_tool = instrument_tool

    def tool(self):
        def decorator(fn: Callable) -> Callable:
            name = fn.__name__
            if name not in self._metadata:
                raise ValueError(f"Plugin attempted to register undeclared tool: {name}")
            guarded = self._instrument_tool(name, self._metadata[name], fn)
            return self._mcp.tool()(guarded)

        return decorator


# Example plugin template
class ExamplePlugin(Plugin):
    """Example plugin for reference."""

    @property
    def name(self) -> str:
        return "example"

    @property
    def version(self) -> str:
        return "1.0.0"

    def register_tools(self, mcp) -> list[str]:
        @mcp.tool()
        def example_tool(target: str) -> dict:
            """Example tool from plugin."""
            return {"plugin": "example", "target": target, "result": "ok"}

        return ["example_tool"]

    def declared_tools(self) -> list[str]:
        return ["example_tool"]

    def security_metadata(self) -> dict[str, dict[str, Any]]:
        return {
            "example_tool": {
                "risk": "passive",
                "capabilities": ["discovery"],
                "target_fields": [{"name": "target", "kind": "host"}],
                "route_support": "direct_only",
            }
        }

    def register_parsers(self) -> dict[str, Callable]:
        def parse_example(text: str) -> dict:
            return {"parsed": text}

        return {"parse_example": parse_example}
