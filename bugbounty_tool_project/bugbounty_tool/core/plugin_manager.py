import os
import importlib
from bugbounty_tool.core.plugins.base_plugin import BasePlugin
from typing import Dict

def load_plugins() -> Dict[str, BasePlugin]:
    """Dynamically load plugins from the plugins directory."""
    plugins = {}
    plugins_dir = os.path.join(os.path.dirname(__file__), "plugins")
    for filename in os.listdir(plugins_dir):
        if filename.endswith("_plugin.py") and filename != "base_plugin.py":
            module_name = f"bugbounty_tool.core.plugins.{filename[:-3]}"
            module = importlib.import_module(module_name)
            for attr in dir(module):
                cls = getattr(module, attr)
                if isinstance(cls, type) and issubclass(cls, BasePlugin) and cls is not BasePlugin:
                    # The tool name is the filename without "_plugin.py"
                    tool_name = filename.replace("_plugin.py", "")
                    plugins[tool_name] = cls()  # instantiate the plugin
    return plugins