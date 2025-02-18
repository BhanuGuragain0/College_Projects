# server/plugins_loader.py
import os
import importlib.util
from .config import Config
import logging

def load_plugins():
    plugins = {}
    plugins_folder = Config.PLUGINS_FOLDER
    if not os.path.isdir(plugins_folder):
        logging.info("No plugins folder found.")
        return plugins

    for filename in os.listdir(plugins_folder):
        if filename.endswith(".py"):
            plugin_path = os.path.join(plugins_folder, filename)
            module_name = filename[:-3]
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                if hasattr(module, "run"):
                    plugins[module_name] = module
                    logging.info(f"Loaded plugin: {module_name}")
            except Exception as e:
                logging.error(f"Failed to load plugin {module_name}: {e}")
    return plugins

# At startup, call load_plugins() to make plugins available.
PLUGINS = load_plugins()
