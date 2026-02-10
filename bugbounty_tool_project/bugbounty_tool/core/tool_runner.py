import os
import shutil
import asyncio
from typing import List, Dict
import yaml
from bugbounty_tool.core.rate_limiter import RateLimiter
from bugbounty_tool.core.plugin_manager import load_plugins
from bugbounty_tool.core.utils import run_command

class ToolRunner:
    """Class to handle tool execution with advanced features and plugin support."""

    def __init__(self, logger, output_dir: str, wordlist: str, config_path: str = "config/config.yaml"):
        self.logger = logger
        self.output_dir = output_dir
        self.wordlist = wordlist
        self.config = self._load_config(config_path)
        self.rate_limiter = RateLimiter(max_calls=5, period=1)
        self.plugins = load_plugins()  # Load available plugins dynamically
        os.makedirs(output_dir, exist_ok=True)

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from a YAML file."""
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
            return config
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            return {}

    def _build_args(self, tool_name: str, target: str, extra_args: List[str]) -> List[str]:
        """Merge config-based arguments with extra_args and substitute {target}."""
        config_args = self.config.get("tools", {}).get(tool_name, {}).get("args", [])
        substituted = [arg.format(target=target) for arg in config_args]
        return substituted + extra_args

    async def run_tool(self, tool_name: str, target: str, extra_args: List[str], output_file: str, timeout: int = 300) -> bool:
        """Execute a tool asynchronously using a plugin if available or default subprocess."""
        await self.rate_limiter.wait()
        output_path = os.path.join(self.output_dir, output_file)

        # Check if a plugin exists for this tool
        if tool_name in self.plugins:
            plugin = self.plugins[tool_name]
            try:
                self.logger.debug(f"Running plugin for {tool_name}")
                output = await plugin.run(target, extra_args)
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(output)
                return True
            except Exception as e:
                self.logger.error(f"Plugin {tool_name} failed: {e}")
                return False

        # Fallback: default command-line execution
        if not shutil.which(tool_name):
            self.logger.warning(f"{tool_name} not installed. Skipping...")
            return False

        full_args = self._build_args(tool_name, target, extra_args)
        self.logger.debug(f"Executing: {tool_name} {' '.join(full_args)}")

        try:
            process = await asyncio.create_subprocess_exec(
                tool_name, *full_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                await asyncio.wait_for(process.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                process.terminate()
                await process.wait()
                self.logger.error(f"{tool_name} timed out after {timeout} seconds")
                return False

            stdout, stderr = await process.communicate()
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(stdout.decode(errors="replace"))

            if process.returncode != 0:
                self.logger.error(f"{tool_name} failed (code {process.returncode}): {stderr.decode(errors='replace').strip()}")
                return False

            if stderr:
                self.logger.warning(f"{tool_name} stderr: {stderr.decode(errors='replace').strip()}")

            return True
        except Exception as e:
            self.logger.error(f"Unexpected error with {tool_name}: {str(e)}")
            return False
