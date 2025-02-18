# bugbounty_tool/core/plugins/wpscan_plugin.py

import asyncio
from typing import List
from bugbounty_tool.core.plugins.base_plugin import BasePlugin

class WpscanPlugin(BasePlugin):
    """
    Plugin for running WPScan for WordPress vulnerability scanning.
    Designed for Kali Linux where wpscan is installed.
    """

    async def run(self, target: str, args: List[str]) -> str:
        """
        Execute wpscan with the given target and arguments.

        :param target: The target URL.
        :param args: Additional arguments.
        :return: Raw output from wpscan.
        """
        # Default command: wpscan --url <target> --enumerate vp
        cmd = ["wpscan", "--url", target, "--enumerate", "vp"] + args
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                return f"Error: {stderr.decode(errors='replace')}"
            return stdout.decode(errors='replace')
        except Exception as e:
            return f"Exception occurred while running wpscan: {str(e)}"

    def parse_output(self, output: str) -> str:
        """
        Parse the WPScan output.

        :param output: Raw output.
        :return: Parsed WPScan results.
        """
        # Implement custom parsing if needed.
        return output