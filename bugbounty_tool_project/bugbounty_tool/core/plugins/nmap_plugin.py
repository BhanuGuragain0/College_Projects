# bugbounty_tool/core/plugins/nmap_plugin.py

import asyncio
from typing import List
from bugbounty_tool.core.plugins.base_plugin import BasePlugin

class NmapPlugin(BasePlugin):
    """
    Plugin for running Nmap for network scanning.
    Designed for Kali Linux with nmap installed.
    """

    async def run(self, target: str, args: List[str]) -> str:
        """
        Execute nmap with the given target and arguments.

        :param target: The target IP/Domain.
        :param args: Additional arguments.
        :return: Raw nmap output.
        """
        # Default command: nmap -sV -A -T4 <target>
        cmd = ["nmap", "-sV", "-A", "-T4", "-Pn", target] + args
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
            return f"Exception occurred while running nmap: {str(e)}"

    def parse_output(self, output: str) -> str:
        """
        Parse the nmap output. (Extend this function with custom parsing as needed.)

        :param output: Raw output.
        :return: Parsed nmap results.
        """
        return output