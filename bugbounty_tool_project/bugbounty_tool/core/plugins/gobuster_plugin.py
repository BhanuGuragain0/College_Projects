# bugbounty_tool/core/plugins/gobuster_plugin.py

import asyncio
from typing import List
from bugbounty_tool.core.plugins.base_plugin import BasePlugin

class GobusterPlugin(BasePlugin):
    """
    Plugin for running Gobuster for directory and DNS brute-forcing.
    Ensure that gobuster is installed on your Kali Linux system.
    """

    async def run(self, target: str, args: List[str]) -> str:
        """
        Run gobuster with the given target and arguments.

        :param target: The target (URL or domain).
        :param args: Additional command-line arguments.
        :return: Raw output from gobuster.
        """
        # Default command uses a common wordlist; adjust as needed.
        cmd = ["gobuster", "dir", "-u", target, "-w", "wordlists/common.txt"] + args
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
            return f"Exception occurred while running gobuster: {str(e)}"

    def parse_output(self, output: str) -> str:
        """
        Parse and return gobuster output.

        :param output: Raw output.
        :return: Processed output.
        """
        # Customize parsing logic here if needed.
        return output