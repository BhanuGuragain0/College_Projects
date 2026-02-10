# bugbounty_tool/core/plugins/wfuzz_plugin.py

import asyncio
from typing import List
from bugbounty_tool.core.plugins.base_plugin import BasePlugin

class WfuzzPlugin(BasePlugin):
    """
    Plugin for running Wfuzz for web application fuzzing.
    Assumes wfuzz is installed on your Kali Linux system.
    """

    async def run(self, target: str, args: List[str]) -> str:
        """
        Execute wfuzz with the given target and arguments.

        :param target: The target URL.
        :param args: Additional arguments.
        :return: Raw output from wfuzz.
        """
        # Default command: wfuzz -c -z file,wordlists/common.txt <target>
        cmd = ["wfuzz", "-c", "-z", "file,wordlists/common.txt", target] + args
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
            return f"Exception occurred while running wfuzz: {str(e)}"

    def parse_output(self, output: str) -> str:
        """
        Parse wfuzz output.

        :param output: Raw output.
        :return: Parsed results.
        """
        # Customize parsing logic if needed.
        return output