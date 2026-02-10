#!/usr/bin/env python3
"""
Dirsearch Plugin for Bug Bounty Automation Tool.

This plugin executes the dirsearch tool for directory brute-forcing.
"""

import asyncio
from typing import List
from bugbounty_tool.core.plugins.base_plugin import BasePlugin
from bugbounty_tool.core.wordlist_manager import WordlistManager  # Corrected absolute import

class DirsearchPlugin(BasePlugin):
    """Dirsearch plugin for directory brute-forcing."""

    async def run(self, target: str, args: List[str]) -> str:
        """
        Run dirsearch with the given target and arguments.
        
        :param target: The target URL.
        :param args: Additional command-line arguments.
        :return: Raw output from dirsearch.
        """
        # Build the command: using -u for URL and -e for all extensions.
        cmd = ["dirsearch", "-u", target, "-e", "*"] + args
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
            return f"Exception occurred while running dirsearch: {str(e)}"

    def parse_output(self, output: str) -> str:
        """
        Parse and return the dirsearch output.
        
        :param output: The raw output from dirsearch.
        :return: The parsed output.
        """
        # Implement your custom parsing logic here; for now, return the raw output.
        return output
