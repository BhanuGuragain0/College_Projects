# bugbounty_tool/core/plugins/base_plugin.py

from abc import ABC, abstractmethod
from typing import List

class BasePlugin(ABC):
    """
    Base class for all plugins.
    Each plugin must implement the asynchronous `run` method and
    the `parse_output` method to process raw tool output.
    """

    @abstractmethod
    async def run(self, target: str, args: List[str]) -> str:
        """
        Execute the tool asynchronously.

        :param target: The target to scan (URL, IP, etc.)
        :param args: Additional command-line arguments.
        :return: The raw output from the tool as a string.
        """
        pass

    @abstractmethod
    def parse_output(self, output: str) -> str:
        """
        Parse the raw output from the tool and return the processed results.

        :param output: The raw output from the tool.
        :return: A processed/parsed result string.
        """
        pass