import os
import logging
from typing import List

class WordlistManager:
    """
    Manage custom wordlists for brute-forcing.

    This class provides methods to retrieve the full path of a wordlist,
    list all available wordlists, and read the content of a given wordlist.
    """

    def __init__(self, wordlist_dir: str = "wordlists") -> None:
        """
        Initialize the WordlistManager.

        :param wordlist_dir: Directory where wordlist files are stored.
        """
        self.wordlist_dir = wordlist_dir
        self.logger = logging.getLogger(__name__)
        # Ensure the wordlist directory exists; if not, attempt to create it.
        if not os.path.exists(self.wordlist_dir):
            try:
                os.makedirs(self.wordlist_dir)
                self.logger.info(f"Created wordlist directory: {self.wordlist_dir}")
            except Exception as e:
                self.logger.error(f"Failed to create wordlist directory '{self.wordlist_dir}': {e}")
                raise

    def get_wordlist(self, name: str) -> str:
        """
        Get the full path to a wordlist file by its name.

        :param name: The file name of the wordlist.
        :return: Full path to the wordlist file.
        :raises FileNotFoundError: If the file does not exist.
        """
        path = os.path.join(self.wordlist_dir, name)
        if not os.path.isfile(path):
            self.logger.error(f"Wordlist file '{name}' not found in '{self.wordlist_dir}'.")
            raise FileNotFoundError(f"Wordlist file '{name}' not found in '{self.wordlist_dir}'.")
        self.logger.debug(f"Found wordlist file: {path}")
        return path

    def list_wordlists(self) -> List[str]:
        """
        List all available wordlist files in the wordlist directory.

        :return: A list of wordlist file names.
        """
        try:
            files = os.listdir(self.wordlist_dir)
            # Filter to include only files (skip directories)
            wordlists = [f for f in files if os.path.isfile(os.path.join(self.wordlist_dir, f))]
            self.logger.debug(f"Available wordlists: {wordlists}")
            return wordlists
        except Exception as e:
            self.logger.error(f"Failed to list wordlists in '{self.wordlist_dir}': {e}")
            return []

    def read_wordlist(self, name: str) -> List[str]:
        """
        Read the contents of a wordlist file and return them as a list of words.

        :param name: The file name of the wordlist.
        :return: A list of non-empty, stripped lines from the file.
        :raises FileNotFoundError: If the wordlist file is not found.
        :raises Exception: For other I/O related errors.
        """
        path = self.get_wordlist(name)
        try:
            with open(path, 'r', encoding='utf-8') as file:
                # Return a list of non-empty, stripped lines.
                words = [line.strip() for line in file if line.strip()]
            self.logger.info(f"Read {len(words)} entries from '{name}'.")
            return words
        except Exception as e:
            self.logger.error(f"Error reading wordlist file '{name}': {e}")
            raise