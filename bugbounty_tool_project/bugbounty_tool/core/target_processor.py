import os
import logging
import subprocess
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

def resolve_asn(asn: str, logger: logging.Logger) -> List[str]:
    """Dummy function to resolve ASN to IP ranges."""
    logger.info(f"Resolving ASN: {asn}. Returning dummy IP range.")
    return ["192.168.1.0/24"]

def apply_exclusions(subdomains: set, exclusions: List[str], logger: logging.Logger) -> List[str]:
    """Apply exclusions to subdomains."""
    return [sub for sub in subdomains if sub not in exclusions]

class TargetProcessor:
    """Handle target processing and data collection."""

    def __init__(self, logger: logging.Logger, output_dir: str):
        self.logger = logger
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def process_asn(self, asn: str) -> List[str]:
        """Process ASN target and return IP ranges."""
        self.logger.info(f"Processing ASN: {asn}")
        return resolve_asn(asn, self.logger)

    def process_domain(self, domain: str, exclusions: List[str]) -> List[str]:
        """Process domain target and return subdomains."""
        self.logger.info(f"Processing domain: {domain}")
        subdomains = self.find_subdomains(domain)
        return apply_exclusions(subdomains, exclusions, self.logger)

    def find_subdomains(self, domain: str) -> List[str]:
        """Find subdomains using multiple external tools with progress tracking."""
        subdomains = set()
        tools = ["subfinder", "amass", "theharvester"]

        with ThreadPoolExecutor(max_workers=len(tools)) as executor:
            futures = {executor.submit(self._run_subdomain_tool, tool, domain): tool for tool in tools}
            for future in tqdm(as_completed(futures), total=len(futures), desc="Enumerating subdomains"):
                try:
                    subdomains.update(future.result())
                except Exception as e:
                    self.logger.error(f"Subdomain tool {futures[future]} failed: {e}")
        return list(subdomains)

    def _run_subdomain_tool(self, tool: str, domain: str) -> List[str]:
        """Run a single subdomain enumeration tool."""
        try:
            result = subprocess.run(
                [tool, "-d", domain],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            return result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            self.logger.error(f"{tool} failed: {e.stderr.strip()}")
            return []