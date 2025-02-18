import logging
import re
from logging.handlers import RotatingFileHandler
import asyncio
from typing import List

def setup_logging(verbose: int = 0) -> logging.Logger:
    """Configure logging system with verbosity levels."""
    log_level = logging.WARNING
    if verbose == 1:
        log_level = logging.INFO
    elif verbose >= 2:
        log_level = logging.DEBUG

    logger = logging.getLogger("bugbounty_tool")
    if not logger.handlers:
        logger.setLevel(log_level)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler = RotatingFileHandler("debug.log", maxBytes=10 * 1024 * 1024, backupCount=5)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    return logger

def validate_target(target: str) -> bool:
    """Validate the target (URL, IP, domain, or ASN)."""
    url_pattern = re.compile(r"https?://(?:www\.)?\S+")
    ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    domain_pattern = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
    asn_pattern = re.compile(r"^AS\d+$")
    return (
        url_pattern.match(target)
        or ip_pattern.match(target)
        or domain_pattern.match(target)
        or asn_pattern.match(target)
    )

async def run_command(cmd: List[str], timeout: int = 300) -> str:
    """Run a command asynchronously and return its output."""
    process = await asyncio.create_subprocess_exec(
         *cmd,
         stdout=asyncio.subprocess.PIPE,
         stderr=asyncio.subprocess.PIPE
    )
    try:
         await asyncio.wait_for(process.wait(), timeout=timeout)
    except asyncio.TimeoutError:
         process.terminate()
         await process.wait()
         raise Exception("Command timed out")
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
         raise Exception(f"Command failed: {stderr.decode().strip()}")
    return stdout.decode()