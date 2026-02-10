#!/usr/bin/env python3
import os
import logging
import asyncio
import click
import subprocess
from bugbounty_tool.core.tool_runner import ToolRunner
from bugbounty_tool.core.target_processor import TargetProcessor
from bugbounty_tool.core.report_generator import ReportGenerator
from bugbounty_tool.core.ai_analyzer import AIAnalyzer
from bugbounty_tool.core.utils import setup_logging, validate_target

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Adjust level as needed
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logging.info("Starting the Bug Bounty Automation Tool CLI...")

@click.group()
def cli() -> None:
    """Bug Bounty Automation Tool CLI"""
    pass

@cli.command()
@click.option("-t", "--target", required=True, help="Target (URL, IP, Domain, or ASN)")
@click.option("-o", "--output", default="results", help="Output directory")
@click.option("--threads", type=int, default=5, help="Maximum concurrent threads")
@click.option("--exclude", multiple=True, help="Targets to exclude")
@click.option("--asn", is_flag=True, help="Treat target as ASN number")
@click.option("-v", "--verbose", count=True, help="Increase verbosity level")
@click.option("--full", is_flag=True, help="Run all available scans")
@click.option("--wordlist", default="common.txt", help="Custom wordlist name for brute-forcing (from wordlists/)")
def scan(target: str, output: str, threads: int, exclude: tuple, asn: bool, verbose: int, full: bool, wordlist: str) -> None:
    """
    Run a security scan on the target.
    
    This command executes various scanning tools concurrently, performs AI analysis on the outputs,
    and generates reports (HTML, Markdown, and JSON) in the output directory.
    """
    if not validate_target(target):
        click.echo("Invalid target. Please provide a valid URL, IP, domain, or ASN.")
        return

    logger = setup_logging(verbose)
    click.echo("Initializing scanning modules...")
    tool_runner = ToolRunner(logger, output, f"wordlists/{wordlist}")
    processor = TargetProcessor(logger, output)
    reporter = ReportGenerator(logger, output)
    ai_analyzer = AIAnalyzer(logger, tool_runner.config)
    loop = asyncio.get_event_loop()

    if asn:
        ip_ranges = processor.process_asn(target)
        logger.info(f"Resolved ASN IP ranges: {ip_ranges}")
    else:
        subdomains = processor.process_domain(target, list(exclude))
        logger.info(f"Found subdomains: {subdomains}")

    tasks = []
    # For nmap, no wordlist is used.
    if full or click.confirm("Run Nmap scan?"):
        tasks.append(tool_runner.run_tool("nmap", target, [], "nmap_scan.txt"))
    if full or click.confirm("Enumerate subdomains?"):
        for tool in ["subfinder", "amass", "theharvester"]:
            tasks.append(tool_runner.run_tool(tool, target, [], f"{tool}_subdomains.txt"))
    if full or click.confirm("Run directory brute-forcing?"):
        tasks.append(tool_runner.run_tool("dirsearch", target, [], "dirsearch.txt"))
    if full or click.confirm("Run SQL injection testing?"):
        tasks.append(tool_runner.run_tool("sqlmap", target, [], "sqlmap.txt"))
    if full or click.confirm("Run web server vulnerability scanning?"):
        tasks.append(tool_runner.run_tool("nikto", target, [], "nikto.txt"))
    if full or click.confirm("Run directory and DNS brute-forcing?"):
        tasks.append(tool_runner.run_tool("gobuster", target, [], "gobuster.txt"))
    if full or click.confirm("Run web application fuzzing?"):
        tasks.append(tool_runner.run_tool("wfuzz", target, [], "wfuzz.txt"))
    if full or click.confirm("Run WordPress vulnerability scanning?"):
        tasks.append(tool_runner.run_tool("wpscan", target, [], "wpscan.txt"))

    async def run_tasks() -> None:
        click.echo("Starting scanning tasks...")
        for task in asyncio.as_completed(tasks):
            try:
                await task
            except Exception as e:
                logger.error(f"Task failed: {e}")
        click.echo("Scanning tasks completed.")

        # Run AI analysis on each tool's output.
        for tool_output in os.listdir(output):
            file_path = os.path.join(output, tool_output)
            if os.path.isfile(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    output_content = f.read()
                analysis = await ai_analyzer.analyze_output(tool_output, output_content)
                logger.info(f"AI Analysis for {tool_output}:\n{analysis}")

        results = reporter.parse_tool_outputs()
        reporter.generate_html_report(results)
        reporter.generate_markdown_report(results)
        reporter.generate_json_report(results)
        logger.info(f"Scan completed. Results are in the '{output}' directory.")

    loop.run_until_complete(run_tasks())

@cli.command()
@click.argument("command", nargs=-1)
def manual(command):
    """
    Run a custom manual command from the terminal.
    
    Example: bugbounty manual "nmap -A 192.168.1.1"
    """
    cmd = " ".join(command)
    click.echo(f"Running manual command: {cmd}")
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        click.echo(output)
    except subprocess.CalledProcessError as e:
        click.echo(f"Command failed with error:\n{e.output}")

if __name__ == "__main__":
    cli()
