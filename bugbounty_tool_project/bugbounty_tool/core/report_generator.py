import os
import json
from typing import Dict
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    """Generate consolidated reports from tool outputs."""

    def __init__(self, logger, output_dir: str):
        self.logger = logger
        self.output_dir = output_dir
        self.env = Environment(loader=FileSystemLoader("templates"))

    def parse_tool_outputs(self) -> Dict[str, str]:
        """Parse all tool outputs into a consolidated dictionary."""
        results = {}
        for tool_output in os.listdir(self.output_dir):
            file_path = os.path.join(self.output_dir, tool_output)
            if os.path.isfile(file_path):
                try:
                    # Open files with errors="replace" to handle invalid UTF-8 characters gracefully.
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        results[tool_output] = f.read()
                except Exception as e:
                    self.logger.error(f"Error reading {file_path}: {e}")
                    results[tool_output] = f"Error reading file: {e}"
        return results

    def generate_html_report(self, results: Dict[str, str]) -> None:
        """Generate an HTML report using Jinja2."""
        template = self.env.get_template("report.html")
        report = template.render(results=results)
        output_file = os.path.join(self.output_dir, "report.html")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
        self.logger.info(f"HTML report generated at {output_file}")

    def generate_markdown_report(self, results: Dict[str, str]) -> None:
        """Generate a Markdown report."""
        template = self.env.get_template("report.md")
        report = template.render(results=results)
        output_file = os.path.join(self.output_dir, "report.md")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
        self.logger.info(f"Markdown report generated at {output_file}")

    def generate_json_report(self, results: Dict[str, str]) -> None:
        """Generate a JSON report."""
        output_file = os.path.join(self.output_dir, "report.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        self.logger.info(f"JSON report generated at {output_file}")

