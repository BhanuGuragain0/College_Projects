import os
import pytest
from bugbounty_tool.core.tool_runner import ToolRunner

@pytest.mark.asyncio
async def test_run_tool_success(tmp_path):
    """Test successful tool execution using a simple command."""
    # Create a temporary results directory.
    output_dir = tmp_path / "results"
    output_dir.mkdir()
    tool_runner = ToolRunner(logger=None, output_dir=str(output_dir), wordlist="wordlists/common.txt")
    # 'echo' should be available on most systems.
    success = await tool_runner.run_tool("echo", "Hello, World!", [], "echo_output.txt", timeout=10)
    assert success is True
    output_file = output_dir / "echo_output.txt"
    assert output_file.exists()
    content = output_file.read_text()
    assert "Hello, World!" in content

@pytest.mark.asyncio
async def test_run_tool_failure(tmp_path):
    """Test failed tool execution."""
    output_dir = tmp_path / "results"
    output_dir.mkdir()
    tool_runner = ToolRunner(logger=None, output_dir=str(output_dir), wordlist="wordlists/common.txt")
    success = await tool_runner.run_tool("nonexistent_tool", "target", [], "invalid_output.txt", timeout=10)
    assert success is False