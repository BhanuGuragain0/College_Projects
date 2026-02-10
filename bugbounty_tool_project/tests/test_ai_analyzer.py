import pytest
from bugbounty_tool.core.ai_analyzer import AIAnalyzer


@pytest.mark.asyncio
async def test_analyze_output_success():
    """Test successful AI analysis."""
    ai_analyzer = AIAnalyzer(logger=None, config={"openai": {"api_key": "test_key"}})
    analysis = await ai_analyzer.analyze_output("nmap", "Sample output")
    assert analysis != "AI analysis failed. Please check logs."


@pytest.mark.asyncio
async def test_analyze_output_failure():
    """Test failed AI analysis."""
    ai_analyzer = AIAnalyzer(logger=None, config={"openai": {"api_key": "invalid_key"}})
    analysis = await ai_analyzer.analyze_output("nmap", "Sample output")
    assert analysis == "AI analysis failed. Please check logs."