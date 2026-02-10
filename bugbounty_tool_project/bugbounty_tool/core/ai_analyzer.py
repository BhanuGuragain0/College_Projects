import openai
from typing import Dict

class AIAnalyzer:
    """Analyze tool outputs using AI and provide insights."""

    def __init__(self, logger, config: Dict):
        self.logger = logger
        self.config = config.get("openai", {})
        openai.api_key = self.config.get("api_key")
        self.model = self.config.get("model", "gpt-4")
        self.temperature = self.config.get("temperature", 0.7)

    async def analyze_output(self, tool_name: str, output: str) -> str:
        """Analyze tool output using AI and return insights."""
        try:
            prompt = f"Analyze the following {tool_name} output and provide actionable insights:\n\n{output}"
            response = await openai.ChatCompletion.acreate(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature
            )
            return response.choices[0].message["content"].strip()
        except Exception as e:
            if self.logger:
                self.logger.error(f"AI analysis failed: {e}")
            return "AI analysis failed. Please check logs."
