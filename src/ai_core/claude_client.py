"""Claude API Client for Security Intelligence"""
import os
from typing import Generator, List, Dict, Any, Optional
import anthropic


class ClaudeClient:
    """Wrapper for Anthropic Claude API."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        self.model = model or os.getenv('CLAUDE_MODEL', 'claude-sonnet-4-20250514')
        self.max_tokens = int(os.getenv('CLAUDE_MAX_TOKENS', '4096'))

        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is required")

        self.client = anthropic.Anthropic(api_key=self.api_key)

    def chat(self, messages: List[Dict[str, str]], system: str = None,
             max_tokens: int = None) -> str:
        """Send a chat message and get a response."""
        try:
            kwargs = {
                "model": self.model,
                "max_tokens": max_tokens or self.max_tokens,
                "messages": messages
            }
            if system:
                kwargs["system"] = system

            response = self.client.messages.create(**kwargs)
            return response.content[0].text

        except anthropic.APIError as e:
            raise Exception(f"Claude API error: {str(e)}")

    def chat_stream(self, messages: List[Dict[str, str]], system: str = None,
                    max_tokens: int = None) -> Generator[str, None, None]:
        """Stream a chat response."""
        try:
            kwargs = {
                "model": self.model,
                "max_tokens": max_tokens or self.max_tokens,
                "messages": messages
            }
            if system:
                kwargs["system"] = system

            with self.client.messages.stream(**kwargs) as stream:
                for text in stream.text_stream:
                    yield text

        except anthropic.APIError as e:
            yield f"Error: {str(e)}"
