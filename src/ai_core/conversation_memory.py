"""Conversation Memory Manager for Long Conversations"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import re


@dataclass
class TokenEstimate:
    """Estimated token counts for a message."""
    input_tokens: int
    role: str
    content_preview: str


@dataclass
class ConversationSummary:
    """Summary of older conversation messages."""
    summary_text: str
    messages_summarized: int
    topics_covered: List[str]
    key_insights: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)


class ConversationMemory:
    """Manages conversation context within token limits."""

    # Approximate token limits
    MAX_CONTEXT_TOKENS = 8000
    SUMMARY_THRESHOLD = 6000
    CHARS_PER_TOKEN = 4  # Rough estimate

    def __init__(self, max_tokens: int = None, summary_threshold: int = None):
        self.max_tokens = max_tokens or self.MAX_CONTEXT_TOKENS
        self.summary_threshold = summary_threshold or self.SUMMARY_THRESHOLD

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for a text string."""
        if not text:
            return 0
        return len(text) // self.CHARS_PER_TOKEN + 1

    def estimate_message_tokens(self, messages: List[Dict[str, Any]]) -> int:
        """Estimate total tokens for a list of messages."""
        total = 0
        for msg in messages:
            content = msg.get('content', '')
            # Add overhead for message structure
            total += self.estimate_tokens(content) + 4
        return total

    def should_summarize(self, messages: List[Dict[str, Any]], system_prompt: str = "") -> bool:
        """Check if messages should be summarized."""
        system_tokens = self.estimate_tokens(system_prompt)
        message_tokens = self.estimate_message_tokens(messages)
        total = system_tokens + message_tokens
        return total > self.summary_threshold

    def prepare_context(
        self,
        messages: List[Dict[str, Any]],
        system_prompt: str,
        existing_summary: str = None
    ) -> Tuple[str, List[Dict[str, Any]], bool]:
        """
        Prepare conversation context for API call.

        Returns:
            Tuple of (enhanced_system_prompt, trimmed_messages, needs_summary_update)
        """
        if not self.should_summarize(messages, system_prompt):
            # No summarization needed, return as-is
            if existing_summary:
                enhanced_prompt = f"{system_prompt}\n\n## Previous Conversation Summary\n{existing_summary}"
                return enhanced_prompt, messages, False
            return system_prompt, messages, False

        # Need to trim messages - keep recent ones
        recent_messages = self._get_recent_messages(messages, system_prompt)

        # Add summary context
        if existing_summary:
            enhanced_prompt = f"{system_prompt}\n\n## Previous Conversation Summary\n{existing_summary}"
        else:
            enhanced_prompt = system_prompt

        return enhanced_prompt, recent_messages, True

    def _get_recent_messages(
        self,
        messages: List[Dict[str, Any]],
        system_prompt: str
    ) -> List[Dict[str, Any]]:
        """Get the most recent messages that fit within token limit."""
        system_tokens = self.estimate_tokens(system_prompt)
        available_tokens = self.max_tokens - system_tokens - 500  # Buffer for summary

        recent = []
        running_total = 0

        # Work backwards from most recent
        for msg in reversed(messages):
            msg_tokens = self.estimate_tokens(msg.get('content', '')) + 4
            if running_total + msg_tokens > available_tokens:
                break
            recent.insert(0, msg)
            running_total += msg_tokens

        return recent

    def generate_summary_prompt(self, messages: List[Dict[str, Any]]) -> str:
        """Generate a prompt for summarizing conversation."""
        conversation_text = []
        for msg in messages:
            role = msg.get('role', 'user').upper()
            content = msg.get('content', '')
            conversation_text.append(f"{role}: {content}")

        return f"""Summarize this conversation in 2-3 paragraphs. Focus on:
1. Key topics discussed
2. Important insights or decisions
3. Any action items or recommendations

Conversation:
{chr(10).join(conversation_text)}

Summary:"""

    def create_summary(
        self,
        messages: List[Dict[str, Any]],
        topics: List[str] = None,
        insights: List[str] = None
    ) -> ConversationSummary:
        """Create a summary object from messages."""
        # Extract key points from messages
        all_content = ' '.join(m.get('content', '') for m in messages)

        # Simple key phrase extraction
        if not insights:
            insights = self._extract_key_insights(all_content)

        return ConversationSummary(
            summary_text=self._create_simple_summary(messages),
            messages_summarized=len(messages),
            topics_covered=topics or [],
            key_insights=insights
        )

    def _create_simple_summary(self, messages: List[Dict[str, Any]]) -> str:
        """Create a simple text summary of messages."""
        if not messages:
            return "No previous conversation."

        # Get first and last few messages as context
        summary_parts = []

        if len(messages) <= 4:
            # Short conversation, summarize all
            for msg in messages:
                role = "User" if msg.get('role') == 'user' else "Assistant"
                content = msg.get('content', '')[:200]
                summary_parts.append(f"{role}: {content}...")
        else:
            # Longer conversation, summarize first and last
            summary_parts.append(f"Conversation started with: {messages[0].get('content', '')[:150]}...")
            summary_parts.append(f"Total of {len(messages)} exchanges.")
            summary_parts.append(f"Most recent discussion: {messages[-1].get('content', '')[:150]}...")

        return "\n".join(summary_parts)

    def _extract_key_insights(self, text: str, max_insights: int = 5) -> List[str]:
        """Extract key insights from text."""
        insights = []

        # Look for recommendation patterns
        patterns = [
            r"recommend[s]?\s+([^.]+)\.",
            r"should\s+([^.]+)\.",
            r"important[ly]?\s*:?\s*([^.]+)\.",
            r"key\s+(?:point|insight|finding)[s]?:?\s*([^.]+)\.",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text.lower())
            for match in matches[:2]:  # Limit per pattern
                cleaned = match.strip()[:100]
                if len(cleaned) > 10 and cleaned not in insights:
                    insights.append(cleaned)

        return insights[:max_insights]


class TopicTracker:
    """Tracks topics discussed in conversation."""

    def __init__(self, topic_keywords: Dict[str, List[str]] = None):
        self.topic_keywords = topic_keywords or self._default_security_keywords()
        self.discussed_topics: List[str] = []

    def _default_security_keywords(self) -> Dict[str, List[str]]:
        """Default security topic keywords."""
        return {
            'vulnerabilities': ['vulnerability', 'cve', 'patch', 'exploit', 'weakness'],
            'incidents': ['incident', 'breach', 'attack', 'compromise', 'response'],
            'compliance': ['compliance', 'audit', 'framework', 'regulation', 'control'],
            'risk': ['risk', 'threat', 'exposure', 'impact', 'likelihood'],
            'access': ['access', 'identity', 'authentication', 'mfa', 'privileged'],
            'threats': ['threat', 'ransomware', 'malware', 'phishing', 'apt'],
            'posture': ['posture', 'security score', 'maturity', 'assessment'],
            'network': ['network', 'firewall', 'segmentation', 'traffic'],
            'endpoint': ['endpoint', 'edr', 'antivirus', 'device'],
        }

    def track_message(self, message: str, role: str = 'user') -> List[str]:
        """Track topics mentioned in a message."""
        new_topics = []
        message_lower = message.lower()

        for topic, keywords in self.topic_keywords.items():
            if any(kw in message_lower for kw in keywords):
                if topic not in self.discussed_topics:
                    self.discussed_topics.append(topic)
                    new_topics.append(topic)

        return new_topics

    def get_discussed_topics(self) -> List[str]:
        """Get all discussed topics."""
        return self.discussed_topics.copy()

    def get_unaddressed_topics(self, context_topics: List[str]) -> List[str]:
        """Get topics from context that haven't been discussed."""
        return [t for t in context_topics if t not in self.discussed_topics]

    def reset(self):
        """Reset tracked topics."""
        self.discussed_topics = []


# Factory functions
def create_conversation_memory(max_tokens: int = None) -> ConversationMemory:
    return ConversationMemory(max_tokens=max_tokens)


def create_topic_tracker() -> TopicTracker:
    """Create topic tracker with security-specific keywords."""
    return TopicTracker()
