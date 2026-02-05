"""Context-Aware Suggestion Engine for Security Intelligence"""
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from enum import Enum


class SuggestionCategory(Enum):
    URGENT = "urgent"  # Immediate attention needed
    OPPORTUNITY = "opportunity"  # Improvement opportunity
    FOLLOW_UP = "follow_up"  # Continue previous discussion
    GENERAL = "general"  # Standard prompts


@dataclass
class SuggestedPrompt:
    prompt_text: str
    relevance_score: float  # 0-100
    category: SuggestionCategory
    rationale: str  # Why this is suggested (for UI tooltip)
    topic_tags: List[str]  # For tracking discussed topics

    def to_dict(self) -> Dict[str, Any]:
        return {
            'prompt': self.prompt_text,
            'relevance': round(self.relevance_score, 1),
            'category': self.category.value,
            'rationale': self.rationale,
            'tags': self.topic_tags
        }


class SecuritySuggestionEngine:
    """Generates context-aware prompt suggestions for Security Intelligence."""

    # Base prompts by mode (fallback when no context signals)
    BASE_PROMPTS = {
        'general': [
            ("What's our overall security posture?", ["posture", "overview"]),
            ("Where are we most vulnerable right now?", ["vulnerabilities", "risk"]),
            ("What should our security priorities be?", ["priorities", "strategy"]),
        ],
        'vulnerability_management': [
            ("Which critical vulnerabilities need immediate attention?", ["vulnerabilities", "critical"]),
            ("What's our patch status across systems?", ["vulnerabilities", "patching"]),
            ("How does our vulnerability count compare to last month?", ["vulnerabilities", "trends"]),
        ],
        'risk_assessment': [
            ("What are our highest risk assets?", ["risk", "assets"]),
            ("How should we prioritize risk remediation?", ["risk", "remediation"]),
            ("What's the potential business impact of our top risks?", ["risk", "impact"]),
        ],
        'compliance_review': [
            ("Where do we have compliance gaps?", ["compliance", "gaps"]),
            ("What frameworks are we compliant with?", ["compliance", "frameworks"]),
            ("What's needed for our next audit?", ["compliance", "audit"]),
        ],
        'threat_analysis': [
            ("What threats are targeting our industry?", ["threats", "intelligence"]),
            ("How are we protected against ransomware?", ["threats", "ransomware"]),
            ("What's our threat landscape look like?", ["threats", "landscape"]),
        ],
        'incident_response': [
            ("What incidents are currently open?", ["incidents", "open"]),
            ("How are we tracking on incident response times?", ["incidents", "response"]),
            ("What patterns do we see in recent incidents?", ["incidents", "patterns"]),
        ],
        'access_management': [
            ("Who has privileged access to critical systems?", ["access", "privileged"]),
            ("Are there any dormant accounts we should review?", ["access", "dormant"]),
            ("How is our MFA adoption?", ["access", "mfa"]),
        ],
        'security_planning': [
            ("Help me build a security roadmap", ["planning", "roadmap"]),
            ("What security investments should we prioritize?", ["planning", "investment"]),
            ("How should we allocate our security budget?", ["planning", "budget"]),
        ],
    }

    # Context-triggered prompts (signal -> prompt)
    CONTEXT_TRIGGERS = {
        # Critical vulnerability triggers
        'critical_vulns': {
            'condition': lambda ctx: ctx.get('vulnerabilities', {}).get('critical', 0) > 0,
            'prompt': "You have {critical} critical vulnerabilities. Should we prioritize remediation?",
            'category': SuggestionCategory.URGENT,
            'relevance': 98,
            'tags': ['vulnerabilities', 'critical', 'urgent']
        },
        'high_vulns': {
            'condition': lambda ctx: ctx.get('vulnerabilities', {}).get('high', 0) > 10,
            'prompt': "{high} high-severity vulnerabilities detected. Let's review the attack surface.",
            'category': SuggestionCategory.URGENT,
            'relevance': 90,
            'tags': ['vulnerabilities', 'high', 'remediation']
        },
        'unpatched_systems': {
            'condition': lambda ctx: ctx.get('patch_compliance', 0) < 80,
            'prompt': "Patch compliance is at {patch_compliance}%. How can we improve patching?",
            'category': SuggestionCategory.URGENT,
            'relevance': 88,
            'tags': ['patching', 'compliance', 'systems']
        },

        # Compliance triggers
        'compliance_gap': {
            'condition': lambda ctx: ctx.get('compliance', {}).get('score', 100) < 70,
            'prompt': "Compliance score is {score}%. Let's address the critical gaps.",
            'category': SuggestionCategory.URGENT,
            'relevance': 92,
            'tags': ['compliance', 'gaps', 'audit']
        },
        'framework_failing': {
            'condition': lambda ctx: any(f.get('status') == 'failing' for f in ctx.get('frameworks', [])),
            'prompt': "Some compliance frameworks are failing. Should we review requirements?",
            'category': SuggestionCategory.URGENT,
            'relevance': 89,
            'tags': ['compliance', 'frameworks', 'requirements']
        },

        # Incident triggers
        'open_incidents': {
            'condition': lambda ctx: ctx.get('incidents', {}).get('open', 0) > 5,
            'prompt': "You have {open} open incidents. Let's discuss response priorities.",
            'category': SuggestionCategory.URGENT,
            'relevance': 94,
            'tags': ['incidents', 'response', 'priorities']
        },
        'critical_incident': {
            'condition': lambda ctx: any(i.get('severity') == 'critical' for i in ctx.get('incident_list', [])),
            'prompt': "A critical incident is active. Do you need response guidance?",
            'category': SuggestionCategory.URGENT,
            'relevance': 99,
            'tags': ['incidents', 'critical', 'response']
        },
        'slow_response': {
            'condition': lambda ctx: ctx.get('mttr_hours', 0) > 24,
            'prompt': "Mean time to resolve is {mttr_hours} hours. How can we speed up response?",
            'category': SuggestionCategory.OPPORTUNITY,
            'relevance': 80,
            'tags': ['incidents', 'mttr', 'efficiency']
        },

        # Risk triggers
        'high_risk_score': {
            'condition': lambda ctx: ctx.get('risk_score', 0) > 75,
            'prompt': "Risk score is {risk_score}/100. Let's identify mitigation strategies.",
            'category': SuggestionCategory.URGENT,
            'relevance': 91,
            'tags': ['risk', 'mitigation', 'strategy']
        },
        'unmitigated_risks': {
            'condition': lambda ctx: len(ctx.get('unmitigated_risks', [])) > 3,
            'prompt': "There are {count} unmitigated risks. Should we review the risk register?",
            'category': SuggestionCategory.OPPORTUNITY,
            'relevance': 82,
            'tags': ['risk', 'register', 'mitigation']
        },

        # Threat triggers
        'active_threats': {
            'condition': lambda ctx: ctx.get('threat_intel', {}).get('active_campaigns', 0) > 0,
            'prompt': "{active_campaigns} threat campaigns are targeting your industry. Review defenses?",
            'category': SuggestionCategory.URGENT,
            'relevance': 87,
            'tags': ['threats', 'campaigns', 'defenses']
        },

        # Access triggers
        'privileged_access_review': {
            'condition': lambda ctx: ctx.get('access', {}).get('privileged_users', 0) > 50,
            'prompt': "You have {privileged_users} privileged accounts. Time for an access review?",
            'category': SuggestionCategory.OPPORTUNITY,
            'relevance': 75,
            'tags': ['access', 'privileged', 'review']
        },
        'low_mfa': {
            'condition': lambda ctx: ctx.get('access', {}).get('mfa_adoption', 100) < 90,
            'prompt': "MFA adoption is at {mfa_adoption}%. Let's discuss rollout strategy.",
            'category': SuggestionCategory.OPPORTUNITY,
            'relevance': 78,
            'tags': ['access', 'mfa', 'adoption']
        },

        # Posture triggers
        'weak_posture': {
            'condition': lambda ctx: ctx.get('posture_score', 100) < 60,
            'prompt': "Security posture score is {posture_score}. Where should we focus first?",
            'category': SuggestionCategory.URGENT,
            'relevance': 93,
            'tags': ['posture', 'improvement', 'priorities']
        },
    }

    def __init__(self):
        pass

    def get_suggestions(
        self,
        mode: str,
        context: Dict[str, Any],
        conversation_history: List[Dict[str, Any]],
        discussed_topics: List[str] = None,
        dismissed_prompts: List[str] = None,
        max_suggestions: int = 4
    ) -> List[SuggestedPrompt]:
        """
        Generate context-aware suggestions.

        Args:
            mode: Current conversation mode
            context: Security context (vulnerabilities, incidents, compliance, etc.)
            conversation_history: Previous messages
            discussed_topics: Topics already covered
            dismissed_prompts: Prompts user has dismissed
            max_suggestions: Maximum number of suggestions to return

        Returns:
            List of SuggestedPrompt objects sorted by relevance
        """
        discussed_topics = discussed_topics or []
        dismissed_prompts = dismissed_prompts or []

        suggestions = []

        # 1. Check context-triggered prompts first (highest priority)
        for trigger_name, trigger in self.CONTEXT_TRIGGERS.items():
            try:
                if trigger['condition'](context):
                    prompt_text = self._format_prompt(trigger['prompt'], context)

                    # Skip if already discussed or dismissed
                    if self._is_topic_discussed(trigger['tags'], discussed_topics):
                        continue
                    if prompt_text in dismissed_prompts:
                        continue

                    suggestions.append(SuggestedPrompt(
                        prompt_text=prompt_text,
                        relevance_score=trigger['relevance'],
                        category=trigger['category'],
                        rationale=f"Based on your current {trigger_name.replace('_', ' ')} status",
                        topic_tags=trigger['tags']
                    ))
            except Exception:
                continue  # Skip malformed triggers

        # 2. Add base prompts for the mode (fill remaining slots)
        base_prompts = self.BASE_PROMPTS.get(mode, self.BASE_PROMPTS['general'])
        for prompt_text, tags in base_prompts:
            if self._is_topic_discussed(tags, discussed_topics):
                continue
            if prompt_text in dismissed_prompts:
                continue

            # Lower relevance for base prompts
            relevance = 50 - (len(suggestions) * 5)  # Decreasing relevance

            suggestions.append(SuggestedPrompt(
                prompt_text=prompt_text,
                relevance_score=max(relevance, 20),
                category=SuggestionCategory.GENERAL,
                rationale=f"Common question for {mode.replace('_', ' ')}",
                topic_tags=tags
            ))

        # 3. Add follow-up suggestions based on conversation history
        if conversation_history:
            follow_ups = self._generate_follow_ups(conversation_history, discussed_topics)
            suggestions.extend(follow_ups)

        # Sort by relevance and return top N
        suggestions.sort(key=lambda x: x.relevance_score, reverse=True)
        return suggestions[:max_suggestions]

    def _format_prompt(self, template: str, context: Dict[str, Any]) -> str:
        """Format prompt template with context values."""
        vulnerabilities = context.get('vulnerabilities', {})
        compliance = context.get('compliance', {})
        incidents = context.get('incidents', {})
        access = context.get('access', {})
        threat_intel = context.get('threat_intel', {})

        # Flatten context for formatting
        format_dict = {
            **vulnerabilities,
            **compliance,
            **incidents,
            **access,
            **threat_intel,
            'patch_compliance': context.get('patch_compliance', 0),
            'risk_score': context.get('risk_score', 0),
            'posture_score': context.get('posture_score', 0),
            'mttr_hours': context.get('mttr_hours', 0),
            'count': len(context.get('unmitigated_risks', [])),
        }

        try:
            return template.format(**format_dict)
        except KeyError:
            return template  # Return unformatted if values missing

    def _is_topic_discussed(self, tags: List[str], discussed: List[str]) -> bool:
        """Check if topic tags overlap with discussed topics."""
        return any(tag in discussed for tag in tags)

    def _generate_follow_ups(
        self,
        history: List[Dict[str, Any]],
        discussed: List[str]
    ) -> List[SuggestedPrompt]:
        """Generate follow-up suggestions based on conversation history."""
        follow_ups = []

        if not history:
            return follow_ups

        # Get last assistant message
        last_messages = [m for m in history[-4:] if m.get('role') == 'assistant']
        if not last_messages:
            return follow_ups

        last_response = last_messages[-1].get('content', '').lower()

        # Check for actionable topics mentioned
        follow_up_triggers = [
            {
                'keywords': ['recommend', 'suggest', 'should consider'],
                'prompt': "Can you elaborate on those security recommendations?",
                'tags': ['follow-up', 'recommendations']
            },
            {
                'keywords': ['vulnerability', 'vulnerabilities', 'cve'],
                'prompt': "How do we prioritize fixing these vulnerabilities?",
                'tags': ['follow-up', 'vulnerabilities']
            },
            {
                'keywords': ['incident', 'breach', 'attack'],
                'prompt': "What's the containment and recovery plan?",
                'tags': ['follow-up', 'incidents']
            },
            {
                'keywords': ['compliance', 'audit', 'framework'],
                'prompt': "What specific controls do we need to implement?",
                'tags': ['follow-up', 'compliance']
            },
            {
                'keywords': ['risk', 'threat', 'exposure'],
                'prompt': "What's the mitigation priority for these risks?",
                'tags': ['follow-up', 'risk']
            },
        ]

        for trigger in follow_up_triggers:
            if any(kw in last_response for kw in trigger['keywords']):
                if not self._is_topic_discussed(trigger['tags'], discussed):
                    follow_ups.append(SuggestedPrompt(
                        prompt_text=trigger['prompt'],
                        relevance_score=70,
                        category=SuggestionCategory.FOLLOW_UP,
                        rationale="Follow up on our previous discussion",
                        topic_tags=trigger['tags']
                    ))

        return follow_ups[:2]  # Max 2 follow-ups

    def extract_topics(self, message: str) -> List[str]:
        """Extract topic tags from a message."""
        topics = []

        topic_keywords = {
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

        message_lower = message.lower()
        for topic, keywords in topic_keywords.items():
            if any(kw in message_lower for kw in keywords):
                topics.append(topic)

        return topics


# Factory function
def create_security_suggestion_engine() -> SecuritySuggestionEngine:
    return SecuritySuggestionEngine()
