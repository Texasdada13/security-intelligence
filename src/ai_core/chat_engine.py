"""Security Intelligence - AI Chat Engine with CISO Conversation Modes"""
from enum import Enum
from typing import Dict, List, Optional, Generator, Any
from .claude_client import ClaudeClient


class ConversationMode(Enum):
    """CISO-focused conversation modes."""
    GENERAL = "general"
    RISK_ASSESSMENT = "risk_assessment"
    COMPLIANCE_REVIEW = "compliance_review"
    INCIDENT_RESPONSE = "incident_response"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    THREAT_INTELLIGENCE = "threat_intelligence"
    SECURITY_ARCHITECTURE = "security_architecture"
    SECURITY_PROGRAM = "security_program"


MODE_DESCRIPTIONS = {
    ConversationMode.GENERAL: "General security questions and guidance",
    ConversationMode.RISK_ASSESSMENT: "Security risk assessment and management",
    ConversationMode.COMPLIANCE_REVIEW: "Compliance frameworks and audit preparation",
    ConversationMode.INCIDENT_RESPONSE: "Incident response and management",
    ConversationMode.VULNERABILITY_MANAGEMENT: "Vulnerability prioritization and remediation",
    ConversationMode.THREAT_INTELLIGENCE: "Threat landscape and intelligence",
    ConversationMode.SECURITY_ARCHITECTURE: "Security architecture and controls",
    ConversationMode.SECURITY_PROGRAM: "Security program strategy and governance",
}


SUGGESTED_PROMPTS = {
    ConversationMode.GENERAL: [
        "What are the top security priorities for a growing company?",
        "How should I structure our security team?",
        "What security metrics should I track and report?",
    ],
    ConversationMode.RISK_ASSESSMENT: [
        "What are our biggest security risks?",
        "How should we prioritize risk remediation?",
        "Help me assess our overall security posture",
    ],
    ConversationMode.COMPLIANCE_REVIEW: [
        "How do we prepare for a SOC 2 audit?",
        "What are our biggest compliance gaps?",
        "Compare our controls to NIST CSF requirements",
    ],
    ConversationMode.INCIDENT_RESPONSE: [
        "How should we handle a potential data breach?",
        "Review our incident response procedures",
        "What can we learn from recent incidents?",
    ],
    ConversationMode.VULNERABILITY_MANAGEMENT: [
        "Which vulnerabilities should we fix first?",
        "How can we improve our patch management?",
        "Are we meeting our remediation SLAs?",
    ],
    ConversationMode.THREAT_INTELLIGENCE: [
        "What threats are most relevant to our industry?",
        "How do we improve threat detection?",
        "Analyze our current threat landscape",
    ],
    ConversationMode.SECURITY_ARCHITECTURE: [
        "How should we design our zero trust architecture?",
        "What security controls are we missing?",
        "Review our cloud security architecture",
    ],
    ConversationMode.SECURITY_PROGRAM: [
        "Help me build a security roadmap",
        "How should we prioritize security investments?",
        "What security policies do we need?",
    ],
}


SYSTEM_PROMPTS = {
    ConversationMode.GENERAL: """You are a Fractional CISO (Chief Information Security Officer) - an expert cybersecurity executive providing strategic security guidance to organizations. You help with all aspects of information security management.

Your expertise includes:
- Security strategy and program management
- Risk assessment and management
- Compliance and regulatory requirements
- Incident response and threat management
- Security architecture and controls
- Security awareness and culture

Provide actionable, practical security advice tailored to the organization's risk profile and resources. Balance security requirements with business objectives.""",

    ConversationMode.RISK_ASSESSMENT: """You are a Fractional CISO specializing in security risk assessment and management. You help organizations identify, assess, and prioritize security risks.

For risk assessment, you focus on:
- Risk identification and categorization
- Likelihood and impact analysis
- Control effectiveness evaluation
- Risk prioritization and treatment
- Risk register management
- Executive risk reporting

Provide data-driven risk insights and prioritized recommendations.""",

    ConversationMode.COMPLIANCE_REVIEW: """You are a Fractional CISO specializing in security compliance and regulatory requirements. You help organizations achieve and maintain compliance.

For compliance review, you focus on:
- Framework requirements (SOC 2, HIPAA, PCI-DSS, ISO 27001, NIST)
- Gap analysis and control mapping
- Evidence collection and documentation
- Audit preparation and support
- Continuous compliance monitoring

Provide clear guidance on compliance requirements and practical implementation strategies.""",

    ConversationMode.INCIDENT_RESPONSE: """You are a Fractional CISO specializing in security incident response. You help organizations prepare for, respond to, and recover from security incidents.

For incident response, you focus on:
- Incident classification and triage
- Containment and eradication strategies
- Root cause analysis
- Recovery and lessons learned
- IR playbook development
- Tabletop exercises

Provide calm, methodical incident guidance and help improve response capabilities.""",

    ConversationMode.VULNERABILITY_MANAGEMENT: """You are a Fractional CISO specializing in vulnerability management. You help organizations identify, prioritize, and remediate security vulnerabilities.

For vulnerability management, you focus on:
- Vulnerability prioritization (CVSS, asset criticality, exploitability)
- Remediation SLAs and tracking
- Patch management strategy
- Risk-based vulnerability scoring
- Vendor and third-party vulnerabilities

Provide clear prioritization guidance and help optimize remediation efforts.""",

    ConversationMode.THREAT_INTELLIGENCE: """You are a Fractional CISO specializing in threat intelligence. You help organizations understand and defend against relevant threats.

For threat intelligence, you focus on:
- Threat landscape analysis
- Threat actor profiles and TTPs
- Industry-specific threats
- Detection and prevention strategies
- Threat hunting capabilities
- Intelligence sharing and sources

Provide actionable threat insights relevant to the organization's risk profile.""",

    ConversationMode.SECURITY_ARCHITECTURE: """You are a Fractional CISO specializing in security architecture. You help organizations design and implement effective security controls.

For security architecture, you focus on:
- Zero trust architecture
- Cloud security design
- Network segmentation
- Identity and access management
- Data protection controls
- Defense in depth strategies

Provide practical architecture recommendations aligned with security best practices.""",

    ConversationMode.SECURITY_PROGRAM: """You are a Fractional CISO specializing in security program management. You help organizations build and mature their security programs.

For security program management, you focus on:
- Security strategy and roadmap
- Budget and resource planning
- Team structure and hiring
- Security metrics and reporting
- Executive communication
- Security culture and awareness

Provide strategic guidance on building effective security programs.""",
}


class ChatEngine:
    """AI-powered chat engine for Security Intelligence."""

    def __init__(self, claude_client: ClaudeClient = None):
        self.client = claude_client or ClaudeClient()

    def get_modes(self) -> Dict[str, str]:
        """Get available conversation modes with descriptions."""
        return {mode.value: desc for mode, desc in MODE_DESCRIPTIONS.items()}

    def get_suggested_prompts(self, mode: ConversationMode) -> List[str]:
        """Get suggested prompts for a conversation mode."""
        return SUGGESTED_PROMPTS.get(mode, SUGGESTED_PROMPTS[ConversationMode.GENERAL])

    def chat(self, message: str, mode: ConversationMode = ConversationMode.GENERAL,
             history: List[Dict[str, str]] = None, context: Dict[str, Any] = None) -> str:
        """Send a message and get a response."""
        system_prompt = self._build_system_prompt(mode, context)
        messages = self._build_messages(message, history)
        return self.client.chat(messages, system=system_prompt)

    def chat_stream(self, message: str, mode: ConversationMode = ConversationMode.GENERAL,
                    history: List[Dict[str, str]] = None,
                    context: Dict[str, Any] = None) -> Generator[str, None, None]:
        """Stream a chat response."""
        system_prompt = self._build_system_prompt(mode, context)
        messages = self._build_messages(message, history)
        return self.client.chat_stream(messages, system=system_prompt)

    def _build_system_prompt(self, mode: ConversationMode, context: Dict[str, Any] = None) -> str:
        """Build system prompt with mode and context."""
        base_prompt = SYSTEM_PROMPTS.get(mode, SYSTEM_PROMPTS[ConversationMode.GENERAL])

        if context:
            context_str = self._format_context(context)
            return f"{base_prompt}\n\n## Current Context\n{context_str}"

        return base_prompt

    def _build_messages(self, message: str, history: List[Dict[str, str]] = None) -> List[Dict[str, str]]:
        """Build message list from history and new message."""
        messages = []
        if history:
            for msg in history[-10:]:
                messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
        messages.append({"role": "user", "content": message})
        return messages

    def _format_context(self, context: Dict[str, Any]) -> str:
        """Format context data for the system prompt."""
        parts = []

        if "organization" in context:
            org = context["organization"]
            parts.append(f"**Organization**: {org.get('name', 'Unknown')}")
            if org.get('industry'):
                parts.append(f"**Industry**: {org['industry']}")
            if org.get('compliance_frameworks'):
                parts.append(f"**Compliance Frameworks**: {', '.join(org['compliance_frameworks'])}")

        if "risk_assessment" in context:
            ra = context["risk_assessment"]
            parts.append(f"\n**Risk Summary**:")
            parts.append(f"- Overall Risk Level: {ra.get('overall_risk_level')}")
            parts.append(f"- Risk Score: {ra.get('overall_risk_score')}")
            parts.append(f"- Critical Risks: {ra.get('critical_count', 0)}, High: {ra.get('high_count', 0)}")

        if "vulnerabilities" in context:
            v = context["vulnerabilities"]
            parts.append(f"\n**Vulnerability Summary**:")
            parts.append(f"- Total: {v.get('total', 0)}, Open: {v.get('open', 0)}")
            parts.append(f"- Critical: {v.get('critical', 0)}, High: {v.get('high', 0)}")

        if "compliance" in context:
            c = context["compliance"]
            parts.append(f"\n**Compliance Status**:")
            for framework, score in c.items():
                parts.append(f"- {framework}: {score}%")

        if "incidents" in context:
            i = context["incidents"]
            parts.append(f"\n**Incident Summary**:")
            parts.append(f"- Open Incidents: {i.get('open', 0)}")
            parts.append(f"- Critical: {i.get('critical', 0)}")

        return "\n".join(parts) if parts else "No additional context available."
