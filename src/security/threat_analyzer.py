"""Threat Intelligence Analyzer"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
from datetime import datetime


class ThreatType(Enum):
    MALWARE = "Malware"
    PHISHING = "Phishing"
    RANSOMWARE = "Ransomware"
    APT = "Advanced Persistent Threat"
    INSIDER = "Insider Threat"
    DDOS = "DDoS"
    EXPLOITATION = "Exploitation"
    DATA_EXFILTRATION = "Data Exfiltration"


class ThreatSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class ThreatIndicator:
    indicator_id: str
    indicator_type: str  # IP, Domain, Hash, URL
    value: str
    threat_type: ThreatType
    severity: ThreatSeverity
    confidence: float  # 0-100
    source: str
    first_seen: datetime
    last_seen: datetime
    description: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "indicator_type": self.indicator_type,
            "value": self.value,
            "threat_type": self.threat_type.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 1),
            "source": self.source,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "description": self.description,
            "tags": self.tags
        }


@dataclass
class ThreatLandscape:
    entity_id: str
    total_indicators: int
    active_threats: int
    threat_level: str
    threat_by_type: Dict[str, int]
    threat_by_severity: Dict[str, int]
    top_threats: List[ThreatIndicator]
    emerging_threats: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "total_indicators": self.total_indicators,
            "active_threats": self.active_threats,
            "threat_level": self.threat_level,
            "threat_by_type": self.threat_by_type,
            "threat_by_severity": self.threat_by_severity,
            "top_threats": [t.to_dict() for t in self.top_threats],
            "emerging_threats": self.emerging_threats,
            "recommendations": self.recommendations
        }


class ThreatAnalyzer:
    """Threat intelligence analysis engine."""

    THREAT_LEVEL_THRESHOLDS = {
        10: "Critical",
        5: "High",
        2: "Medium",
        0: "Low"
    }

    def __init__(self):
        self.indicators: List[ThreatIndicator] = []

    def add_indicator(self, indicator: ThreatIndicator):
        """Add a threat indicator."""
        self.indicators.append(indicator)

    def analyze_landscape(self, indicators: List[ThreatIndicator] = None,
                          entity_id: str = "unknown") -> ThreatLandscape:
        """Analyze current threat landscape."""
        indicators = indicators or self.indicators

        # Count by type
        by_type: Dict[str, int] = {}
        for i in indicators:
            key = i.threat_type.value
            by_type[key] = by_type.get(key, 0) + 1

        # Count by severity
        by_severity: Dict[str, int] = {}
        for i in indicators:
            key = i.severity.value
            by_severity[key] = by_severity.get(key, 0) + 1

        # Active threats (high confidence, recent)
        now = datetime.utcnow()
        active = [i for i in indicators if i.confidence >= 70 and
                  (now - i.last_seen).days <= 7]

        # Determine threat level
        critical_count = by_severity.get("Critical", 0)
        high_count = by_severity.get("High", 0)
        threat_score = critical_count * 2 + high_count
        threat_level = self._determine_threat_level(threat_score)

        # Top threats
        sorted_indicators = sorted(
            indicators,
            key=lambda x: (
                0 if x.severity == ThreatSeverity.CRITICAL else
                1 if x.severity == ThreatSeverity.HIGH else 2,
                -x.confidence
            )
        )
        top_threats = sorted_indicators[:5]

        # Emerging threats (identify common patterns)
        emerging = self._identify_emerging_threats(indicators)

        # Recommendations
        recommendations = self._generate_recommendations(by_type, by_severity, active)

        return ThreatLandscape(
            entity_id=entity_id,
            total_indicators=len(indicators),
            active_threats=len(active),
            threat_level=threat_level,
            threat_by_type=by_type,
            threat_by_severity=by_severity,
            top_threats=top_threats,
            emerging_threats=emerging,
            recommendations=recommendations
        )

    def _determine_threat_level(self, score: int) -> str:
        """Determine overall threat level."""
        for threshold, level in sorted(self.THREAT_LEVEL_THRESHOLDS.items(), reverse=True):
            if score >= threshold:
                return level
        return "Low"

    def _identify_emerging_threats(self, indicators: List[ThreatIndicator]) -> List[str]:
        """Identify emerging threat patterns."""
        emerging = []

        # Look for recent high-confidence indicators
        recent = [i for i in indicators if (datetime.utcnow() - i.first_seen).days <= 30]
        if len(recent) > len(indicators) * 0.3:
            emerging.append("Significant increase in new threat indicators")

        # Check for ransomware trends
        ransomware = [i for i in indicators if i.threat_type == ThreatType.RANSOMWARE]
        if len(ransomware) > 3:
            emerging.append("Elevated ransomware activity detected")

        # Check for APT indicators
        apt = [i for i in indicators if i.threat_type == ThreatType.APT]
        if apt:
            emerging.append("Advanced persistent threat indicators present")

        return emerging[:5]

    def _generate_recommendations(self, by_type: Dict[str, int],
                                  by_severity: Dict[str, int],
                                  active: List[ThreatIndicator]) -> List[str]:
        """Generate threat-based recommendations."""
        recs = []

        if by_severity.get("Critical", 0) > 0:
            recs.append("Immediately investigate critical severity indicators")

        if by_type.get("Ransomware", 0) > 0:
            recs.append("Review backup and recovery procedures")
            recs.append("Ensure endpoint detection is up to date")

        if by_type.get("Phishing", 0) > 0:
            recs.append("Conduct security awareness training on phishing")

        if len(active) > 5:
            recs.append("Increase security monitoring intensity")

        if by_type.get("Exploitation", 0) > 0:
            recs.append("Verify patch levels on critical systems")

        return recs[:5]
