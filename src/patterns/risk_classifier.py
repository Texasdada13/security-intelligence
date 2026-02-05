"""Security Risk Classification Engine"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class RiskLevel(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    MINIMAL = "Minimal"


class RiskCategory(Enum):
    CYBER = "Cyber Risk"
    COMPLIANCE = "Compliance Risk"
    OPERATIONAL = "Operational Risk"
    THIRD_PARTY = "Third Party Risk"
    DATA = "Data Risk"
    PHYSICAL = "Physical Security Risk"


@dataclass
class RiskFactor:
    id: str
    name: str
    category: RiskCategory
    weight: float = 1.0
    description: str = ""


@dataclass
class RiskAssessment:
    risk_id: str
    risk_name: str
    category: str
    likelihood: float  # 1-5
    impact: float  # 1-5
    raw_score: float
    risk_level: RiskLevel
    current_controls: List[str]
    residual_risk: float
    mitigation_priority: int
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_id": self.risk_id,
            "risk_name": self.risk_name,
            "category": self.category,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "raw_score": round(self.raw_score, 1),
            "risk_level": self.risk_level.value,
            "current_controls": self.current_controls,
            "residual_risk": round(self.residual_risk, 1),
            "mitigation_priority": self.mitigation_priority,
            "recommendations": self.recommendations
        }


@dataclass
class RiskRegister:
    entity_id: str
    total_risks: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_risk_score: float
    overall_risk_level: RiskLevel
    risk_assessments: List[RiskAssessment]
    top_risks: List[str]
    risk_trend: str  # Improving, Stable, Deteriorating
    priority_actions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "total_risks": self.total_risks,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "overall_risk_score": round(self.overall_risk_score, 1),
            "overall_risk_level": self.overall_risk_level.value,
            "risk_assessments": [ra.to_dict() for ra in self.risk_assessments],
            "top_risks": self.top_risks,
            "risk_trend": self.risk_trend,
            "priority_actions": self.priority_actions
        }


class RiskClassifier:
    """Security risk classification and assessment engine."""

    RISK_THRESHOLDS = {
        20: RiskLevel.CRITICAL,
        15: RiskLevel.HIGH,
        10: RiskLevel.MEDIUM,
        5: RiskLevel.LOW,
        0: RiskLevel.MINIMAL
    }

    def __init__(self, risk_factors: Optional[List[RiskFactor]] = None):
        self.risk_factors = {rf.id: rf for rf in (risk_factors or [])}

    def assess_risk(self, risk_id: str, risk_name: str, category: RiskCategory,
                    likelihood: float, impact: float, control_effectiveness: float = 0.5,
                    current_controls: List[str] = None) -> RiskAssessment:
        """Assess a single risk."""
        # Calculate raw risk score (likelihood * impact)
        raw_score = likelihood * impact

        # Calculate residual risk after controls
        residual = raw_score * (1 - control_effectiveness)

        # Determine risk level
        risk_level = self._classify_risk_level(raw_score)

        # Calculate priority (1 = highest priority)
        priority = self._calculate_priority(raw_score, impact)

        # Generate recommendations
        recommendations = self._generate_recommendations(risk_name, risk_level, control_effectiveness)

        return RiskAssessment(
            risk_id=risk_id,
            risk_name=risk_name,
            category=category.value,
            likelihood=likelihood,
            impact=impact,
            raw_score=raw_score,
            risk_level=risk_level,
            current_controls=current_controls or [],
            residual_risk=residual,
            mitigation_priority=priority,
            recommendations=recommendations
        )

    def create_risk_register(self, risk_data: List[Dict[str, Any]],
                            entity_id: str = "unknown",
                            previous_score: float = None) -> RiskRegister:
        """Create comprehensive risk register from risk data."""
        assessments = []

        for risk in risk_data:
            assessment = self.assess_risk(
                risk_id=risk.get("id", ""),
                risk_name=risk.get("name", ""),
                category=RiskCategory(risk.get("category", RiskCategory.CYBER.value)),
                likelihood=risk.get("likelihood", 3),
                impact=risk.get("impact", 3),
                control_effectiveness=risk.get("control_effectiveness", 0.5),
                current_controls=risk.get("controls", [])
            )
            assessments.append(assessment)

        # Count by level
        critical = sum(1 for a in assessments if a.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for a in assessments if a.risk_level == RiskLevel.HIGH)
        medium = sum(1 for a in assessments if a.risk_level == RiskLevel.MEDIUM)
        low = sum(1 for a in assessments if a.risk_level == RiskLevel.LOW)

        # Calculate overall risk score
        if assessments:
            overall_score = sum(a.residual_risk for a in assessments) / len(assessments)
        else:
            overall_score = 0

        # Determine overall risk level
        overall_level = self._classify_risk_level(overall_score)

        # Top risks
        sorted_risks = sorted(assessments, key=lambda x: x.raw_score, reverse=True)
        top_risks = [a.risk_name for a in sorted_risks[:5]]

        # Determine trend
        if previous_score is not None:
            if overall_score < previous_score * 0.9:
                trend = "Improving"
            elif overall_score > previous_score * 1.1:
                trend = "Deteriorating"
            else:
                trend = "Stable"
        else:
            trend = "Baseline"

        # Priority actions
        priority_actions = []
        for a in sorted_risks[:5]:
            if a.recommendations:
                priority_actions.append(f"{a.risk_name}: {a.recommendations[0]}")

        return RiskRegister(
            entity_id=entity_id,
            total_risks=len(assessments),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            overall_risk_score=overall_score,
            overall_risk_level=overall_level,
            risk_assessments=assessments,
            top_risks=top_risks,
            risk_trend=trend,
            priority_actions=priority_actions
        )

    def _classify_risk_level(self, score: float) -> RiskLevel:
        for threshold, level in sorted(self.RISK_THRESHOLDS.items(), reverse=True):
            if score >= threshold:
                return level
        return RiskLevel.MINIMAL

    def _calculate_priority(self, raw_score: float, impact: float) -> int:
        """Calculate priority 1-5 (1 = highest)."""
        combined = (raw_score * 0.6 + impact * 0.4 * 5)
        if combined >= 20:
            return 1
        elif combined >= 15:
            return 2
        elif combined >= 10:
            return 3
        elif combined >= 5:
            return 4
        return 5

    def _generate_recommendations(self, risk_name: str, level: RiskLevel,
                                  control_effectiveness: float) -> List[str]:
        """Generate risk mitigation recommendations."""
        recs = []

        if level == RiskLevel.CRITICAL:
            recs.append(f"Immediate action required: Implement emergency controls for {risk_name}")
            recs.append("Escalate to executive leadership immediately")
        elif level == RiskLevel.HIGH:
            recs.append(f"High priority: Enhance controls for {risk_name}")
            recs.append("Develop detailed remediation plan within 30 days")
        elif level == RiskLevel.MEDIUM:
            recs.append(f"Monitor and improve controls for {risk_name}")

        if control_effectiveness < 0.3:
            recs.append("Existing controls are inadequate - implement additional safeguards")
        elif control_effectiveness < 0.6:
            recs.append("Review and strengthen existing control implementation")

        return recs[:3]


def create_default_risk_factors() -> List[RiskFactor]:
    """Create default set of security risk factors."""
    return [
        RiskFactor("ransomware", "Ransomware Attack", RiskCategory.CYBER, 1.2),
        RiskFactor("data_breach", "Data Breach", RiskCategory.DATA, 1.3),
        RiskFactor("phishing", "Phishing/Social Engineering", RiskCategory.CYBER, 1.1),
        RiskFactor("insider_threat", "Insider Threat", RiskCategory.OPERATIONAL, 1.0),
        RiskFactor("third_party", "Third Party Breach", RiskCategory.THIRD_PARTY, 1.1),
        RiskFactor("compliance_violation", "Compliance Violation", RiskCategory.COMPLIANCE, 1.0),
        RiskFactor("ddos", "DDoS Attack", RiskCategory.CYBER, 0.9),
        RiskFactor("physical_breach", "Physical Security Breach", RiskCategory.PHYSICAL, 0.8),
        RiskFactor("cloud_misconfiguration", "Cloud Misconfiguration", RiskCategory.CYBER, 1.1),
        RiskFactor("supply_chain", "Supply Chain Attack", RiskCategory.THIRD_PARTY, 1.2),
    ]
