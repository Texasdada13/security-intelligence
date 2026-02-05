"""Security Posture Scoring Engine"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class SecurityDomain(Enum):
    ACCESS_CONTROL = "Access Control"
    DATA_PROTECTION = "Data Protection"
    NETWORK_SECURITY = "Network Security"
    ENDPOINT_SECURITY = "Endpoint Security"
    INCIDENT_RESPONSE = "Incident Response"
    VULNERABILITY_MANAGEMENT = "Vulnerability Management"
    SECURITY_AWARENESS = "Security Awareness"
    GOVERNANCE = "Governance & Compliance"


@dataclass
class ScoringComponent:
    id: str
    name: str
    weight: float
    domain: SecurityDomain
    description: str = ""
    max_score: float = 100.0


@dataclass
class ComponentScore:
    component_id: str
    component_name: str
    domain: str
    raw_score: float
    weighted_score: float
    max_score: float
    weight: float
    rating: str
    gaps: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component_id": self.component_id,
            "component_name": self.component_name,
            "domain": self.domain,
            "raw_score": round(self.raw_score, 1),
            "weighted_score": round(self.weighted_score, 2),
            "rating": self.rating,
            "gaps": self.gaps,
            "recommendations": self.recommendations
        }


@dataclass
class SecurityPostureReport:
    entity_id: str
    overall_score: float
    overall_rating: str
    grade: str
    domain_scores: Dict[str, float]
    component_scores: List[ComponentScore]
    critical_gaps: List[str]
    high_priority_recommendations: List[str]
    maturity_level: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "overall_score": round(self.overall_score, 1),
            "overall_rating": self.overall_rating,
            "grade": self.grade,
            "domain_scores": {k: round(v, 1) for k, v in self.domain_scores.items()},
            "component_scores": [cs.to_dict() for cs in self.component_scores],
            "critical_gaps": self.critical_gaps,
            "high_priority_recommendations": self.high_priority_recommendations,
            "maturity_level": self.maturity_level
        }


class SecurityScoringEngine:
    """Multi-dimensional security posture scoring engine."""

    RATING_THRESHOLDS = {90: "Excellent", 80: "Good", 70: "Fair", 50: "Poor", 0: "Critical"}
    GRADE_THRESHOLDS = {90: "A", 80: "B", 70: "C", 60: "D", 0: "F"}
    MATURITY_LEVELS = {90: "Optimized", 75: "Managed", 60: "Defined", 40: "Developing", 0: "Initial"}

    def __init__(self, components: List[ScoringComponent], domain_weights: Optional[Dict[str, float]] = None):
        self.components = {c.id: c for c in components}
        self.domain_weights = domain_weights or {}
        self.total_weight = sum(c.weight for c in components)

    def calculate_score(self, values: Dict[str, float], entity_id: str = "unknown") -> SecurityPostureReport:
        """Calculate comprehensive security posture score."""
        component_scores = []
        domain_totals: Dict[str, List[float]] = {}

        for comp_id, comp in self.components.items():
            raw_score = values.get(comp_id, 0)
            normalized = min(100, (raw_score / comp.max_score) * 100)
            weighted = normalized * (comp.weight / self.total_weight)

            rating = self._get_rating(normalized)
            gaps = self._identify_gaps(comp, normalized)
            recs = self._generate_recommendations(comp, normalized)

            component_scores.append(ComponentScore(
                component_id=comp_id,
                component_name=comp.name,
                domain=comp.domain.value,
                raw_score=raw_score,
                weighted_score=weighted,
                max_score=comp.max_score,
                weight=comp.weight,
                rating=rating,
                gaps=gaps,
                recommendations=recs
            ))

            domain = comp.domain.value
            if domain not in domain_totals:
                domain_totals[domain] = []
            domain_totals[domain].append(normalized)

        # Calculate domain scores
        domain_scores = {
            domain: sum(scores) / len(scores)
            for domain, scores in domain_totals.items() if scores
        }

        # Calculate overall score
        overall = sum(cs.weighted_score for cs in component_scores)

        # Identify critical gaps
        critical_gaps = []
        for cs in component_scores:
            if cs.raw_score < 50:
                critical_gaps.extend(cs.gaps)

        # High priority recommendations
        sorted_components = sorted(component_scores, key=lambda x: x.raw_score)
        high_priority = []
        for cs in sorted_components[:5]:
            if cs.recommendations:
                high_priority.append(cs.recommendations[0])

        return SecurityPostureReport(
            entity_id=entity_id,
            overall_score=overall,
            overall_rating=self._get_rating(overall),
            grade=self._get_grade(overall),
            domain_scores=domain_scores,
            component_scores=component_scores,
            critical_gaps=critical_gaps[:10],
            high_priority_recommendations=high_priority,
            maturity_level=self._get_maturity(overall)
        )

    def _get_rating(self, score: float) -> str:
        for threshold, rating in sorted(self.RATING_THRESHOLDS.items(), reverse=True):
            if score >= threshold:
                return rating
        return "Critical"

    def _get_grade(self, score: float) -> str:
        for threshold, grade in sorted(self.GRADE_THRESHOLDS.items(), reverse=True):
            if score >= threshold:
                return grade
        return "F"

    def _get_maturity(self, score: float) -> str:
        for threshold, level in sorted(self.MATURITY_LEVELS.items(), reverse=True):
            if score >= threshold:
                return level
        return "Initial"

    def _identify_gaps(self, comp: ScoringComponent, score: float) -> List[str]:
        gaps = []
        if score < 50:
            gaps.append(f"Critical gap in {comp.name}")
        elif score < 70:
            gaps.append(f"{comp.name} needs improvement")
        return gaps

    def _generate_recommendations(self, comp: ScoringComponent, score: float) -> List[str]:
        recs = []
        if score < 50:
            recs.append(f"Immediately address {comp.name} - critical security risk")
        elif score < 70:
            recs.append(f"Prioritize improving {comp.name}")
        elif score < 85:
            recs.append(f"Continue enhancing {comp.name}")
        return recs


def create_security_posture_engine() -> SecurityScoringEngine:
    """Create a comprehensive security posture scoring engine."""
    components = [
        # Access Control
        ScoringComponent("mfa_coverage", "MFA Coverage", 10, SecurityDomain.ACCESS_CONTROL, "Percentage of users with MFA enabled"),
        ScoringComponent("privileged_access", "Privileged Access Management", 8, SecurityDomain.ACCESS_CONTROL, "PAM implementation maturity"),
        ScoringComponent("identity_governance", "Identity Governance", 7, SecurityDomain.ACCESS_CONTROL, "Identity lifecycle management"),

        # Data Protection
        ScoringComponent("data_encryption", "Data Encryption", 9, SecurityDomain.DATA_PROTECTION, "Encryption at rest and in transit"),
        ScoringComponent("dlp_coverage", "DLP Coverage", 7, SecurityDomain.DATA_PROTECTION, "Data loss prevention implementation"),
        ScoringComponent("backup_recovery", "Backup & Recovery", 8, SecurityDomain.DATA_PROTECTION, "Backup testing and recovery capabilities"),

        # Network Security
        ScoringComponent("firewall_config", "Firewall Configuration", 8, SecurityDomain.NETWORK_SECURITY, "Firewall rule optimization"),
        ScoringComponent("network_segmentation", "Network Segmentation", 7, SecurityDomain.NETWORK_SECURITY, "Network isolation"),
        ScoringComponent("intrusion_detection", "IDS/IPS", 6, SecurityDomain.NETWORK_SECURITY, "Intrusion detection/prevention"),

        # Endpoint Security
        ScoringComponent("edr_coverage", "EDR Coverage", 9, SecurityDomain.ENDPOINT_SECURITY, "Endpoint detection and response"),
        ScoringComponent("patch_compliance", "Patch Compliance", 8, SecurityDomain.ENDPOINT_SECURITY, "Patch management effectiveness"),
        ScoringComponent("device_hardening", "Device Hardening", 6, SecurityDomain.ENDPOINT_SECURITY, "Endpoint hardening standards"),

        # Incident Response
        ScoringComponent("ir_plan", "IR Plan Maturity", 7, SecurityDomain.INCIDENT_RESPONSE, "Incident response planning"),
        ScoringComponent("ir_testing", "IR Testing", 6, SecurityDomain.INCIDENT_RESPONSE, "Tabletop exercises and drills"),
        ScoringComponent("siem_soc", "SIEM/SOC", 8, SecurityDomain.INCIDENT_RESPONSE, "Security monitoring capabilities"),

        # Vulnerability Management
        ScoringComponent("vuln_scanning", "Vulnerability Scanning", 7, SecurityDomain.VULNERABILITY_MANAGEMENT, "Scanning coverage and frequency"),
        ScoringComponent("remediation_sla", "Remediation SLAs", 6, SecurityDomain.VULNERABILITY_MANAGEMENT, "Vulnerability fix times"),
        ScoringComponent("pen_testing", "Penetration Testing", 5, SecurityDomain.VULNERABILITY_MANAGEMENT, "Regular penetration testing"),

        # Security Awareness
        ScoringComponent("training_completion", "Training Completion", 6, SecurityDomain.SECURITY_AWARENESS, "Security awareness training"),
        ScoringComponent("phishing_resistance", "Phishing Resistance", 7, SecurityDomain.SECURITY_AWARENESS, "Phishing simulation results"),

        # Governance
        ScoringComponent("policy_coverage", "Policy Coverage", 6, SecurityDomain.GOVERNANCE, "Security policy completeness"),
        ScoringComponent("risk_assessments", "Risk Assessments", 7, SecurityDomain.GOVERNANCE, "Regular risk assessment process"),
        ScoringComponent("compliance_status", "Compliance Status", 8, SecurityDomain.GOVERNANCE, "Regulatory compliance status"),
    ]

    return SecurityScoringEngine(components)
