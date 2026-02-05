"""Compliance Assessment Engine"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class ComplianceFramework(Enum):
    SOC2 = "SOC 2"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI-DSS"
    ISO_27001 = "ISO 27001"
    NIST_CSF = "NIST CSF"
    GDPR = "GDPR"
    CCPA = "CCPA"
    CIS = "CIS Controls"


class ControlStatus(Enum):
    IMPLEMENTED = "Implemented"
    PARTIAL = "Partially Implemented"
    PLANNED = "Planned"
    NOT_IMPLEMENTED = "Not Implemented"
    NOT_APPLICABLE = "Not Applicable"


@dataclass
class ControlRequirement:
    control_id: str
    name: str
    description: str
    framework: ComplianceFramework
    category: str
    criticality: str = "Medium"  # Critical, High, Medium, Low


@dataclass
class ControlAssessment:
    control_id: str
    control_name: str
    framework: str
    category: str
    status: ControlStatus
    score: float  # 0-100
    evidence: List[str]
    gaps: List[str]
    remediation_steps: List[str]
    due_date: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "framework": self.framework,
            "category": self.category,
            "status": self.status.value,
            "score": round(self.score, 1),
            "evidence": self.evidence,
            "gaps": self.gaps,
            "remediation_steps": self.remediation_steps,
            "due_date": self.due_date
        }


@dataclass
class ComplianceReport:
    entity_id: str
    framework: str
    overall_score: float
    overall_status: str
    controls_total: int
    controls_implemented: int
    controls_partial: int
    controls_missing: int
    category_scores: Dict[str, float]
    control_assessments: List[ControlAssessment]
    critical_gaps: List[str]
    remediation_roadmap: List[str]
    audit_readiness: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "framework": self.framework,
            "overall_score": round(self.overall_score, 1),
            "overall_status": self.overall_status,
            "controls_total": self.controls_total,
            "controls_implemented": self.controls_implemented,
            "controls_partial": self.controls_partial,
            "controls_missing": self.controls_missing,
            "category_scores": {k: round(v, 1) for k, v in self.category_scores.items()},
            "critical_gaps": self.critical_gaps,
            "remediation_roadmap": self.remediation_roadmap,
            "audit_readiness": self.audit_readiness
        }


class ComplianceEngine:
    """Compliance assessment and gap analysis engine."""

    STATUS_SCORES = {
        ControlStatus.IMPLEMENTED: 100,
        ControlStatus.PARTIAL: 50,
        ControlStatus.PLANNED: 20,
        ControlStatus.NOT_IMPLEMENTED: 0,
        ControlStatus.NOT_APPLICABLE: 100
    }

    READINESS_THRESHOLDS = {
        90: "Audit Ready",
        75: "Nearly Ready",
        60: "Significant Work Needed",
        40: "Major Gaps",
        0: "Not Ready"
    }

    def __init__(self, framework: ComplianceFramework, controls: List[ControlRequirement]):
        self.framework = framework
        self.controls = {c.control_id: c for c in controls}

    def assess_compliance(self, control_statuses: Dict[str, Dict[str, Any]],
                         entity_id: str = "unknown") -> ComplianceReport:
        """Assess compliance against framework controls."""
        assessments = []
        category_totals: Dict[str, List[float]] = {}

        for control_id, control in self.controls.items():
            status_data = control_statuses.get(control_id, {})

            status = ControlStatus(status_data.get("status", ControlStatus.NOT_IMPLEMENTED.value))
            score = self.STATUS_SCORES.get(status, 0)
            evidence = status_data.get("evidence", [])
            gaps = self._identify_gaps(control, status)
            remediation = self._generate_remediation(control, status)

            assessment = ControlAssessment(
                control_id=control_id,
                control_name=control.name,
                framework=self.framework.value,
                category=control.category,
                status=status,
                score=score,
                evidence=evidence,
                gaps=gaps,
                remediation_steps=remediation,
                due_date=status_data.get("due_date", "")
            )
            assessments.append(assessment)

            if control.category not in category_totals:
                category_totals[control.category] = []
            category_totals[control.category].append(score)

        # Calculate metrics
        category_scores = {
            cat: sum(scores) / len(scores)
            for cat, scores in category_totals.items() if scores
        }

        overall_score = sum(a.score for a in assessments) / len(assessments) if assessments else 0

        implemented = sum(1 for a in assessments if a.status == ControlStatus.IMPLEMENTED)
        partial = sum(1 for a in assessments if a.status == ControlStatus.PARTIAL)
        missing = sum(1 for a in assessments if a.status in [ControlStatus.NOT_IMPLEMENTED, ControlStatus.PLANNED])

        # Critical gaps
        critical_gaps = []
        for a in assessments:
            ctrl = self.controls.get(a.control_id)
            if ctrl and ctrl.criticality == "Critical" and a.status != ControlStatus.IMPLEMENTED:
                critical_gaps.extend(a.gaps)

        # Remediation roadmap
        sorted_assessments = sorted(assessments, key=lambda x: (
            0 if self.controls[x.control_id].criticality == "Critical" else 1,
            x.score
        ))
        roadmap = []
        for a in sorted_assessments[:10]:
            if a.remediation_steps:
                roadmap.append(f"{a.control_name}: {a.remediation_steps[0]}")

        # Audit readiness
        readiness = self._determine_readiness(overall_score)

        # Overall status
        if overall_score >= 90:
            status = "Compliant"
        elif overall_score >= 70:
            status = "Substantially Compliant"
        elif overall_score >= 50:
            status = "Partially Compliant"
        else:
            status = "Non-Compliant"

        return ComplianceReport(
            entity_id=entity_id,
            framework=self.framework.value,
            overall_score=overall_score,
            overall_status=status,
            controls_total=len(assessments),
            controls_implemented=implemented,
            controls_partial=partial,
            controls_missing=missing,
            category_scores=category_scores,
            control_assessments=assessments,
            critical_gaps=critical_gaps[:10],
            remediation_roadmap=roadmap,
            audit_readiness=readiness
        )

    def _identify_gaps(self, control: ControlRequirement, status: ControlStatus) -> List[str]:
        """Identify gaps for a control."""
        gaps = []
        if status == ControlStatus.NOT_IMPLEMENTED:
            gaps.append(f"{control.name} is not implemented")
        elif status == ControlStatus.PARTIAL:
            gaps.append(f"{control.name} is only partially implemented")
        elif status == ControlStatus.PLANNED:
            gaps.append(f"{control.name} is planned but not yet implemented")
        return gaps

    def _generate_remediation(self, control: ControlRequirement, status: ControlStatus) -> List[str]:
        """Generate remediation steps for a control."""
        steps = []
        if status in [ControlStatus.NOT_IMPLEMENTED, ControlStatus.PLANNED]:
            steps.append(f"Implement {control.name}")
            steps.append(f"Document evidence of implementation")
            steps.append(f"Conduct testing to verify effectiveness")
        elif status == ControlStatus.PARTIAL:
            steps.append(f"Complete implementation of {control.name}")
            steps.append(f"Address identified gaps")
        return steps

    def _determine_readiness(self, score: float) -> str:
        """Determine audit readiness based on score."""
        for threshold, readiness in sorted(self.READINESS_THRESHOLDS.items(), reverse=True):
            if score >= threshold:
                return readiness
        return "Not Ready"


def create_compliance_engine(framework: ComplianceFramework) -> ComplianceEngine:
    """Create a compliance engine for a specific framework."""
    controls = []

    if framework == ComplianceFramework.SOC2:
        controls = [
            ControlRequirement("CC1.1", "COSO Principles", "Control environment", framework, "Common Criteria", "Critical"),
            ControlRequirement("CC2.1", "Information Communication", "Internal communications", framework, "Common Criteria", "High"),
            ControlRequirement("CC3.1", "Risk Assessment", "Risk identification", framework, "Common Criteria", "Critical"),
            ControlRequirement("CC4.1", "Monitoring Activities", "Ongoing monitoring", framework, "Common Criteria", "High"),
            ControlRequirement("CC5.1", "Control Activities", "Control selection", framework, "Common Criteria", "Critical"),
            ControlRequirement("CC6.1", "Logical Access", "Access controls", framework, "Security", "Critical"),
            ControlRequirement("CC6.6", "Endpoint Security", "Workstation controls", framework, "Security", "High"),
            ControlRequirement("CC7.1", "System Operations", "Operational procedures", framework, "Availability", "Medium"),
            ControlRequirement("CC7.2", "Change Management", "Change processes", framework, "Availability", "High"),
            ControlRequirement("CC8.1", "Incident Response", "Incident handling", framework, "Security", "Critical"),
            ControlRequirement("CC9.1", "Risk Mitigation", "Vendor management", framework, "Security", "High"),
        ]
    elif framework == ComplianceFramework.HIPAA:
        controls = [
            ControlRequirement("164.308(a)(1)", "Security Management", "Risk analysis", framework, "Administrative", "Critical"),
            ControlRequirement("164.308(a)(3)", "Workforce Security", "Authorization procedures", framework, "Administrative", "High"),
            ControlRequirement("164.308(a)(4)", "Information Access", "Access authorization", framework, "Administrative", "Critical"),
            ControlRequirement("164.308(a)(5)", "Security Awareness", "Training program", framework, "Administrative", "Medium"),
            ControlRequirement("164.308(a)(6)", "Security Incidents", "Incident procedures", framework, "Administrative", "High"),
            ControlRequirement("164.310(a)", "Facility Access", "Physical safeguards", framework, "Physical", "High"),
            ControlRequirement("164.310(d)", "Device Controls", "Hardware disposal", framework, "Physical", "Medium"),
            ControlRequirement("164.312(a)", "Access Control", "Unique user ID", framework, "Technical", "Critical"),
            ControlRequirement("164.312(b)", "Audit Controls", "Activity logging", framework, "Technical", "High"),
            ControlRequirement("164.312(c)", "Integrity Controls", "Data integrity", framework, "Technical", "Critical"),
            ControlRequirement("164.312(e)", "Transmission Security", "Encryption", framework, "Technical", "Critical"),
        ]
    elif framework == ComplianceFramework.NIST_CSF:
        controls = [
            ControlRequirement("ID.AM", "Asset Management", "Asset inventory", framework, "Identify", "High"),
            ControlRequirement("ID.RA", "Risk Assessment", "Risk identification", framework, "Identify", "Critical"),
            ControlRequirement("PR.AC", "Access Control", "Identity management", framework, "Protect", "Critical"),
            ControlRequirement("PR.DS", "Data Security", "Data protection", framework, "Protect", "Critical"),
            ControlRequirement("PR.IP", "Protective Processes", "Security policies", framework, "Protect", "High"),
            ControlRequirement("PR.AT", "Awareness Training", "Security training", framework, "Protect", "Medium"),
            ControlRequirement("DE.AE", "Anomaly Detection", "Security monitoring", framework, "Detect", "High"),
            ControlRequirement("DE.CM", "Continuous Monitoring", "Ongoing monitoring", framework, "Detect", "High"),
            ControlRequirement("RS.RP", "Response Planning", "Incident response", framework, "Respond", "Critical"),
            ControlRequirement("RS.CO", "Response Communications", "Incident reporting", framework, "Respond", "High"),
            ControlRequirement("RC.RP", "Recovery Planning", "Recovery procedures", framework, "Recover", "High"),
        ]
    else:
        # Default CIS Controls
        controls = [
            ControlRequirement("CIS1", "Hardware Inventory", "Asset inventory", framework, "Basic", "Critical"),
            ControlRequirement("CIS2", "Software Inventory", "Software tracking", framework, "Basic", "Critical"),
            ControlRequirement("CIS3", "Data Protection", "Data classification", framework, "Basic", "Critical"),
            ControlRequirement("CIS4", "Secure Configuration", "Hardening standards", framework, "Basic", "High"),
            ControlRequirement("CIS5", "Account Management", "Access control", framework, "Basic", "Critical"),
            ControlRequirement("CIS6", "Access Control Management", "Permissions", framework, "Basic", "High"),
            ControlRequirement("CIS7", "Vulnerability Management", "Patching", framework, "Foundational", "High"),
            ControlRequirement("CIS8", "Audit Log Management", "Logging", framework, "Foundational", "High"),
            ControlRequirement("CIS9", "Email/Browser Protection", "Endpoint protection", framework, "Foundational", "Medium"),
            ControlRequirement("CIS10", "Malware Defenses", "Anti-malware", framework, "Foundational", "High"),
        ]

    return ComplianceEngine(framework, controls)
