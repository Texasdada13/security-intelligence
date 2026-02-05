"""Security Incident Tracking and Management"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
from datetime import datetime, timedelta


class IncidentSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class IncidentStatus(Enum):
    NEW = "New"
    INVESTIGATING = "Investigating"
    CONTAINED = "Contained"
    ERADICATED = "Eradicated"
    RECOVERED = "Recovered"
    CLOSED = "Closed"


class IncidentCategory(Enum):
    MALWARE = "Malware Infection"
    DATA_BREACH = "Data Breach"
    PHISHING = "Phishing Attack"
    RANSOMWARE = "Ransomware"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"
    DDOS = "DDoS Attack"
    INSIDER_THREAT = "Insider Threat"
    POLICY_VIOLATION = "Policy Violation"
    OTHER = "Other"


@dataclass
class SecurityIncident:
    incident_id: str
    title: str
    category: IncidentCategory
    severity: IncidentSeverity
    status: IncidentStatus
    description: str
    affected_systems: List[str]
    detected_at: datetime
    contained_at: datetime = None
    resolved_at: datetime = None
    root_cause: str = ""
    impact_assessment: str = ""
    lessons_learned: str = ""
    assigned_to: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "description": self.description,
            "affected_systems": self.affected_systems,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "contained_at": self.contained_at.isoformat() if self.contained_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "root_cause": self.root_cause,
            "impact_assessment": self.impact_assessment,
            "assigned_to": self.assigned_to
        }

    @property
    def time_to_contain(self) -> Optional[float]:
        """Time to contain in hours."""
        if self.contained_at and self.detected_at:
            return (self.contained_at - self.detected_at).total_seconds() / 3600
        return None

    @property
    def time_to_resolve(self) -> Optional[float]:
        """Time to resolve in hours."""
        if self.resolved_at and self.detected_at:
            return (self.resolved_at - self.detected_at).total_seconds() / 3600
        return None


@dataclass
class IncidentMetrics:
    entity_id: str
    total_incidents: int
    open_incidents: int
    critical_open: int
    avg_time_to_contain: float  # hours
    avg_time_to_resolve: float  # hours
    incidents_by_category: Dict[str, int]
    incidents_by_severity: Dict[str, int]
    monthly_trend: List[int]
    top_affected_systems: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "total_incidents": self.total_incidents,
            "open_incidents": self.open_incidents,
            "critical_open": self.critical_open,
            "avg_time_to_contain": round(self.avg_time_to_contain, 1),
            "avg_time_to_resolve": round(self.avg_time_to_resolve, 1),
            "incidents_by_category": self.incidents_by_category,
            "incidents_by_severity": self.incidents_by_severity,
            "monthly_trend": self.monthly_trend,
            "top_affected_systems": self.top_affected_systems,
            "recommendations": self.recommendations
        }


class IncidentTracker:
    """Security incident tracking and metrics engine."""

    # SLA targets (hours)
    CONTAINMENT_SLA = {
        IncidentSeverity.CRITICAL: 4,
        IncidentSeverity.HIGH: 24,
        IncidentSeverity.MEDIUM: 72,
        IncidentSeverity.LOW: 168
    }

    RESOLUTION_SLA = {
        IncidentSeverity.CRITICAL: 24,
        IncidentSeverity.HIGH: 72,
        IncidentSeverity.MEDIUM: 168,
        IncidentSeverity.LOW: 336
    }

    def __init__(self):
        self.incidents: List[SecurityIncident] = []

    def add_incident(self, incident: SecurityIncident):
        """Add an incident to the tracker."""
        self.incidents.append(incident)

    def is_sla_breached(self, incident: SecurityIncident, sla_type: str = "containment") -> bool:
        """Check if incident has breached SLA."""
        sla_hours = (self.CONTAINMENT_SLA if sla_type == "containment"
                     else self.RESOLUTION_SLA).get(incident.severity, 72)

        if sla_type == "containment":
            if incident.contained_at:
                elapsed = (incident.contained_at - incident.detected_at).total_seconds() / 3600
            else:
                elapsed = (datetime.utcnow() - incident.detected_at).total_seconds() / 3600
        else:
            if incident.resolved_at:
                elapsed = (incident.resolved_at - incident.detected_at).total_seconds() / 3600
            else:
                elapsed = (datetime.utcnow() - incident.detected_at).total_seconds() / 3600

        return elapsed > sla_hours

    def generate_metrics(self, incidents: List[SecurityIncident] = None,
                        entity_id: str = "unknown") -> IncidentMetrics:
        """Generate comprehensive incident metrics."""
        incidents = incidents or self.incidents

        # Count open incidents
        open_incidents = [i for i in incidents if i.status not in
                         [IncidentStatus.CLOSED, IncidentStatus.RECOVERED]]
        critical_open = [i for i in open_incidents if i.severity == IncidentSeverity.CRITICAL]

        # Calculate average times
        contain_times = [i.time_to_contain for i in incidents if i.time_to_contain]
        resolve_times = [i.time_to_resolve for i in incidents if i.time_to_resolve]

        avg_contain = sum(contain_times) / len(contain_times) if contain_times else 0
        avg_resolve = sum(resolve_times) / len(resolve_times) if resolve_times else 0

        # Count by category
        by_category: Dict[str, int] = {}
        for i in incidents:
            key = i.category.value
            by_category[key] = by_category.get(key, 0) + 1

        # Count by severity
        by_severity: Dict[str, int] = {}
        for i in incidents:
            key = i.severity.value
            by_severity[key] = by_severity.get(key, 0) + 1

        # Monthly trend (last 6 months - mock data)
        monthly_trend = [5, 7, 4, 8, 6, len(incidents) // 6]

        # Top affected systems
        system_counts: Dict[str, int] = {}
        for i in incidents:
            for system in i.affected_systems:
                system_counts[system] = system_counts.get(system, 0) + 1
        top_systems = sorted(system_counts.keys(), key=lambda x: system_counts[x], reverse=True)[:5]

        # Generate recommendations
        recommendations = self._generate_recommendations(incidents, by_category, avg_contain)

        return IncidentMetrics(
            entity_id=entity_id,
            total_incidents=len(incidents),
            open_incidents=len(open_incidents),
            critical_open=len(critical_open),
            avg_time_to_contain=avg_contain,
            avg_time_to_resolve=avg_resolve,
            incidents_by_category=by_category,
            incidents_by_severity=by_severity,
            monthly_trend=monthly_trend,
            top_affected_systems=top_systems,
            recommendations=recommendations
        )

    def _generate_recommendations(self, incidents: List[SecurityIncident],
                                  by_category: Dict[str, int],
                                  avg_contain: float) -> List[str]:
        """Generate incident response recommendations."""
        recs = []

        # Check for recurring categories
        if by_category.get("Phishing Attack", 0) > 3:
            recs.append("High phishing activity - enhance email security and user training")

        if by_category.get("Malware Infection", 0) > 2:
            recs.append("Review endpoint protection and detection capabilities")

        if by_category.get("Unauthorized Access", 0) > 0:
            recs.append("Strengthen access controls and implement MFA")

        # Check response times
        if avg_contain > 24:
            recs.append("Improve incident detection and response times")

        # Check for critical incidents
        critical = [i for i in incidents if i.severity == IncidentSeverity.CRITICAL]
        if critical:
            recs.append("Conduct post-incident review for all critical incidents")

        return recs[:5]
