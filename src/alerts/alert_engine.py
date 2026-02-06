"""Alert engine for Security Intelligence - monitors security metrics and generates alerts."""
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertCategory(Enum):
    VULNERABILITY = "vulnerability"
    INCIDENT = "incident"
    COMPLIANCE = "compliance"
    POSTURE = "posture"
    THREAT = "threat"


@dataclass
class Alert:
    """Represents a security alert."""
    id: str
    severity: AlertSeverity
    category: AlertCategory
    title: str
    message: str
    metric_name: str
    current_value: Any
    threshold_value: Any
    recommendation: str
    created_at: datetime

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'severity': self.severity.value,
            'category': self.category.value,
            'title': self.title,
            'message': self.message,
            'metric_name': self.metric_name,
            'current_value': self.current_value,
            'threshold_value': self.threshold_value,
            'recommendation': self.recommendation,
            'created_at': self.created_at.isoformat()
        }


class AlertEngine:
    """Engine for generating security alerts based on thresholds."""

    # Default thresholds
    THRESHOLDS = {
        'critical_vulns_max': 0,       # Any critical vulns trigger alert
        'high_vulns_max': 5,           # More than 5 high vulns
        'posture_score_critical': 50,  # Below 50 is critical
        'posture_score_warning': 70,   # Below 70 needs attention
        'compliance_critical': 60,      # Below 60% is critical
        'compliance_warning': 80,       # Below 80% needs attention
        'open_incidents_max': 3,        # More than 3 open incidents
        'mttr_warning_hours': 24,       # MTTR over 24 hours
        'mttr_critical_hours': 72,      # MTTR over 72 hours
    }

    def __init__(self, custom_thresholds: Optional[Dict] = None):
        self.thresholds = {**self.THRESHOLDS}
        if custom_thresholds:
            self.thresholds.update(custom_thresholds)
        self._alert_counter = 0

    def _generate_id(self) -> str:
        self._alert_counter += 1
        return f"sec-alert-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self._alert_counter}"

    def check_metrics(self, data: Dict[str, Any]) -> List[Alert]:
        """Check all metrics and generate alerts."""
        alerts = []

        metrics = data.get('metrics', {})
        vulns = data.get('vulnerabilities_by_severity', {})
        incidents = data.get('incidents_by_status', {})
        compliance = data.get('compliance', [])

        # Check critical vulnerabilities
        critical_vulns = vulns.get('critical', 0)
        if critical_vulns > self.thresholds['critical_vulns_max']:
            alerts.append(Alert(
                id=self._generate_id(),
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.VULNERABILITY,
                title=f"Critical: {critical_vulns} Critical Vulnerabilities Detected",
                message=f"You have {critical_vulns} critical vulnerabilities that require immediate attention.",
                metric_name="Critical Vulnerabilities",
                current_value=critical_vulns,
                threshold_value=self.thresholds['critical_vulns_max'],
                recommendation="Immediately prioritize patching critical vulnerabilities. Consider emergency change window if needed.",
                created_at=datetime.now()
            ))

        # Check high vulnerabilities
        high_vulns = vulns.get('high', 0)
        if high_vulns > self.thresholds['high_vulns_max']:
            alerts.append(Alert(
                id=self._generate_id(),
                severity=AlertSeverity.WARNING,
                category=AlertCategory.VULNERABILITY,
                title=f"Warning: {high_vulns} High Severity Vulnerabilities",
                message=f"You have {high_vulns} high-severity vulnerabilities exceeding the threshold of {self.thresholds['high_vulns_max']}.",
                metric_name="High Vulnerabilities",
                current_value=high_vulns,
                threshold_value=self.thresholds['high_vulns_max'],
                recommendation="Schedule patching for high-severity vulnerabilities within the next sprint cycle.",
                created_at=datetime.now()
            ))

        # Check security posture score
        posture = metrics.get('posture_score', 100)
        if posture < self.thresholds['posture_score_critical']:
            alerts.append(Alert(
                id=self._generate_id(),
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.POSTURE,
                title="Critical: Security Posture Below Safe Threshold",
                message=f"Your security posture score is {posture}, well below the critical threshold of {self.thresholds['posture_score_critical']}.",
                metric_name="Security Posture",
                current_value=posture,
                threshold_value=self.thresholds['posture_score_critical'],
                recommendation="Conduct an emergency security review. Address critical and high vulnerabilities immediately.",
                created_at=datetime.now()
            ))
        elif posture < self.thresholds['posture_score_warning']:
            alerts.append(Alert(
                id=self._generate_id(),
                severity=AlertSeverity.WARNING,
                category=AlertCategory.POSTURE,
                title="Warning: Security Posture Needs Improvement",
                message=f"Your security posture score is {posture}, below the target of {self.thresholds['posture_score_warning']}.",
                metric_name="Security Posture",
                current_value=posture,
                threshold_value=self.thresholds['posture_score_warning'],
                recommendation="Review and remediate open vulnerabilities. Update security controls and policies.",
                created_at=datetime.now()
            ))

        # Check compliance frameworks
        for framework in compliance:
            name = framework.get('framework', 'Unknown')
            score = framework.get('score', 100)

            if score < self.thresholds['compliance_critical']:
                alerts.append(Alert(
                    id=self._generate_id(),
                    severity=AlertSeverity.CRITICAL,
                    category=AlertCategory.COMPLIANCE,
                    title=f"Critical: {name} Compliance Below Threshold",
                    message=f"{name} compliance is at {score}%, which may result in audit failures or regulatory penalties.",
                    metric_name=f"{name} Compliance",
                    current_value=score,
                    threshold_value=self.thresholds['compliance_critical'],
                    recommendation=f"Immediately address {name} control gaps. Consider engaging compliance specialists.",
                    created_at=datetime.now()
                ))
            elif score < self.thresholds['compliance_warning']:
                alerts.append(Alert(
                    id=self._generate_id(),
                    severity=AlertSeverity.WARNING,
                    category=AlertCategory.COMPLIANCE,
                    title=f"Warning: {name} Compliance Needs Attention",
                    message=f"{name} compliance is at {score}%, below the target of {self.thresholds['compliance_warning']}%.",
                    metric_name=f"{name} Compliance",
                    current_value=score,
                    threshold_value=self.thresholds['compliance_warning'],
                    recommendation=f"Review {name} requirements and create a remediation plan for control gaps.",
                    created_at=datetime.now()
                ))

        # Check open incidents
        open_incidents = incidents.get('open', 0) + incidents.get('investigating', 0)
        if open_incidents > self.thresholds['open_incidents_max']:
            alerts.append(Alert(
                id=self._generate_id(),
                severity=AlertSeverity.WARNING,
                category=AlertCategory.INCIDENT,
                title=f"Warning: {open_incidents} Open Security Incidents",
                message=f"You have {open_incidents} unresolved security incidents, exceeding the threshold of {self.thresholds['open_incidents_max']}.",
                metric_name="Open Incidents",
                current_value=open_incidents,
                threshold_value=self.thresholds['open_incidents_max'],
                recommendation="Review incident queue and prioritize by impact. Consider adding resources to the incident response team.",
                created_at=datetime.now()
            ))

        # Check MTTR
        mttr = metrics.get('mttr_hours', 0)
        if mttr > self.thresholds['mttr_critical_hours']:
            alerts.append(Alert(
                id=self._generate_id(),
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.INCIDENT,
                title="Critical: Mean Time to Remediate Too High",
                message=f"MTTR is {mttr:.1f} hours, significantly exceeding the {self.thresholds['mttr_critical_hours']}-hour target.",
                metric_name="MTTR",
                current_value=mttr,
                threshold_value=self.thresholds['mttr_critical_hours'],
                recommendation="Review incident response processes. Implement automation and playbooks to accelerate remediation.",
                created_at=datetime.now()
            ))
        elif mttr > self.thresholds['mttr_warning_hours']:
            alerts.append(Alert(
                id=self._generate_id(),
                severity=AlertSeverity.WARNING,
                category=AlertCategory.INCIDENT,
                title="Warning: MTTR Above Target",
                message=f"MTTR is {mttr:.1f} hours, exceeding the {self.thresholds['mttr_warning_hours']}-hour target.",
                metric_name="MTTR",
                current_value=mttr,
                threshold_value=self.thresholds['mttr_warning_hours'],
                recommendation="Identify bottlenecks in incident response workflow. Consider additional training or tools.",
                created_at=datetime.now()
            ))

        # Sort by severity (critical first)
        severity_order = {AlertSeverity.CRITICAL: 0, AlertSeverity.WARNING: 1, AlertSeverity.INFO: 2}
        alerts.sort(key=lambda a: severity_order[a.severity])

        return alerts

    def get_alert_summary(self, alerts: List[Alert]) -> Dict:
        """Get a summary of alerts by severity."""
        summary = {
            'total': len(alerts),
            'critical': sum(1 for a in alerts if a.severity == AlertSeverity.CRITICAL),
            'warning': sum(1 for a in alerts if a.severity == AlertSeverity.WARNING),
            'info': sum(1 for a in alerts if a.severity == AlertSeverity.INFO),
            'categories': {}
        }

        for alert in alerts:
            cat = alert.category.value
            if cat not in summary['categories']:
                summary['categories'][cat] = 0
            summary['categories'][cat] += 1

        return summary


def create_alert_engine(custom_thresholds: Optional[Dict] = None) -> AlertEngine:
    """Factory function to create an alert engine."""
    return AlertEngine(custom_thresholds)
