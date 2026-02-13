"""Security Intelligence - Database Models"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()


def generate_uuid():
    return str(uuid.uuid4())


class Organization(db.Model):
    __tablename__ = 'organizations'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    name = db.Column(db.String(200), nullable=False)
    industry = db.Column(db.String(100))
    size = db.Column(db.String(50))
    compliance_frameworks = db.Column(db.JSON)  # List of applicable frameworks
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    assets = db.relationship('Asset', backref='organization', lazy=True)
    vulnerabilities = db.relationship('Vulnerability', backref='organization', lazy=True)
    incidents = db.relationship('Incident', backref='organization', lazy=True)
    compliance_assessments = db.relationship('ComplianceAssessment', backref='organization', lazy=True)
    risk_assessments = db.relationship('RiskAssessment', backref='organization', lazy=True)
    chat_sessions = db.relationship('ChatSession', backref='organization', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'industry': self.industry,
            'size': self.size,
            'compliance_frameworks': self.compliance_frameworks,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    asset_type = db.Column(db.String(50))  # Server, Workstation, Network Device, Application, Data
    criticality = db.Column(db.String(20))  # Critical, High, Medium, Low
    ip_address = db.Column(db.String(50))
    hostname = db.Column(db.String(200))
    owner = db.Column(db.String(100))
    location = db.Column(db.String(100))
    status = db.Column(db.String(20), default='active')
    last_scanned = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'asset_type': self.asset_type,
            'criticality': self.criticality,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'status': self.status,
            'last_scanned': self.last_scanned.isoformat() if self.last_scanned else None
        }


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    asset_id = db.Column(db.String(36), db.ForeignKey('assets.id'))
    title = db.Column(db.String(300), nullable=False)
    cve_id = db.Column(db.String(20))
    severity = db.Column(db.String(20))  # Critical, High, Medium, Low
    cvss_score = db.Column(db.Float)
    status = db.Column(db.String(30), default='Open')  # Open, In Progress, Remediated, Accepted
    description = db.Column(db.Text)
    remediation_notes = db.Column(db.Text)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime)
    remediated_at = db.Column(db.DateTime)

    asset = db.relationship('Asset', backref='vulnerabilities')

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'cve_id': self.cve_id,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'status': self.status,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None,
            'due_date': self.due_date.isoformat() if self.due_date else None
        }


class Incident(db.Model):
    __tablename__ = 'incidents'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    title = db.Column(db.String(300), nullable=False)
    category = db.Column(db.String(50))  # Malware, Data Breach, Phishing, etc.
    severity = db.Column(db.String(20))  # Critical, High, Medium, Low
    status = db.Column(db.String(30), default='New')  # New, Investigating, Contained, Resolved, Closed
    description = db.Column(db.Text)
    affected_systems = db.Column(db.JSON)  # List of affected system names
    root_cause = db.Column(db.Text)
    impact_assessment = db.Column(db.Text)
    lessons_learned = db.Column(db.Text)
    assigned_to = db.Column(db.String(100))
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    contained_at = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'category': self.category,
            'severity': self.severity,
            'status': self.status,
            'affected_systems': self.affected_systems,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'assigned_to': self.assigned_to
        }


class ComplianceAssessment(db.Model):
    __tablename__ = 'compliance_assessments'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    framework = db.Column(db.String(50))  # SOC2, HIPAA, PCI-DSS, etc.
    overall_score = db.Column(db.Float)
    overall_status = db.Column(db.String(30))
    controls_total = db.Column(db.Integer)
    controls_implemented = db.Column(db.Integer)
    controls_partial = db.Column(db.Integer)
    controls_missing = db.Column(db.Integer)
    category_scores = db.Column(db.JSON)
    critical_gaps = db.Column(db.JSON)
    remediation_roadmap = db.Column(db.JSON)
    audit_readiness = db.Column(db.String(30))
    assessed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'framework': self.framework,
            'overall_score': self.overall_score,
            'overall_status': self.overall_status,
            'controls_total': self.controls_total,
            'controls_implemented': self.controls_implemented,
            'audit_readiness': self.audit_readiness,
            'assessed_at': self.assessed_at.isoformat() if self.assessed_at else None
        }


class RiskAssessment(db.Model):
    __tablename__ = 'risk_assessments'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    overall_risk_score = db.Column(db.Float)
    overall_risk_level = db.Column(db.String(20))
    total_risks = db.Column(db.Integer)
    critical_count = db.Column(db.Integer)
    high_count = db.Column(db.Integer)
    medium_count = db.Column(db.Integer)
    low_count = db.Column(db.Integer)
    top_risks = db.Column(db.JSON)
    priority_actions = db.Column(db.JSON)
    risk_trend = db.Column(db.String(20))
    assessed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'overall_risk_score': self.overall_risk_score,
            'overall_risk_level': self.overall_risk_level,
            'total_risks': self.total_risks,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'risk_trend': self.risk_trend,
            'assessed_at': self.assessed_at.isoformat() if self.assessed_at else None
        }


class ChatSession(db.Model):
    __tablename__ = 'chat_sessions'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=True)
    mode = db.Column(db.String(50), default='general')
    title = db.Column(db.String(200))
    context = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Enhanced chat fields
    discussed_topics = db.Column(db.JSON, default=list)
    dismissed_suggestions = db.Column(db.JSON, default=list)
    conversation_summary = db.Column(db.Text)
    summary_updated_at = db.Column(db.DateTime)
    topic_tags = db.Column(db.JSON, default=list)
    key_insights = db.Column(db.JSON, default=list)

    messages = db.relationship('ChatMessage', backref='session', lazy=True,
                               order_by='ChatMessage.created_at')
    uploaded_files = db.relationship('UploadedFile', backref='session', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'mode': self.mode,
            'title': self.title,
            'discussed_topics': self.discussed_topics or [],
            'topic_tags': self.topic_tags or [],
            'has_summary': self.conversation_summary is not None,
            'file_count': len(self.uploaded_files) if self.uploaded_files else 0,
            'message_count': len(self.messages) if self.messages else 0,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    session_id = db.Column(db.String(36), db.ForeignKey('chat_sessions.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'role': self.role,
            'content': self.content,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class UploadedFile(db.Model):
    """Uploaded files for chat analysis."""
    __tablename__ = 'uploaded_files'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    session_id = db.Column(db.String(36), db.ForeignKey('chat_sessions.id'), nullable=False)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=True)

    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    file_size = db.Column(db.Integer)

    analysis_result = db.Column(db.JSON)
    context_summary = db.Column(db.Text)
    row_count = db.Column(db.Integer)
    column_count = db.Column(db.Integer)
    detected_metrics = db.Column(db.JSON)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'filename': self.filename,
            'file_type': self.file_type,
            'file_size': self.file_size,
            'row_count': self.row_count,
            'column_count': self.column_count,
            'detected_metrics': self.detected_metrics,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ISOAssessment(db.Model):
    __tablename__ = 'iso_assessments'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=True)
    framework = db.Column(db.String(50))
    overall_score = db.Column(db.Float)
    grade = db.Column(db.String(5))
    controls_compliant = db.Column(db.Integer)
    controls_partial = db.Column(db.Integer)
    controls_gap = db.Column(db.Integer)
    total_controls = db.Column(db.Integer)
    clause_scores = db.Column(db.JSON)
    gap_analysis = db.Column(db.JSON)
    certification_readiness = db.Column(db.JSON)
    synergies = db.Column(db.JSON)
    assessed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'framework': self.framework,
            'overall_score': self.overall_score, 'grade': self.grade,
            'controls_compliant': self.controls_compliant,
            'controls_partial': self.controls_partial,
            'controls_gap': self.controls_gap,
            'assessed_at': self.assessed_at.isoformat() if self.assessed_at else None
        }


class PentestEngagement(db.Model):
    __tablename__ = 'pentest_engagements'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=True)
    engagement_name = db.Column(db.String(200))
    pentest_type = db.Column(db.String(50))
    status = db.Column(db.String(30), default='planned')
    overall_score = db.Column(db.Float)
    grade = db.Column(db.String(5))
    findings_count = db.Column(db.Integer)
    critical_count = db.Column(db.Integer)
    high_count = db.Column(db.Integer)
    medium_count = db.Column(db.Integer)
    low_count = db.Column(db.Integer)
    findings_detail = db.Column(db.JSON)
    owasp_coverage = db.Column(db.JSON)
    remediation_progress = db.Column(db.JSON)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'engagement_name': self.engagement_name,
            'pentest_type': self.pentest_type, 'status': self.status,
            'overall_score': self.overall_score, 'grade': self.grade,
            'findings_count': self.findings_count,
            'critical_count': self.critical_count,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class CodeReviewAssessment(db.Model):
    __tablename__ = 'code_review_assessments'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=True)
    project_name = db.Column(db.String(200))
    languages = db.Column(db.JSON)
    overall_score = db.Column(db.Float)
    grade = db.Column(db.String(5))
    files_reviewed = db.Column(db.Integer)
    total_findings = db.Column(db.Integer)
    critical_count = db.Column(db.Integer)
    high_count = db.Column(db.Integer)
    medium_count = db.Column(db.Integer)
    low_count = db.Column(db.Integer)
    findings_by_category = db.Column(db.JSON)
    guardrails_status = db.Column(db.JSON)
    assessed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'project_name': self.project_name,
            'languages': self.languages,
            'overall_score': self.overall_score, 'grade': self.grade,
            'files_reviewed': self.files_reviewed,
            'total_findings': self.total_findings,
            'assessed_at': self.assessed_at.isoformat() if self.assessed_at else None
        }


class NetworkAssessment(db.Model):
    __tablename__ = 'network_assessments'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=True)
    assessment_type = db.Column(db.String(50))
    overall_score = db.Column(db.Float)
    grade = db.Column(db.String(5))
    external_ips = db.Column(db.Integer)
    open_ports = db.Column(db.Integer)
    ssl_tls_issues = db.Column(db.Integer)
    findings_count = db.Column(db.Integer)
    critical_count = db.Column(db.Integer)
    high_count = db.Column(db.Integer)
    hardening_scores = db.Column(db.JSON)
    segmentation_review = db.Column(db.JSON)
    findings_detail = db.Column(db.JSON)
    assessed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'assessment_type': self.assessment_type,
            'overall_score': self.overall_score, 'grade': self.grade,
            'external_ips': self.external_ips, 'open_ports': self.open_ports,
            'findings_count': self.findings_count,
            'assessed_at': self.assessed_at.isoformat() if self.assessed_at else None
        }


class DevSecOpsAssessment(db.Model):
    __tablename__ = 'devsecops_assessments'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=True)
    overall_score = db.Column(db.Float)
    grade = db.Column(db.String(5))
    maturity_level = db.Column(db.Integer)
    pipeline_scans = db.Column(db.JSON)
    security_gates = db.Column(db.JSON)
    sdlc_maturity = db.Column(db.JSON)
    tool_coverage = db.Column(db.JSON)
    recommendations = db.Column(db.JSON)
    assessed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'overall_score': self.overall_score, 'grade': self.grade,
            'maturity_level': self.maturity_level,
            'assessed_at': self.assessed_at.isoformat() if self.assessed_at else None
        }


class AuditReadinessAssessment(db.Model):
    __tablename__ = 'audit_readiness_assessments'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=True)
    framework = db.Column(db.String(50))
    readiness_score = db.Column(db.Float)
    grade = db.Column(db.String(5))
    controls_covered = db.Column(db.Integer)
    controls_partial = db.Column(db.Integer)
    controls_no_evidence = db.Column(db.Integer)
    total_controls = db.Column(db.Integer)
    evidence_freshness_pct = db.Column(db.Float)
    automated_collection_pct = db.Column(db.Float)
    evidence_summary = db.Column(db.JSON)
    audit_export = db.Column(db.JSON)
    recommendations = db.Column(db.JSON)
    assessed_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'framework': self.framework,
            'readiness_score': self.readiness_score, 'grade': self.grade,
            'controls_covered': self.controls_covered,
            'evidence_freshness_pct': self.evidence_freshness_pct,
            'assessed_at': self.assessed_at.isoformat() if self.assessed_at else None
        }
