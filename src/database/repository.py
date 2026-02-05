"""Security Intelligence - Repository Pattern for Data Access"""
from typing import List, Optional, Dict, Any
from datetime import datetime
from .models import db, Organization, Asset, Vulnerability, Incident, ComplianceAssessment, RiskAssessment, ChatSession, ChatMessage


class OrganizationRepository:
    @staticmethod
    def create(name: str, **kwargs) -> Organization:
        org = Organization(name=name, **kwargs)
        db.session.add(org)
        db.session.commit()
        return org

    @staticmethod
    def get_by_id(org_id: str) -> Optional[Organization]:
        return Organization.query.get(org_id)

    @staticmethod
    def get_all() -> List[Organization]:
        return Organization.query.order_by(Organization.name).all()

    @staticmethod
    def update(org_id: str, **kwargs) -> Optional[Organization]:
        org = Organization.query.get(org_id)
        if org:
            for key, value in kwargs.items():
                if hasattr(org, key):
                    setattr(org, key, value)
            db.session.commit()
        return org

    @staticmethod
    def delete(org_id: str) -> bool:
        org = Organization.query.get(org_id)
        if org:
            db.session.delete(org)
            db.session.commit()
            return True
        return False


class AssetRepository:
    @staticmethod
    def create(organization_id: str, name: str, **kwargs) -> Asset:
        asset = Asset(organization_id=organization_id, name=name, **kwargs)
        db.session.add(asset)
        db.session.commit()
        return asset

    @staticmethod
    def get_by_organization(org_id: str) -> List[Asset]:
        return Asset.query.filter_by(organization_id=org_id).all()

    @staticmethod
    def get_by_criticality(org_id: str, criticality: str) -> List[Asset]:
        return Asset.query.filter_by(organization_id=org_id, criticality=criticality).all()


class VulnerabilityRepository:
    @staticmethod
    def create(organization_id: str, title: str, **kwargs) -> Vulnerability:
        vuln = Vulnerability(organization_id=organization_id, title=title, **kwargs)
        db.session.add(vuln)
        db.session.commit()
        return vuln

    @staticmethod
    def get_by_organization(org_id: str) -> List[Vulnerability]:
        return Vulnerability.query.filter_by(organization_id=org_id).order_by(Vulnerability.discovered_at.desc()).all()

    @staticmethod
    def get_open(org_id: str) -> List[Vulnerability]:
        return Vulnerability.query.filter_by(organization_id=org_id, status='Open').all()

    @staticmethod
    def get_by_severity(org_id: str, severity: str) -> List[Vulnerability]:
        return Vulnerability.query.filter_by(organization_id=org_id, severity=severity).all()

    @staticmethod
    def update(vuln_id: str, **kwargs) -> Optional[Vulnerability]:
        vuln = Vulnerability.query.get(vuln_id)
        if vuln:
            for key, value in kwargs.items():
                if hasattr(vuln, key):
                    setattr(vuln, key, value)
            db.session.commit()
        return vuln


class IncidentRepository:
    @staticmethod
    def create(organization_id: str, title: str, **kwargs) -> Incident:
        incident = Incident(organization_id=organization_id, title=title, **kwargs)
        db.session.add(incident)
        db.session.commit()
        return incident

    @staticmethod
    def get_by_organization(org_id: str) -> List[Incident]:
        return Incident.query.filter_by(organization_id=org_id).order_by(Incident.detected_at.desc()).all()

    @staticmethod
    def get_open(org_id: str) -> List[Incident]:
        return Incident.query.filter_by(organization_id=org_id).filter(
            Incident.status.notin_(['Closed', 'Resolved'])
        ).all()

    @staticmethod
    def update(incident_id: str, **kwargs) -> Optional[Incident]:
        incident = Incident.query.get(incident_id)
        if incident:
            for key, value in kwargs.items():
                if hasattr(incident, key):
                    setattr(incident, key, value)
            db.session.commit()
        return incident


class ComplianceRepository:
    @staticmethod
    def create(organization_id: str, framework: str, **kwargs) -> ComplianceAssessment:
        assessment = ComplianceAssessment(organization_id=organization_id, framework=framework, **kwargs)
        db.session.add(assessment)
        db.session.commit()
        return assessment

    @staticmethod
    def get_latest(org_id: str, framework: str = None) -> Optional[ComplianceAssessment]:
        query = ComplianceAssessment.query.filter_by(organization_id=org_id)
        if framework:
            query = query.filter_by(framework=framework)
        return query.order_by(ComplianceAssessment.assessed_at.desc()).first()

    @staticmethod
    def get_all_frameworks(org_id: str) -> List[ComplianceAssessment]:
        # Get latest assessment for each framework
        subquery = db.session.query(
            ComplianceAssessment.framework,
            db.func.max(ComplianceAssessment.assessed_at).label('max_date')
        ).filter_by(organization_id=org_id).group_by(ComplianceAssessment.framework).subquery()

        return ComplianceAssessment.query.filter_by(organization_id=org_id).join(
            subquery,
            db.and_(
                ComplianceAssessment.framework == subquery.c.framework,
                ComplianceAssessment.assessed_at == subquery.c.max_date
            )
        ).all()


class RiskRepository:
    @staticmethod
    def create(organization_id: str, **kwargs) -> RiskAssessment:
        assessment = RiskAssessment(organization_id=organization_id, **kwargs)
        db.session.add(assessment)
        db.session.commit()
        return assessment

    @staticmethod
    def get_latest(org_id: str) -> Optional[RiskAssessment]:
        return RiskAssessment.query.filter_by(organization_id=org_id)\
            .order_by(RiskAssessment.assessed_at.desc()).first()


class ChatRepository:
    @staticmethod
    def create_session(mode: str = 'general', organization_id: str = None,
                       title: str = None, context: Dict = None) -> ChatSession:
        session = ChatSession(mode=mode, organization_id=organization_id,
                              title=title or "Chat Session", context=context or {})
        db.session.add(session)
        db.session.commit()
        return session

    @staticmethod
    def get_session(session_id: str) -> Optional[ChatSession]:
        return ChatSession.query.get(session_id)

    @staticmethod
    def get_sessions(organization_id: str = None, limit: int = 20) -> List[ChatSession]:
        query = ChatSession.query
        if organization_id:
            query = query.filter_by(organization_id=organization_id)
        return query.order_by(ChatSession.updated_at.desc()).limit(limit).all()

    @staticmethod
    def add_message(session_id: str, role: str, content: str) -> ChatMessage:
        message = ChatMessage(session_id=session_id, role=role, content=content)
        db.session.add(message)
        session = ChatSession.query.get(session_id)
        if session:
            session.updated_at = datetime.utcnow()
        db.session.commit()
        return message

    @staticmethod
    def get_messages(session_id: str) -> List[ChatMessage]:
        return ChatMessage.query.filter_by(session_id=session_id).order_by(ChatMessage.created_at).all()

    @staticmethod
    def delete_session(session_id: str) -> bool:
        session = ChatSession.query.get(session_id)
        if session:
            ChatMessage.query.filter_by(session_id=session_id).delete()
            db.session.delete(session)
            db.session.commit()
            return True
        return False
