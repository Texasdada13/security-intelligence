"""Security Intelligence - Flask Web Application"""
import os
import sys
from flask import Flask, render_template, request, jsonify, Response, stream_with_context

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import get_config
from src.database.models import db
from src.database.repository import OrganizationRepository, VulnerabilityRepository, IncidentRepository, ComplianceRepository, RiskRepository, ChatRepository
from src.ai_core.chat_engine import ChatEngine, ConversationMode
from src.patterns.security_scoring import create_security_posture_engine
from src.patterns.compliance_engine import create_compliance_engine, ComplianceFramework


def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='../static')
    config = get_config()
    app.config.from_object(config)
    db.init_app(app)

    with app.app_context():
        db.create_all()

    try:
        chat_engine = ChatEngine()
    except Exception as e:
        print(f"Warning: Could not initialize ChatEngine: {e}")
        chat_engine = None

    security_engine = create_security_posture_engine()

    # ==================== PAGE ROUTES ====================

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/dashboard')
    def dashboard():
        organizations = OrganizationRepository.get_all()
        return render_template('dashboard.html', organizations=organizations)

    @app.route('/organization/<org_id>')
    def organization_detail(org_id):
        org = OrganizationRepository.get_by_id(org_id)
        if not org:
            return render_template('404.html'), 404

        vulnerabilities = VulnerabilityRepository.get_by_organization(org_id)
        incidents = IncidentRepository.get_by_organization(org_id)
        compliance = ComplianceRepository.get_latest(org_id)
        risk = RiskRepository.get_latest(org_id)

        return render_template('organization.html',
                               organization=org,
                               vulnerabilities=vulnerabilities,
                               incidents=incidents,
                               compliance=compliance,
                               risk=risk)

    @app.route('/chat')
    def chat_page():
        modes = {mode.value: desc for mode, desc in [
            (ConversationMode.GENERAL, "General security questions"),
            (ConversationMode.RISK_ASSESSMENT, "Risk assessment"),
            (ConversationMode.COMPLIANCE_REVIEW, "Compliance review"),
            (ConversationMode.INCIDENT_RESPONSE, "Incident response"),
            (ConversationMode.VULNERABILITY_MANAGEMENT, "Vulnerability management"),
            (ConversationMode.THREAT_INTELLIGENCE, "Threat intelligence"),
            (ConversationMode.SECURITY_ARCHITECTURE, "Security architecture"),
            (ConversationMode.SECURITY_PROGRAM, "Security program"),
        ]}
        return render_template('chat.html', modes=modes)

    # ==================== API ROUTES ====================

    @app.route('/api/organizations', methods=['GET', 'POST'])
    def api_organizations():
        if request.method == 'POST':
            data = request.json
            org = OrganizationRepository.create(
                name=data.get('name'),
                industry=data.get('industry'),
                size=data.get('size'),
                compliance_frameworks=data.get('compliance_frameworks', [])
            )
            return jsonify(org.to_dict()), 201
        organizations = OrganizationRepository.get_all()
        return jsonify([org.to_dict() for org in organizations])

    @app.route('/api/organizations/<org_id>', methods=['GET', 'PUT', 'DELETE'])
    def api_organization(org_id):
        if request.method == 'DELETE':
            success = OrganizationRepository.delete(org_id)
            return jsonify({'success': success})
        if request.method == 'PUT':
            data = request.json
            org = OrganizationRepository.update(org_id, **data)
            return jsonify(org.to_dict()) if org else ('Not found', 404)
        org = OrganizationRepository.get_by_id(org_id)
        return jsonify(org.to_dict()) if org else ('Not found', 404)

    @app.route('/api/organizations/<org_id>/vulnerabilities', methods=['GET', 'POST'])
    def api_vulnerabilities(org_id):
        if request.method == 'POST':
            data = request.json
            vuln = VulnerabilityRepository.create(organization_id=org_id, **data)
            return jsonify(vuln.to_dict()), 201
        vulns = VulnerabilityRepository.get_by_organization(org_id)
        return jsonify([v.to_dict() for v in vulns])

    @app.route('/api/organizations/<org_id>/incidents', methods=['GET', 'POST'])
    def api_incidents(org_id):
        if request.method == 'POST':
            data = request.json
            incident = IncidentRepository.create(organization_id=org_id, **data)
            return jsonify(incident.to_dict()), 201
        incidents = IncidentRepository.get_by_organization(org_id)
        return jsonify([i.to_dict() for i in incidents])

    # ==================== CHAT API ====================

    @app.route('/api/chat/sessions', methods=['GET', 'POST'])
    def api_chat_sessions():
        if request.method == 'POST':
            data = request.json
            session = ChatRepository.create_session(
                mode=data.get('mode', 'general'),
                organization_id=data.get('organization_id'),
                title=data.get('title'),
                context=data.get('context')
            )
            return jsonify(session.to_dict()), 201
        sessions = ChatRepository.get_sessions(limit=20)
        return jsonify([s.to_dict() for s in sessions])

    @app.route('/api/chat/sessions/<session_id>', methods=['GET', 'DELETE'])
    def api_chat_session(session_id):
        if request.method == 'DELETE':
            success = ChatRepository.delete_session(session_id)
            return jsonify({'success': success})
        session = ChatRepository.get_session(session_id)
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        messages = ChatRepository.get_messages(session_id)
        return jsonify({
            'session': session.to_dict(),
            'messages': [m.to_dict() for m in messages]
        })

    @app.route('/api/chat/sessions/<session_id>/messages', methods=['POST'])
    def api_chat_message(session_id):
        if not chat_engine:
            return jsonify({'error': 'Chat engine not available'}), 503

        session = ChatRepository.get_session(session_id)
        if not session:
            return jsonify({'error': 'Session not found'}), 404

        data = request.json
        user_message = data.get('message', '')
        ChatRepository.add_message(session_id, 'user', user_message)

        messages = ChatRepository.get_messages(session_id)
        history = [{'role': m.role, 'content': m.content} for m in messages[:-1]]
        mode = ConversationMode(session.mode) if session.mode else ConversationMode.GENERAL
        context = session.context or {}

        response = chat_engine.chat(user_message, mode=mode, history=history, context=context)
        ChatRepository.add_message(session_id, 'assistant', response)

        return jsonify({'response': response})

    @app.route('/api/chat/sessions/<session_id>/stream', methods=['POST'])
    def api_chat_stream(session_id):
        if not chat_engine:
            return jsonify({'error': 'Chat engine not available'}), 503

        session = ChatRepository.get_session(session_id)
        if not session:
            return jsonify({'error': 'Session not found'}), 404

        data = request.json
        user_message = data.get('message', '')
        ChatRepository.add_message(session_id, 'user', user_message)

        messages = ChatRepository.get_messages(session_id)
        history = [{'role': m.role, 'content': m.content} for m in messages[:-1]]
        mode = ConversationMode(session.mode) if session.mode else ConversationMode.GENERAL
        context = session.context or {}

        def generate():
            full_response = []
            for chunk in chat_engine.chat_stream(user_message, mode=mode, history=history, context=context):
                full_response.append(chunk)
                yield f"data: {chunk}\n\n"
            ChatRepository.add_message(session_id, 'assistant', ''.join(full_response))
            yield "data: [DONE]\n\n"

        return Response(stream_with_context(generate()), mimetype='text/event-stream')

    @app.route('/api/chat/prompts/<mode>')
    def api_suggested_prompts(mode):
        if chat_engine:
            try:
                prompts = chat_engine.get_suggested_prompts(ConversationMode(mode))
                return jsonify({'prompts': prompts})
            except ValueError:
                pass
        return jsonify({'prompts': []})

    @app.route('/health')
    def health():
        return jsonify({
            'status': 'healthy',
            'service': 'security-intelligence',
            'ai_enabled': chat_engine is not None
        })

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not found'}), 404
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('500.html'), 500

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
