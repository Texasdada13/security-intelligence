"""Security Intelligence - Flask Web Application"""
import os
import sys
from flask import Flask, render_template, request, jsonify, Response, stream_with_context

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import get_config
from src.database.models import db
from src.database.repository import OrganizationRepository, VulnerabilityRepository, IncidentRepository, ComplianceRepository, RiskRepository, ChatRepository
from src.ai_core.chat_engine import ChatEngine, ConversationMode
from src.ai_core.file_analyzer import create_file_analyzer
from src.patterns.security_scoring import create_security_posture_engine
from src.database.models import UploadedFile
from src.patterns.compliance_engine import create_compliance_engine, ComplianceFramework
from src.demo.data_generator import create_security_demo_generator


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
    file_analyzer = create_file_analyzer()

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

    @app.route('/api/chat/sessions/<session_id>/suggestions', methods=['GET'])
    def api_chat_suggestions(session_id):
        """Get context-aware suggestions for a chat session."""
        if not chat_engine:
            return jsonify({'suggestions': [], 'error': 'Chat engine not available'}), 503

        session = ChatRepository.get_session(session_id)
        if not session:
            return jsonify({'error': 'Session not found'}), 404

        messages = ChatRepository.get_messages(session_id)
        history = [{'role': m.role, 'content': m.content} for m in messages]
        context = session.context or {}
        discussed_topics = session.discussed_topics or []
        dismissed_prompts = session.dismissed_suggestions or []

        suggestions = chat_engine.get_dynamic_suggestions(
            mode=session.mode or 'general',
            context=context,
            conversation_history=history,
            discussed_topics=discussed_topics,
            dismissed_prompts=dismissed_prompts,
            max_suggestions=4
        )

        return jsonify({
            'suggestions': suggestions,
            'context_summary': {
                'mode': session.mode,
                'discussed_topics': discussed_topics,
                'message_count': len(messages)
            }
        })

    @app.route('/api/chat/sessions/<session_id>/dismiss', methods=['POST'])
    def api_dismiss_suggestion(session_id):
        """Dismiss a suggestion so it won't appear again."""
        session = ChatRepository.get_session(session_id)
        if not session:
            return jsonify({'error': 'Session not found'}), 404

        data = request.json
        prompt_text = data.get('prompt')

        if prompt_text:
            dismissed = session.dismissed_suggestions or []
            if prompt_text not in dismissed:
                dismissed.append(prompt_text)
                session.dismissed_suggestions = dismissed
                db.session.commit()

        return jsonify({'success': True})

    @app.route('/api/chat/sessions/<session_id>/topics', methods=['POST'])
    def api_track_topics(session_id):
        """Track discussed topics from a message."""
        if not chat_engine:
            return jsonify({'error': 'Chat engine not available'}), 503

        session = ChatRepository.get_session(session_id)
        if not session:
            return jsonify({'error': 'Session not found'}), 404

        data = request.json
        message = data.get('message', '')
        new_topics = chat_engine.extract_topics(message)

        discussed = session.discussed_topics or []
        for topic in new_topics:
            if topic not in discussed:
                discussed.append(topic)

        session.discussed_topics = discussed
        db.session.commit()

        return jsonify({
            'new_topics': new_topics,
            'all_topics': discussed
        })

    # ==================== FILE UPLOAD API ====================

    @app.route('/api/chat/sessions/<session_id>/upload', methods=['POST'])
    def api_upload_file(session_id):
        """Upload a file for analysis."""
        session = ChatRepository.get_session(session_id)
        if not session:
            return jsonify({'error': 'Session not found'}), 404

        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        content = file.read()
        filename = file.filename

        try:
            result = file_analyzer.analyze_file(content, filename)
        except Exception as e:
            return jsonify({'error': f'Failed to analyze file: {str(e)}'}), 400

        uploaded_file = UploadedFile(
            session_id=session_id,
            filename=filename,
            file_type=result.file_type,
            file_size=len(content),
            analysis_result=result.to_dict(),
            context_summary=result.data_summary,
            row_count=result.row_count,
            column_count=result.column_count,
            detected_metrics=result.detected_metrics
        )
        db.session.add(uploaded_file)
        db.session.commit()

        return jsonify({
            'file_id': uploaded_file.id,
            'filename': filename,
            'analysis': result.to_dict()
        }), 201

    @app.route('/api/chat/sessions/<session_id>/files', methods=['GET'])
    def api_list_files(session_id):
        """List files uploaded to a session."""
        session = ChatRepository.get_session(session_id)
        if not session:
            return jsonify({'error': 'Session not found'}), 404

        files = UploadedFile.query.filter_by(session_id=session_id).all()
        return jsonify({'files': [f.to_dict() for f in files]})

    @app.route('/api/chat/sessions/<session_id>/files/<file_id>', methods=['GET', 'DELETE'])
    def api_file_detail(session_id, file_id):
        """Get or delete a specific file."""
        uploaded_file = UploadedFile.query.filter_by(id=file_id, session_id=session_id).first()
        if not uploaded_file:
            return jsonify({'error': 'File not found'}), 404

        if request.method == 'DELETE':
            db.session.delete(uploaded_file)
            db.session.commit()
            return jsonify({'success': True})

        return jsonify(uploaded_file.to_dict())

    # ==================== DEMO DATA API ====================

    @app.route('/api/demo/generate', methods=['POST'])
    def api_generate_demo():
        """Generate demo security data."""
        data = request.json or {}
        org_name = data.get('organization_name')
        seed = data.get('seed')

        generator = create_security_demo_generator(seed)
        demo_data = generator.generate_full_demo(org_name)

        return jsonify(demo_data)

    @app.route('/api/demo/load', methods=['POST'])
    def api_load_demo():
        """Generate demo data and load it into the database."""
        data = request.json or {}
        org_name = data.get('organization_name', 'Demo Security Corp')
        seed = data.get('seed')

        generator = create_security_demo_generator(seed)
        demo_data = generator.generate_full_demo(org_name)

        # Create organization
        org = OrganizationRepository.create(
            name=demo_data['organization']['name'],
            industry=demo_data['organization']['industry'],
            size=str(demo_data['organization']['employee_count']),
            compliance_frameworks=demo_data['organization']['compliance_frameworks']
        )

        # Create vulnerabilities
        for vuln_data in demo_data['vulnerabilities']:
            VulnerabilityRepository.create(
                organization_id=org.id,
                cve_id=vuln_data['cve_id'],
                title=vuln_data['title'],
                severity=vuln_data['severity'],
                cvss_score=vuln_data['cvss_score'],
                status=vuln_data['status'],
                affected_asset=vuln_data['affected_asset']
            )

        # Create incidents
        for incident_data in demo_data['incidents']:
            IncidentRepository.create(
                organization_id=org.id,
                title=incident_data['title'],
                incident_type=incident_data['incident_type'],
                severity=incident_data['severity'],
                status=incident_data['status']
            )

        return jsonify({
            'success': True,
            'organization_id': org.id,
            'organization_name': org.name,
            'vulnerabilities_created': len(demo_data['vulnerabilities']),
            'incidents_created': len(demo_data['incidents']),
            'compliance_frameworks': demo_data['organization']['compliance_frameworks'],
            'metrics_summary': demo_data['metrics_summary']
        }), 201

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
