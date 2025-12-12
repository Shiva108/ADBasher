"""
ADBasher Web Dashboard - Flask Backend
Provides REST API and WebSocket support for campaign management
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
import sys
import uuid
import threading
from datetime import datetime
import json

# Add core to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.orchestrator import Orchestrator
from core.database import DatabaseManager, Target, Credential, Vulnerability

# Import logging and security utilities
from logging_config import app_logger, audit_logger, log_campaign_event, log_security_event
from security import rate_limit, sanitize_html, validate_content_type
from encryption import encrypt_sensitive_data, decrypt_sensitive_data

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory campaign tracking (will move to Redis for production)
active_campaigns = {}

class CampaignManager:
    """Manages penetration test campaigns"""
    
    def __init__(self, campaign_id, config):
        self.campaign_id = campaign_id
        self.config = config
        self.status = "initializing"
        self.progress = 0
        self.current_phase = "Setup"
        self.findings = []
        self.start_time = datetime.now()
        self.orchestrator = None
        self.stop_flag = threading.Event()  # For graceful shutdown
        self.thread = None
    
    def start(self):
        """Launch attack campaign in background thread"""
        self.status = "running"
        self.thread = threading.Thread(target=self._run_attacks)
        self.thread.daemon = True
        self.thread.start()
    
    def _run_attacks(self):
        """Execute attack workflow"""
        try:
            # Update phase
            self._update_phase("Reconnaissance", 10)
            
            # Check if stopped
            if self.stop_flag.is_set():
                self._cleanup()
                return
            
            # Initialize orchestrator with config
            args_namespace = self._config_to_args()
            self.orchestrator = Orchestrator(args_namespace)
            
            # Run phases
            self.orchestrator.initialize_session()
            
            # Recon
            self._update_phase("Reconnaissance", 20)
            if self.stop_flag.is_set():
                self._cleanup()
                return
            self.orchestrator.run_recon()
            
            # Credential attacks
            self._update_phase("Credential Attacks", 40)
            if self.stop_flag.is_set():
                self._cleanup()
                return
            self.orchestrator.run_cred_attacks()
            
            # Post-exploitation (if enabled)
            if self.config.get('enable_post_exploit', True):
                self._update_phase("Post-Exploitation", 60)
                if self.stop_flag.is_set():
                    self._cleanup()
                    return
                self.orchestrator.run_vuln_analysis()
            
            # Lateral movement (if admin creds)
            if self.config.get('enable_lateral_movement', False):
                self._update_phase("Lateral Movement", 80)
                if self.stop_flag.is_set():
                    self._cleanup()
                    return
                self.orchestrator.run_lateral_movement()
            
            # Reporting
            self._update_phase("Generating Report", 95)
            if self.stop_flag.is_set():
                self._cleanup()
                return
            self.orchestrator.run_reporting()
            
            self._update_phase("Complete", 100)
            self.status = "completed"
            
        except Exception as e:
            self.status = "failed"
            self._broadcast_error(str(e))
            import traceback
            print(f"Campaign {self.campaign_id} failed: {traceback.format_exc()}")
    
    def _cleanup(self):
        """Clean up resources on stop"""
        try:
            if self.orchestrator and self.orchestrator.db:
                # Close database connections
                self.orchestrator.db.close()
            
            self.status = "stopped"
            self._update_phase("Stopped by user", self.progress)
            
        except Exception as e:
            print(f"Error during cleanup: {e}")
    
    def _config_to_args(self):
        """Convert web config to orchestrator args"""
        from argparse import Namespace
        
        # Decrypt sensitive data for use
        decrypted_config = decrypt_sensitive_data(self.config)
        
        args = Namespace()
        args.target = decrypted_config.get('targets', [])
        args.username = decrypted_config.get('username')
        args.password = decrypted_config.get('password')  # Now decrypted
        args.domain = decrypted_config.get('domain')
        args.config_file = None
        
        return args
    
    def _update_phase(self, phase_name, progress):
        """Update campaign phase and broadcast to clients"""
        self.current_phase = phase_name
        self.progress = progress
        
        # Broadcast update via WebSocket
        socketio.emit('campaign_update', {
            'campaign_id': self.campaign_id,
            'phase': phase_name,
            'progress': progress,
            'status': self.status
        }, room=f'campaign_{self.campaign_id}')
    
    def _broadcast_error(self, error_msg):
        """Broadcast error to connected clients"""
        socketio.emit('campaign_error', {
            'campaign_id': self.campaign_id,
            'error': error_msg
        }, room=f'campaign_{self.campaign_id}')
    
    def get_status(self):
        """Get current campaign status"""
        # Get real-time stats from database if orchestrator exists
        stats = {
            'targets': 0,
            'credentials': 0,
            'vulnerabilities': 0
        }
        
        if self.orchestrator and self.orchestrator.db:
            try:
                session = self.orchestrator.db.get_session()
                stats['targets'] = session.query(Target).count()
                stats['credentials'] = session.query(Credential).count()
                stats['vulnerabilities'] = session.query(Vulnerability).count()
                session.close()
            except Exception as e:
                print(f"Error getting stats: {e}")
        
        return {
            'campaign_id': self.campaign_id,
            'name': self.config.get('name'),
            'status': self.status,
            'progress': self.progress,
            'current_phase': self.current_phase,
            'start_time': self.start_time.isoformat(),
            'elapsed_seconds': (datetime.now() - self.start_time).total_seconds(),
            'statistics': stats
        }
    
    def stop(self):
        """Stop campaign execution gracefully"""
        self.stop_flag.set()
        self.status = "stopping"
        self._update_phase("Stopping...", self.progress)


# ============================================================================
# REST API Endpoints
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/campaigns', methods=['GET'])
@rate_limit(max_requests=30, window_seconds=60)
def list_campaigns():
    """List all campaigns"""
    try:
        campaigns = []
        for campaign_id, manager in active_campaigns.items():
            campaigns.append(manager.get_status())
        
        return jsonify({'campaigns': campaigns})
    except Exception as e:
        app_logger.error(f'Error listing campaigns: {e}')
        return jsonify({'error': 'Failed to list campaigns'}), 500

@app.route('/api/campaigns', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)
@validate_content_type('application/json')
def create_campaign():
    """Create new penetration test campaign"""
    try:
        data = request.json
        client_ip = request.remote_addr
        
        if not data:
            log_security_event(audit_logger, 'invalid_request', 'Empty request body', ip_address=client_ip)
            return jsonify({'error': 'Request body is required'}), 400
        
        # Import validation utilities
        from validation import (
            validate_campaign_name, validate_domain, validate_targets,
            validate_username, validate_email, sanitize_string,
            validate_content_type, log_security_event
        )
        
        # Validate required fields
        required_fields = ['name', 'domain', 'targets']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Validate campaign name
        is_valid, error_msg = validate_campaign_name(data['name'])
        if not is_valid:
            log_security_event(audit_logger, 'validation_failed', f'Campaign name: {error_msg}', ip_address=client_ip)
            return jsonify({'error': f'Invalid campaign name: {error_msg}'}), 400
        
        # Validate domain
        is_valid, error_msg = validate_domain(data['domain'])
        if not is_valid:
            return jsonify({'error': f'Invalid domain: {error_msg}'}), 400
        
        # Validate targets
        is_valid, error_msg = validate_targets(data['targets'])
        if not is_valid:
            return jsonify({'error': f'Invalid targets: {error_msg}'}), 400
        
        # Validate optional username
        if 'username' in data and data['username']:
            is_valid, error_msg = validate_username(data['username'])
            if not is_valid:
                return jsonify({'error': f'Invalid username: {error_msg}'}), 400
        
        # Validate optional email
        if 'notification_email' in data and data['notification_email']:
            is_valid, error_msg = validate_email(data['notification_email'])
            if not is_valid:
                return jsonify({'error': f'Invalid email: {error_msg}'}), 400
        
        # Generate campaign ID
        campaign_id = str(uuid.uuid4())
        
        # Create campaign manager with sanitized inputs
        config = {
            'name': sanitize_string(data['name'], 100),
            'domain': sanitize_string(data['domain'], 253),
            'targets': [sanitize_string(t, 253) for t in data['targets']],
            'username': sanitize_string(data.get('username', ''), 256) if data.get('username') else None,
            'password': data.get('password'),  # Don't sanitize passwords
            'enable_post_exploit': bool(data.get('enable_post_exploit', True)),
            'enable_lateral_movement': bool(data.get('enable_lateral_movement', False)),
            'attack_profile': sanitize_string(data.get('attack_profile', 'balanced'), 50),
            'notification_email': sanitize_string(data.get('notification_email', ''), 256) if data.get('notification_email') else None
        }
        
        # Encrypt sensitive data before storage
        encrypted_config = encrypt_sensitive_data(config)
        
        manager = CampaignManager(campaign_id, encrypted_config)
        active_campaigns[campaign_id] = manager
        
        # Log campaign creation (don't log sensitive data)
        log_campaign_event(app_logger, 'created', campaign_id, f'Campaign: {config["name"]}, Domain: {config["domain"]}')
        audit_logger.info(f'Campaign created', extra={'campaign_id': campaign_id, 'ip_address': client_ip})
        
        # Start campaign
        manager.start()
        
        return jsonify({
            'campaign_id': campaign_id,
            'status': 'created',
            'message': 'Campaign started successfully'
        }), 201
        
    except Exception as e:
        app_logger.error(f'Failed to create campaign: {e}')
        return jsonify({'error': f'Failed to create campaign: {str(e)}'}), 500

@app.route('/api/campaigns/<campaign_id>', methods=['GET'])
@rate_limit(max_requests=60, window_seconds=60)
def get_campaign(campaign_id):
    """Get campaign status"""
    if campaign_id not in active_campaigns:
        return jsonify({'error': 'Campaign not found'}), 404
    
    manager = active_campaigns[campaign_id]
    return jsonify(manager.get_status())

@app.route('/api/campaigns/<campaign_id>/stop', methods=['POST'])
@rate_limit(max_requests=20, window_seconds=60)
def stop_campaign(campaign_id):
    """Stop running campaign"""
    if campaign_id not in active_campaigns:
        return jsonify({'error': 'Campaign not found'}), 404
    
    manager = active_campaigns[campaign_id]
    manager.stop()
    
    # Log stopping event
    log_campaign_event(app_logger, 'stopped', campaign_id)
    audit_logger.warning(f'Campaign stopped', extra={'campaign_id': campaign_id, 'ip_address': request.remote_addr})
    
    return jsonify({
        'campaign_id': campaign_id,
        'status': 'stopped',
        'message': 'Campaign stopped successfully'
    })

@app.route('/api/campaigns/<campaign_id>/findings', methods=['GET'])
def get_findings(campaign_id):
    """Get campaign findings"""
    if campaign_id not in active_campaigns:
        return jsonify({'error': 'Campaign not found'}), 404
    
    manager = active_campaigns[campaign_id]
    
    if not manager.orchestrator or not manager.orchestrator.db:
        return jsonify({'findings': []})
    
    # Get findings from database
    session = manager.orchestrator.db.get_session()
    
    findings = []
    
    # Credentials
    credentials = session.query(Credential).all()
    for cred in credentials:
        findings.append({
            'type': 'credential',
            'severity': 'high' if cred.is_admin else 'medium',
            'title': f'Credential Discovered: {cred.username}',
            'details': {
                'username': cred.username,
                'domain': cred.domain,
                'source': cred.source,
                'is_admin': cred.is_admin
            },
            'timestamp': cred.discovered_at.isoformat() if cred.discovered_at else None
        })
    
    # Vulnerabilities
    vulnerabilities = session.query(Vulnerability).all()
    for vuln in vulnerabilities:
        findings.append({
            'type': 'vulnerability',
            'severity': vuln.severity.lower(),
            'title': vuln.name,
            'details': {
                'description': vuln.description,
                'cve_id': vuln.cve_id
            },
            'timestamp': vuln.discovered_at.isoformat() if vuln.discovered_at else None
        })
    
    session.close()
    
    # Sort by timestamp (newest first)
    findings.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return jsonify({'findings': findings})

@app.route('/api/campaigns/<campaign_id>/report', methods=['GET'])
def download_report(campaign_id):
    """Download campaign report"""
    if campaign_id not in active_campaigns:
        return jsonify({'error': 'Campaign not found'}), 404
    
    manager = active_campaigns[campaign_id]
    
    if not manager.orchestrator:
        return jsonify({'error': 'Report not yet available'}), 400
    
    # Get report path
    session_dir = manager.orchestrator.session_dir
    report_path = os.path.join(session_dir, 'report.md')
    
    if not os.path.exists(report_path):
        return jsonify({'error': 'Report file not found'}), 404
    
    return send_from_directory(session_dir, 'report.md', 
                               as_attachment=True,
                               download_name=f'adbasher_report_{campaign_id}.md')


# ============================================================================
# WebSocket Endpoints
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    print(f'Client connected: {request.sid}')
    emit('connection_established', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    print(f'Client disconnected: {request.sid}')

@socketio.on('subscribe_campaign')
def handle_campaign_subscription(data):
    """Subscribe to campaign updates"""
    campaign_id = data.get('campaign_id')
    
    if campaign_id not in active_campaigns:
        emit('error', {'message': 'Campaign not found'})
        return
    
    # Join room for this campaign
    join_room(f'campaign_{campaign_id}')
    
    # Send initial status
    manager = active_campaigns[campaign_id]
    emit('campaign_update', manager.get_status())

@socketio.on('unsubscribe_campaign')
def handle_campaign_unsubscription(data):
    """Unsubscribe from campaign updates"""
    campaign_id = data.get('campaign_id')
    leave_room(f'campaign_{campaign_id}')


# ============================================================================
# Frontend Routes (Serve React App)
# ============================================================================

@app.route('/assets/<path:filename>')
def serve_assets(filename):
    """Serve static assets from React build"""
    return send_from_directory(os.path.join(os.path.dirname(__file__), 'frontend/dist/assets'), filename)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react_app(path):
    """Serve React app for all non-API routes (SPA routing)"""
    # Don't intercept API routes
    if path.startswith('api/'):
        return jsonify({'error': 'Not found'}), 404
    
    # Serve index.html for all other routes
    frontend_dist = os.path.join(os.path.dirname(__file__), 'frontend/dist')
    
    # Check if specific file exists in dist
    file_path = os.path.join(frontend_dist, path)
    if path and os.path.exists(file_path) and os.path.isfile(file_path):
        return send_from_directory(frontend_dist, path)
    
    # Otherwise serve index.html (SPA routing)
    return send_from_directory(frontend_dist, 'index.html')


# ============================================================================
# Main
# ============================================================================

if __name__ == '__main__':
    # Initialize logging
    app_logger.info('Starting ADBasher Web Dashboard')
    app_logger.info(f'Logs directory: {os.path.abspath("logs")}')
    
    # Run with SocketIO
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        app_logger.critical(f'Fatal error starting server: {e}')
        raise
