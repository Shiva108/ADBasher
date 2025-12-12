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
    
    def start(self):
        """Launch attack campaign in background thread"""
        self.status = "running"
        thread = threading.Thread(target=self._run_attacks)
        thread.daemon = True
        thread.start()
    
    def _run_attacks(self):
        """Execute attack workflow"""
        try:
            # Update phase
            self._update_phase("Reconnaissance", 10)
            
            # Initialize orchestrator with config
            args_namespace = self._config_to_args()
            self.orchestrator = Orchestrator(args_namespace)
            
            # Run phases
            self.orchestrator.initialize_session()
            
            # Recon
            self._update_phase("Reconnaissance", 20)
            self.orchestrator.run_recon()
            
            # Credential attacks
            self._update_phase("Credential Attacks", 40)
            self.orchestrator.run_cred_attacks()
            
            # Post-exploitation (if enabled)
            if self.config.get('enable_post_exploit', True):
                self._update_phase("Post-Exploitation", 60)
                self.orchestrator.run_vuln_analysis()
            
            # Lateral movement (if admin creds)
            if self.config.get('enable_lateral_movement', False):
                self._update_phase("Lateral Movement", 80)
                self.orchestrator.run_lateral_movement()
            
            # Reporting
            self._update_phase("Generating Report", 95)
            self.orchestrator.run_reporting()
            
            self._update_phase("Complete", 100)
            self.status = "completed"
            
        except Exception as e:
            self.status = "failed"
            self._broadcast_error(str(e))
    
    def _config_to_args(self):
        """Convert web config to orchestrator args"""
        from argparse import Namespace
        
        args = Namespace()
        args.target = self.config.get('targets', [])
        args.username = self.config.get('username')
        args.password = self.config.get('password')
        args.domain = self.config.get('domain')
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
            session = self.orchestrator.db.get_session()
            stats['targets'] = session.query(Target).count()
            stats['credentials'] = session.query(Credential).count()
            stats['vulnerabilities'] = session.query(Vulnerability).count()
            session.close()
        
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
        """Stop campaign execution"""
        self.status = "stopped"
        # TODO: Implement graceful shutdown of orchestrator
        self._update_phase("Stopped by user", self.progress)


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
def list_campaigns():
    """List all campaigns"""
    campaigns = []
    for campaign_id, manager in active_campaigns.items():
        campaigns.append(manager.get_status())
    
    return jsonify({'campaigns': campaigns})

@app.route('/api/campaigns', methods=['POST'])
def create_campaign():
    """Create new penetration test campaign"""
    data = request.json
    
    # Validate required fields
    required_fields = ['name', 'domain', 'targets']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Generate campaign ID
    campaign_id = str(uuid.uuid4())
    
    # Create campaign manager
    config = {
        'name': data['name'],
        'domain': data.get('domain'),
        'targets': data.get('targets', []),
        'username': data.get('username'),
        'password': data.get('password'),
        'enable_post_exploit': data.get('enable_post_exploit', True),
        'enable_lateral_movement': data.get('enable_lateral_movement', False),
        'attack_profile': data.get('attack_profile', 'balanced'),
        'notification_email': data.get('notification_email')
    }
    
    manager = CampaignManager(campaign_id, config)
    active_campaigns[campaign_id] = manager
    
    # Start campaign
    manager.start()
    
    return jsonify({
        'campaign_id': campaign_id,
        'status': 'created',
        'message': 'Campaign started successfully'
    }), 201

@app.route('/api/campaigns/<campaign_id>', methods=['GET'])
def get_campaign(campaign_id):
    """Get campaign status"""
    if campaign_id not in active_campaigns:
        return jsonify({'error': 'Campaign not found'}), 404
    
    manager = active_campaigns[campaign_id]
    return jsonify(manager.get_status())

@app.route('/api/campaigns/<campaign_id>/stop', methods=['POST'])
def stop_campaign(campaign_id):
    """Stop running campaign"""
    if campaign_id not in active_campaigns:
        return jsonify({'error': 'Campaign not found'}), 404
    
    manager = active_campaigns[campaign_id]
    manager.stop()
    
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
# Main
# ============================================================================

if __name__ == '__main__':
    # Run with SocketIO
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
