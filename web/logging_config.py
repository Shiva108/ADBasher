"""
Structured logging configuration for ADBasher web dashboard
Provides comprehensive logging with rotation, structured formats, and audit trails
"""

import logging
import logging.handlers
import os
import json
from datetime import datetime
from pathlib import Path

# Create logs directory
LOGS_DIR = Path(__file__).parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)

class StructuredFormatter(logging.Formatter):
    """JSON-based structured logger"""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, 'campaign_id'):
            log_data['campaign_id'] = record.campaign_id
        if hasattr(record, 'user_id'):
            log_data['user_id'] = record.user_id
        if hasattr(record, 'ip_address'):
            log_data['ip_address'] = record.ip_address
        
        return json.dumps(log_data)

def setup_logging():
    """Configure application logging"""
    
    # Main application logger
    app_logger = logging.getLogger('adbasher.web')
    app_logger.setLevel(logging.INFO)
    
    # Console handler (human-readable)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    app_logger.addHandler(console_handler)
    
    # File handler (JSON structured)
    file_handler = logging.handlers.RotatingFileHandler(
        LOGS_DIR / 'app.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(StructuredFormatter())
    app_logger.addHandler(file_handler)
    
    # Error log handler
    error_handler = logging.handlers.RotatingFileHandler(
        LOGS_DIR / 'errors.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(StructuredFormatter())
    app_logger.addHandler(error_handler)
    
    return app_logger

def setup_audit_logging():
    """Configure security audit logging"""
    
    audit_logger = logging.getLogger('adbasher.audit')
    audit_logger.setLevel(logging.INFO)
    
    # Audit log handler (separate file)
    audit_handler = logging.handlers.RotatingFileHandler(
        LOGS_DIR / 'audit.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10  # Keep more audit logs
    )
    audit_handler.setLevel(logging.INFO)
    audit_handler.setFormatter(StructuredFormatter())
    audit_logger.addHandler(audit_handler)
    
    return audit_logger

def setup_performance_logging():
    """Configure performance monitoring logging"""
    
    perf_logger = logging.getLogger('adbasher.performance')
    perf_logger.setLevel(logging.INFO)
    
    # Performance log handler
    perf_handler = logging.handlers.RotatingFileHandler(
        LOGS_DIR / 'performance.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=3
    )
    perf_handler.setLevel(logging.INFO)
    perf_handler.setFormatter(StructuredFormatter())
    perf_logger.addHandler(perf_handler)
    
    return perf_logger

def log_campaign_event(logger, event_type, campaign_id, details=None):
    """Log a campaign event with structured data"""
    extra = {'campaign_id': campaign_id}
    message = f"Campaign event: {event_type}"
    if details:
        message += f" - {details}"
    logger.info(message, extra=extra)

def log_security_event(audit_logger, event_type, details, ip_address=None, user_id=None):
    """Log a security event for audit trail"""
    extra = {}
    if ip_address:
        extra['ip_address'] = ip_address
    if user_id:
        extra['user_id'] = user_id
    
    audit_logger.warning(f"Security event: {event_type} - {details}", extra=extra)

# Initialize loggers
app_logger = setup_logging()
audit_logger = setup_audit_logging()
perf_logger = setup_performance_logging()
