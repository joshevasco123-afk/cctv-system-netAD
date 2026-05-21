from flask import Blueprint, jsonify, request, session, abort, make_response
from database.models import db, CameraLog
from functools import wraps
import re
import os
import logging
from logging.handlers import RotatingFileHandler
import time

logger_bp = Blueprint('logger', __name__)

# =====================================================================
# HARDENING MODULE IX: Web-Root Isolation & Log Rotation Config
# =====================================================================
LOG_FILE_PATH = os.environ.get('SECURE_LOG_PATH', '/tmp/secure_cctv_system.log')

secure_file_handler = RotatingFileHandler(LOG_FILE_PATH, maxBytes=5 * 1024 * 1024, backupCount=5)
secure_file_handler.setFormatter(logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s'))

app_logger = logging.getLogger('SecureCCTVLogger')
app_logger.setLevel(logging.INFO)
app_logger.addHandler(secure_file_handler)
app_logger.propagate = False 

# =====================================================================
# HARDENING MODULE I & III: Route Protection Access Control
# =====================================================================
def secure_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin') or not session.get('user_id'):
            return abort(403, description="Access Denied: Unauthenticated Session")
            
        now = time.time()
        if now - session.get('last_activity', now) > 900:
            session.clear() # Linisin ang session cookies para sa proteksyon
            return abort(401, description="Session Expired: Please Re-authenticate")
            
        current_agent = request.headers.get('User-Agent', '')
        if session.get('user_agent') != current_agent:
            return abort(401, description="Security Violation: Session Footprint Changed")
            
        session['last_activity'] = now # I-update ang rolling timeout check
        return f(*args, **kwargs)
    return decorated_function

# =====================================================================
# HARDENING MODULE X: Log Input Sanitization & Anti-Injection Filters
# =====================================================================
def sanitize_log_input(raw_data):
    if not raw_data:
        return "EMPTY_FIELD"
    
    # Basagin ang CRLF at Log Injection vectors
    clean_string = str(raw_data).replace('\n', '\\n').replace('\r', '\\r')
    
    # Ligtas na alphanumeric, brackets, spaces, at logging symbols lamang
    clean_string = re.sub(r'[^\w\s\.\-\:\[\]\_]', '', clean_string)
    
    # HARDENING FIX: Substring Redaction sa halip na burahin ang buong mensahe
    sensitive_keywords = ['password', 'secret', 'token', 'pass', 'api_key', 'cookie']
    for keyword in sensitive_keywords:
        # Gagamit ng case-insensitive regex substitution para palitan lamang ang sensitibong salita
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        clean_string = pattern.sub("[REDACTED_SENSITIVE_KEYWORD]", clean_string)
            
    return clean_string.strip()

def get_audit_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
    
    cleaned_ip = "".join(c for c in ip if c.isalnum() or c in ['.', ':'])
    return cleaned_ip if cleaned_ip else "UNKNOWN_AUDIT_IP"

# =====================================================================
# CORE LOGGING OPERATIONS (Immutable Append-Only Infrastructure)
# =====================================================================
def emit_secure_log(event_type, description):
    try:
        client_ip = get_audit_ip()
        sanitized_event = sanitize_log_input(event_type)
        sanitized_desc = sanitize_log_input(description)
        
        allowed_events = [
            'ADMIN_LOGIN_SUCCESSFUL', 'UNAUTHORIZED_LOGIN_ATTEMPT', 
            'SECURE_STREAM_STARTED', 'ADMIN_LOGOUT_REQUESTED', 
            'SYSTEM_MODIFICATION_ATTEMPT'
        ]
        if sanitized_event not in allowed_events:
            sanitized_event = "FILTERED_GENERIC_SECURITY_EVENT"

        # 1. Isulat sa physical rotating local file structure
        log_payload = f"IP: {client_ip} | EVENT: {sanitized_event} | DESC: {sanitized_desc}"
        app_logger.info(log_payload)

        # 2. HARDENING FIX: Isinama ang description para mai-save din sa SQL model integration
        new_log = CameraLog(
            event=sanitized_event, 
            description=sanitized_desc,  # Siguraduhing may ganitong field sa iyong db.Model definition
            ip_address=client_ip
        )
        db.session.add(new_log)
        db.session.commit()
        
    except Exception:
        db.session.rollback() # Siguraduhing walang maiiwang hanging transaction state

# =====================================================================
# CORE SECURED ROUTE ENDPOINTS & HANDSHAKES
# =====================================================================
@logger_bp.route('/view/audit_trail', methods=['GET'])
@secure_admin_required
def view_audit_trail():
    try:
        logs_query = CameraLog.query.order_by(CameraLog.id.desc()).limit(100).all()
        
        log_list = []
        for item in logs_query:
            log_list.append({
                "id": item.id,
                "event": item.event,
                "description": getattr(item, 'description', 'No Context Data Saved'),
                "ip_address": item.ip_address,
                "timestamp": item.timestamp.strftime("%Y-%m-%d %H:%M:%S") if getattr(item, 'timestamp', None) else "N/A"
            })
            
        response = jsonify({"status": "success", "audit_data": log_list})
        response.headers["Content-Disposition"] = "inline"
        return response

    except Exception:
        return abort(500, description="Internal Server Error: Secure Isolation Execution Blocked.")

# =====================================================================
# EXTRA HARDENING MIDDLEWARE: Cross-Origin & Protocol Protection
# =====================================================================
@logger_bp.after_request
def apply_endpoint_cors_lockdown(response):
    # HARDENING FIX: Ganap na pinapatay ang cross-origin visibility.
    # Tinanggal ang "null" value assignment para maiwasan ang local sandboxed execution bypasses.
    if "Access-Control-Allow-Origin" in response.headers:
        del response.headers["Access-Control-Allow-Origin"]
        
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response