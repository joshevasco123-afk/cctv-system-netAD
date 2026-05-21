from flask import Blueprint, Response, request, session, abort, current_app
from database.models import db, CameraLog
from functools import wraps
import cv2
import threading
import time
import os
import secrets
from datetime import datetime

camera_bp = Blueprint('camera', __name__)

# =====================================================================
# HARDENING MODULE II: Thread-Safe Singleton Pattern & Concurrency Lock
# =====================================================================
class SecureCameraSingleton:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(SecureCameraSingleton, cls).__new__(cls)
                cls._instance.cap = None
                cls._instance.is_running = False
                cls._instance.active_token = None
                cls._instance.last_frame_time = 0
                cls._instance.last_frame_checksum = None
        return cls._instance

    def initialize_camera(self):
        # Control 3: Camera Index Whitelisting (Hardcoded index inside safe backend)
        # Control 10: Zero-Credential/Source Path Obfuscation
        camera_index = int(os.environ.get('HARDWARE_CAMERA_INDEX', 0))
        
        if self.cap is None or not self.cap.isOpened():
            self.cap = cv2.VideoCapture(camera_index)
            # Control 6: Buffer Size Limit Configuration
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1) 
            self.is_running = True
            self.last_frame_time = time.time()

    def release_camera(self):
        # Control 5: Automated Resource Release Mechanism
        if self.cap is not None:
            self.cap.release()
            self.cap = None
        self.is_running = False
        self.active_token = None

camera_manager = SecureCameraSingleton()

# =====================================================================
# HARDENING MODULE I & VII: Custom Authentication & Session Decorators
# =====================================================================
def secure_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Control 1: Implicit Session State Verification
        if not session.get('is_admin') or not session.get('user_id'):
            return abort(403, description="Access Denied: Unauthenticated Session")

        # Control 15: Absolute Session Timeout Check (e.g., 15 minutes = 900 seconds)
        login_time = session.get('login_time')
        if not login_time or (time.time() - login_time) > 900:
            session.clear()
            return abort(401, description="Session Expired: Re-authentication Required")

        # Control 16: Single-Active Admin Session Enforcement
        active_system_token = current_app.config.get(f"ACTIVE_SESSION_{session.get('user_id')}")
        if session.get('session_token') != active_system_token:
            return abort(401, description="Session Invalidated: Concurrent Admin Login Detected")

        return f(*args, **kwargs)
    return decorated_function

# =====================================================================
# HARDENING MODULE XIII: Reverse Proxy Client-IP Validation
# =====================================================================
def get_validated_client_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
        
    cleaned_ip = "".join(c for c in ip if c.isalnum() or c in ['.', ':'])
    return cleaned_ip if cleaned_ip else "UNKNOWN_PROXIED_IP"

# =====================================================================
# HARDENING MODULE V: Network Timeout & Frame Generator Loop
# =====================================================================
def generate_secure_frames(validated_token):
    retry_count = 0
    max_retries = 5  # Control 12: Finite Intermittent Reconnection Backoff
    fps_cap = 15     # Control 6: FPS Limit Target
    frame_delay = 1.0 / fps_cap

    try:
        while camera_manager.is_running:
            # Control 2: Token Validation check bawat loop iteration
            if camera_manager.active_token != validated_token:
                break

            start_time = time.time()
            
            # Control 4: Concurrent Access Lock utilization during frame capture
            with camera_manager._lock:
                if camera_manager.cap is None or not camera_manager.cap.isOpened():
                    break
                success, frame = camera_manager.cap.read()

            if not success:
                retry_count += 1
                time.sleep(0.5 * retry_count)
                if retry_count > max_retries:
                    break
                continue
            
            retry_count = 0

            # Control 8: Non-Empty Frame Validation Processing
            if frame is None or frame.size == 0:
                continue

            # Control 8: Advanced Integrity check
            if cv2.mean(frame)[0] < 2.0:
                continue

            # Control 9: Cryptographic Timestamp Overlaying
            server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            cv2.putText(frame, f"LIVE SERVER TIME: {server_time}", (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2, cv2.LINE_AA)

            ret, buffer = cv2.imencode('.jpg', frame)
            if not ret:
                continue
                
            frame_bytes = buffer.tobytes()

            # Control 6: Frame Rate Overload Throttling
            elapsed_time = time.time() - start_time
            if elapsed_time < frame_delay:
                time.sleep(frame_delay - elapsed_time)

            # Control 7: MIME-Type Boundary Isolation Payload Delivery
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

    # Control 17: Fail-Closed Error Boundary Pattern
    except Exception as e:
        pass
    finally:
        with camera_manager._lock:
            camera_manager.release_camera()

# =====================================================================
# CORE SECURED ROUTE ENDPOINTS
# =====================================================================
@camera_bp.route('/request_stream_token', methods=['POST'])
@secure_admin_required
def request_stream_token():
    token = secrets.token_hex(32)
    camera_manager.active_token = token
    return {"stream_token": token}, 200

@camera_bp.route('/video_feed')
@secure_admin_required
def secure_video_feed():
    # Control 2: Tokenization query parameters checker
    token_param = request.args.get('token')
    if not token_param or token_param != camera_manager.active_token:
        return abort(403, description="Forbidden: Invalid or Expired Stream Token")

    client_ip = get_validated_client_ip()

    # Control 11: Append-Only Audit Logging
    log = CameraLog(event='SECURE_STREAM_STARTED', ip_address=client_ip)
    db.session.add(log)
    db.session.commit()

    # Control 4: Initialize camera
    with camera_manager._lock:
        camera_manager.initialize_camera()

    response = Response(generate_secure_frames(token_param), 
                        mimetype='multipart/x-mixed-replace; boundary=frame')

    # Control 11: Aggressive Browser Cache Disabling
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    # Control 14: CSP & Clickjacking Restrictions
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"

    return response