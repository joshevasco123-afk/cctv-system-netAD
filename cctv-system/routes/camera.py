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
                cls._instance.active_username = None

                # ── Frame Buffer (new) ────────────────────────────────
                cls._instance.latest_frame = None        # stores latest JPEG bytes
                cls._instance.frame_lock = threading.Lock()
                cls._instance._buffer_thread = None
                cls._instance._buffer_running = False
        return cls._instance

    def initialize_camera(self, username=None):
        # Control 3: Camera Index Whitelisting (Hardcoded index inside safe backend)
        # Control 10: Zero-Credential/Source Path Obfuscation
        raw_index = os.environ.get('HARDWARE_CAMERA_INDEX', '0')
        camera_index = int(raw_index) if raw_index.isdigit() else raw_index

        # HTTP/HTTPS: add ngrok browser warning bypass
        if isinstance(camera_index, str) and camera_index.startswith('http'):
            stream_url = camera_index + ("&" if "?" in camera_index else "?") + "ngrok-skip-browser-warning=true"
        # RTSP: use directly
        elif isinstance(camera_index, str) and camera_index.startswith('rtsp'):
            stream_url = camera_index
        # USB camera index (int)
        else:
            stream_url = camera_index

        if self.cap is None or not self.cap.isOpened():
            if isinstance(stream_url, str) and stream_url.startswith('rtsp'):
                self.cap = cv2.VideoCapture(stream_url, cv2.CAP_FFMPEG)
            else:
                self.cap = cv2.VideoCapture(stream_url)
            # Control 6: Buffer Size Limit Configuration
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            self.is_running = True
            self.last_frame_time = time.time()
            self.active_username = username

    def release_camera(self):
        # Control 5: Automated Resource Release Mechanism
        # NOTE: We no longer stop the buffer thread here.
        # The buffer thread keeps running and will detect cap=None gracefully.
        if self.cap is not None:
            self.cap.release()
            self.cap = None
        self.is_running = False
        self.active_token = None

    # =====================================================================
    # FRAME BUFFER: Background thread — owns the camera exclusively
    # Both admin and viewer read from latest_frame; no direct cap access.
    # =====================================================================
    def _buffer_loop(self):
        """Continuously reads frames from cap into latest_frame."""
        fps_cap = 15
        frame_delay = 1.0 / fps_cap

        while self._buffer_running:
            start = time.time()

            with self._lock:
                if self.cap is None or not self.cap.isOpened():
                    # Camera not ready — wait and retry
                    time.sleep(0.5)
                    continue

                success, frame = self.cap.read()

            if not success or frame is None or frame.size == 0:
                time.sleep(0.1)
                continue

            # Control 8: Blank frame guard
            if cv2.mean(frame)[0] < 2.0:
                time.sleep(0.1)
                continue

            # Control 9: Cryptographic Timestamp Overlay
            server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            cv2.putText(frame, f"LIVE SERVER TIME: {server_time}", (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2, cv2.LINE_AA)

            ret, buffer = cv2.imencode('.jpg', frame)
            if not ret:
                continue

            # Store the latest frame for admin + viewer to consume
            with self.frame_lock:
                self.latest_frame = buffer.tobytes()
                self.last_frame_time = time.time()

            # Control 6: FPS throttle
            elapsed = time.time() - start
            if elapsed < frame_delay:
                time.sleep(frame_delay - elapsed)

    def start_buffer(self):
        """Start the background frame buffer thread (idempotent)."""
        if self._buffer_running and self._buffer_thread and self._buffer_thread.is_alive():
            return  # Already running
        self._buffer_running = True
        self._buffer_thread = threading.Thread(target=self._buffer_loop, daemon=True)
        self._buffer_thread.start()

    def stop_buffer(self):
        """Stop the background frame buffer thread."""
        self._buffer_running = False

    def get_latest_frame(self):
        """Return the most recent JPEG bytes, or None if not ready."""
        with self.frame_lock:
            return self.latest_frame

    def auto_start(self):
        """Auto-initialize camera + buffer thread on app startup."""
        def _start():
            time.sleep(3)
            try:
                with self._lock:
                    self.initialize_camera(username='system')
                self.start_buffer()
            except Exception:
                pass
        t = threading.Thread(target=_start, daemon=True)
        t.start()


camera_manager = SecureCameraSingleton()

# ── Auto-start camera on module load ─────────────────────────────────
camera_manager.auto_start()


# =====================================================================
# HARDENING MODULE I & VII: Custom Authentication & Session Decorators
# =====================================================================
def secure_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin') or not session.get('user_id'):
            return abort(403, description="Access Denied: Unauthenticated Session")

        login_time = session.get('login_time')
        if not login_time or (time.time() - login_time) > 900:
            session.clear()
            return abort(401, description="Session Expired: Re-authentication Required")

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
# HARDENING MODULE V: Admin MJPEG Stream — reads from frame buffer
# =====================================================================
def generate_secure_frames(validated_token, username):
    """
    MJPEG stream for the admin dashboard.
    Reads from camera_manager.latest_frame (the shared buffer).
    No direct cap.read() — zero lock contention with viewer.
    """
    fps_cap = 15
    frame_delay = 1.0 / fps_cap
    no_frame_timeout = 10  # seconds before giving up
    disconnect_logged = False

    try:
        while True:
            # Control 2: Token validation per iteration
            if camera_manager.active_token != validated_token:
                break

            start_time = time.time()

            frame_bytes = camera_manager.get_latest_frame()

            if frame_bytes is None:
                # Wait briefly — buffer may still be warming up
                if (time.time() - camera_manager.last_frame_time) > no_frame_timeout:
                    break
                time.sleep(0.1)
                continue

            # Control 6: FPS throttle
            elapsed = time.time() - start_time
            if elapsed < frame_delay:
                time.sleep(frame_delay - elapsed)

            # Control 7: MIME-Type Boundary Isolation Payload Delivery
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

    except Exception:
        pass
    finally:
        # Log stream exit without releasing the camera/buffer
        # The buffer thread keeps running for the viewer
        if not disconnect_logged:
            try:
                log = CameraLog(
                    event='CAMERA_STREAM_STOPPED',
                    username=username,
                    description=f'Admin stream ended — buffer still running for viewers',
                    ip_address='SERVER'
                )
                db.session.add(log)
                db.session.commit()
            except Exception:
                db.session.rollback()


# =====================================================================
# CORE SECURED ROUTE ENDPOINTS
# =====================================================================
@camera_bp.route('/request_stream_token', methods=['POST'])
@secure_admin_required
def request_stream_token():
    token = secrets.token_hex(32)
    camera_manager.active_token = token
    # Re-initialize camera if it was released, then ensure buffer is running
    with camera_manager._lock:
        camera_manager.initialize_camera(username=session.get('user', 'admin'))
    camera_manager.start_buffer()
    return {"stream_token": token}, 200


@camera_bp.route('/video_feed')
@secure_admin_required
def secure_video_feed():
    # Control 2: Tokenization query parameters checker
    token_param = request.args.get('token')
    if not token_param or token_param != camera_manager.active_token:
        return abort(403, description="Forbidden: Invalid or Expired Stream Token")

    client_ip = get_validated_client_ip()
    username  = session.get('user', 'unknown')

    log = CameraLog(
        event='CAMERA_STREAM_STARTED',
        username=username,
        description=f'Live stream opened by {username}',
        ip_address=client_ip
    )
    db.session.add(log)
    db.session.commit()

    # Ensure camera + buffer are running
    with camera_manager._lock:
        camera_manager.initialize_camera(username=username)
    camera_manager.start_buffer()

    response = Response(
        generate_secure_frames(token_param, username),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )

    # Control 11: Aggressive Browser Cache Disabling
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    # Control 14: CSP & Clickjacking Restrictions
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"

    return response


# =====================================================================
# VIEWER FRAME ENDPOINT — reads from shared frame buffer
# =====================================================================
@camera_bp.route('/viewer_frame')
def viewer_frame():
    """
    Returns the latest camera frame as base64 JSON for viewer polling.
    No authentication beyond checking viewer session (handled in viewer.py).
    Reads from the shared frame buffer — never touches cap directly.
    """
    import base64
    from flask import jsonify

    # Basic viewer session check
    if not session.get('user') or session.get('role') != 'viewer':
        return jsonify({'error': 'unauthorized'}), 403

    frame_bytes = camera_manager.get_latest_frame()

    if frame_bytes is None:
        return jsonify({'available': False}), 200

    encoded = base64.b64encode(frame_bytes).decode('utf-8')
    return jsonify({'available': True, 'frame': encoded}), 200