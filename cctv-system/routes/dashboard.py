from flask import Blueprint, render_template, session, redirect, url_for, request, abort
from database.models import db, LoginLog, CameraLog, AlertLog, ActivityLog, BlockedIP
from functools import wraps
from datetime import datetime, date
from sqlalchemy import func

dashboard_bp = Blueprint('dashboard', __name__)

# ─── Decorators ────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("auth.home"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ─── Admin dashboard ───────────────────────────────────────────────────────────
@dashboard_bp.route("/dashboard")
@login_required
@admin_required
def dashboard():
    today_start = datetime.combine(date.today(), datetime.min.time())

    # Login attempts today
    login_attempts_today = LoginLog.query.filter(
        LoginLog.timestamp >= today_start
    ).count()

    # Failed logins today
    failed_logins_today = LoginLog.query.filter(
        LoginLog.timestamp >= today_start,
        LoginLog.status == 'failed'
    ).count()

    # ── Blocked IPs (from BlockedIP table) ────────────────────────────
    blocked_ips_db    = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    blocked_ips_count = len(blocked_ips_db)
    blocked_ips_list  = [entry.ip_address for entry in blocked_ips_db]
    blocked_ips_set   = set(blocked_ips_list)   # for O(1) lookup in the logs table

    # Active sessions = unique users with successful login today
    from flask import current_app
    active_sessions = sum(
    1 for key in current_app.config
    if key.startswith("ACTIVE_SESSION_")
    and current_app.config[key] is not None
)

    # Active cameras
    active_cameras = 0
    latest_cam = CameraLog.query.order_by(CameraLog.timestamp.desc()).first()
    if latest_cam and latest_cam.event in [
        'started', 'SECURE_STREAM_STARTED', 'STREAM_STARTED', 'CAMERA_STREAM_STARTED'
    ]:
        active_cameras = 1

    # AI Alerts today
    alerts_today = AlertLog.query.filter(
        AlertLog.timestamp >= today_start
    ).count()

    # Suspicious activity count today
    suspicious_today = ActivityLog.query.filter(
        ActivityLog.timestamp >= today_start,
        ActivityLog.severity == 'suspicious'
    ).count()

    # Recent alert logs
    recent_alerts = AlertLog.query.order_by(AlertLog.timestamp.desc()).limit(10).all()

    # Activity logs (admin actions + suspicious)
    activity_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(50).all()

    # Login logs and camera logs
    login_logs  = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(50).all()
    camera_logs = CameraLog.query.order_by(CameraLog.timestamp.desc()).limit(20).all()

    register_error   = request.args.get("register_error")
    register_success = request.args.get("register_success")

    return render_template("dashboard.html",
                           user=session["user"],
                           login_logs=login_logs,
                           camera_logs=camera_logs,
                           recent_alerts=recent_alerts,
                           activity_logs=activity_logs,
                           register_error=register_error,
                           register_success=register_success,
                           login_attempts_today=login_attempts_today,
                           failed_logins_today=failed_logins_today,
                           blocked_ips_count=blocked_ips_count,
                           blocked_ips_list=blocked_ips_list,
                           blocked_ips_set=blocked_ips_set,
                           blocked_ips_db=blocked_ips_db,
                           active_sessions=active_sessions,
                           active_cameras=active_cameras,
                           alerts_today=alerts_today,
                           suspicious_today=suspicious_today)
