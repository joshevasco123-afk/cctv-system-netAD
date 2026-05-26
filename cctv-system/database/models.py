from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='viewer')
    otp_secret = db.Column(db.String(32), nullable=True)   # ← NEW: per-user TOTP secret
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginLog(db.Model):
    __tablename__ = 'login_logs'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'success' or 'failed'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class CameraLog(db.Model):
    __tablename__ = 'camera_logs'
    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(100), nullable=False)   # widened to 100 for longer event names
    username = db.Column(db.String(100), nullable=True) # who triggered the event (None = system)
    description = db.Column(db.String(255), nullable=True)  # human-readable detail
    ip_address = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class AlertLog(db.Model):
    __tablename__ = 'alert_logs'
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    severity = db.Column(db.String(20), default='medium')  # 'low', 'medium', 'high'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), default='info')  # 'info' or 'suspicious'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ── NEW: Persistent IP block list ─────────────────────────────────────
class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    blocked_by = db.Column(db.String(100), nullable=True)   # admin username who blocked it
    reason = db.Column(db.String(255), nullable=True)       # optional reason / auto-filled
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)