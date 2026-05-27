from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone, timedelta

db = SQLAlchemy()

PH_TZ = timezone(timedelta(hours=8))

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='viewer')
    otp_secret = db.Column(db.String(32), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(PH_TZ))

class LoginLog(db.Model):
    __tablename__ = 'login_logs'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(PH_TZ))

class CameraLog(db.Model):
    __tablename__ = 'camera_logs'
    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(PH_TZ))

class AlertLog(db.Model):
    __tablename__ = 'alert_logs'
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    severity = db.Column(db.String(20), default='medium')
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(PH_TZ))

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    event = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), default='info')
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(PH_TZ))

class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    blocked_by = db.Column(db.String(100), nullable=True)
    reason = db.Column(db.String(255), nullable=True)
    blocked_at = db.Column(db.DateTime, default=lambda: datetime.now(PH_TZ))