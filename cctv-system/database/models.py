from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='viewer')
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
    event = db.Column(db.String(50), nullable=False)  # 'started' or 'stopped'
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