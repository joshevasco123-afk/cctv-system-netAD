from flask import Blueprint, request, session, jsonify
from database.models import db, BlockedIP, ActivityLog
from functools import wraps
import re

blocked_bp = Blueprint('blocked', __name__, url_prefix='/blocked')

# ── Helpers ───────────────────────────────────────────────────────────

def _admin_required(f):
    """Reuse the same session checks already established in app.py."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('is_admin') or not session.get('user_id'):
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        return f(*args, **kwargs)
    return wrapper


_IP_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'          # IPv4
    r'|^([0-9a-fA-F]{0,4}:){2,7}'        # IPv6 (loose check)
    r'[0-9a-fA-F]{0,4}$'
)

def _valid_ip(ip: str) -> bool:
    return bool(ip and _IP_RE.match(ip.strip()))


def _sanitize_ip(ip: str) -> str:
    return "".join(c for c in ip if c.isalnum() or c in ['.', ':'])


def _get_client_ip() -> str:
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or 'UNKNOWN'


# ── Block endpoint ────────────────────────────────────────────────────

@blocked_bp.route('/block', methods=['POST'])
@_admin_required
def block_ip():
    data = request.get_json(silent=True) or {}
    raw_ip = data.get('ip_address', '').strip()
    ip = _sanitize_ip(raw_ip)

    if not _valid_ip(ip):
        return jsonify({'success': False, 'message': 'Invalid IP address.'}), 400

    # Don't allow blocking server's own loopback
    if ip.startswith('127.') or ip == '::1':
        return jsonify({'success': False, 'message': 'Cannot block loopback address.'}), 400

    # Already blocked?
    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    if existing:
        return jsonify({'success': False, 'message': f'{ip} is already blocked.'}), 409

    admin_user = session.get('user', 'admin')
    client_ip  = _get_client_ip()

    try:
        entry = BlockedIP(
            ip_address=ip,
            blocked_by=admin_user,
            reason=data.get('reason') or 'Manual block by admin'
        )
        db.session.add(entry)

        # Audit trail
        log = ActivityLog(
            event='IP_BLOCKED',
            description=f'Admin {admin_user} blocked {ip}',
            ip_address=client_ip,
            severity='suspicious'
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({'success': True, 'message': f'{ip} has been blocked.'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Database error. Please try again.'}), 500


# ── Unblock endpoint ──────────────────────────────────────────────────

@blocked_bp.route('/unblock', methods=['POST'])
@_admin_required
def unblock_ip():
    data = request.get_json(silent=True) or {}
    raw_ip = data.get('ip_address', '').strip()
    ip = _sanitize_ip(raw_ip)

    if not _valid_ip(ip):
        return jsonify({'success': False, 'message': 'Invalid IP address.'}), 400

    entry = BlockedIP.query.filter_by(ip_address=ip).first()
    if not entry:
        return jsonify({'success': False, 'message': f'{ip} is not in the block list.'}), 404

    admin_user = session.get('user', 'admin')
    client_ip  = _get_client_ip()

    try:
        db.session.delete(entry)

        log = ActivityLog(
            event='IP_UNBLOCKED',
            description=f'Admin {admin_user} unblocked {ip}',
            ip_address=client_ip,
            severity='info'
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({'success': True, 'message': f'{ip} has been unblocked.'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Database error. Please try again.'}), 500