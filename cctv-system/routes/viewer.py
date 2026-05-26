from flask import Blueprint, render_template, session, redirect, url_for
from functools import wraps

viewer_bp = Blueprint('viewer', __name__)

def viewer_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user") or session.get("role") != "viewer":
            return redirect(url_for("viewer_login"))
        return f(*args, **kwargs)
    return decorated

@viewer_bp.route("/viewer")
@viewer_login_required
def viewer():
    return render_template("viewer.html", username=session.get("user"))