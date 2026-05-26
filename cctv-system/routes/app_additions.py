# ======================================================================
# ADD THESE TWO IMPORTS to the existing blueprint imports block
# (right after: from routes.camera import camera_bp)
# ======================================================================

from routes.blocked import blocked_bp
from routes.viewer import viewer_bp

app.register_blueprint(blocked_bp)
app.register_blueprint(viewer_bp)


# ======================================================================
# VIEWER LOGIN — STEP 1: Username + Password
# Add this route AFTER the existing /logout route
# ======================================================================

@app.route("/viewer-login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def viewer_login():
    from database.models import User
    client_ip = get_sanitized_ip()
    now = time.time()

    # ── IP Lockout check (reuses same tracker as admin) ──────────────
    if client_ip in IP_FAILED_ATTEMPTS:
        failures, lockout_time = IP_FAILED_ATTEMPTS[client_ip]
        if failures >= 10:
            if now - lockout_time < 300:
                return make_response(render_template("viewer_login.html",
                    error="IP temporarily locked out. Try again later."))
            else:
                IP_FAILED_ATTEMPTS[client_ip] = [0, 0]

    if request.method == "POST":
        input_user = "".join(c for c in request.form.get("username", "") if c.isalnum() or c == "_")
        input_pass = request.form.get("password", "")

        # Progressive delay
        if client_ip in IP_FAILED_ATTEMPTS:
            failures = IP_FAILED_ATTEMPTS[client_ip][0]
            if failures > 0:
                time.sleep(min(0.5 * failures, 10))

        user = User.query.filter_by(username=input_user, role="viewer").first()

        peppered_input = input_pass + PEPPER
        password_match = (
            user is not None
            and bcrypt.check_password_hash(user.password, peppered_input)
        )

        if user and password_match:
            session["viewer_otp_pending"] = True
            session["viewer_otp_user"]    = user.username
            session["viewer_otp_ip"]      = client_ip
            return redirect(url_for("viewer_verify_otp"))
        else:
            if client_ip not in IP_FAILED_ATTEMPTS:
                IP_FAILED_ATTEMPTS[client_ip] = [1, now]
            else:
                IP_FAILED_ATTEMPTS[client_ip][0] += 1
                IP_FAILED_ATTEMPTS[client_ip][1] = now

            log = CameraLog(
                event=f"UNAUTHORIZED_VIEWER_LOGIN_ATTEMPT_USER_{input_user}",
                ip_address=client_ip
            )
            db.session.add(log)
            db.session.commit()

            return make_response(render_template("viewer_login.html",
                error="Invalid credentials."))

    session.pop("viewer_otp_pending", None)
    session.pop("viewer_otp_user", None)
    session.pop("viewer_otp_ip", None)
    return render_template("viewer_login.html")


# ======================================================================
# VIEWER LOGIN — STEP 2: OTP Verification
# ======================================================================

@app.route("/viewer-verify-otp", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def viewer_verify_otp():
    from database.models import User
    if not session.get("viewer_otp_pending"):
        return redirect(url_for("viewer_login"))

    client_ip = get_sanitized_ip()
    now = time.time()

    if request.method == "POST":
        input_otp  = request.form.get("otp", "").strip()
        username   = session.get("viewer_otp_user")
        user       = User.query.filter_by(username=username, role="viewer").first()

        if not user or not user.otp_secret:
            return make_response(render_template("otp.html",
                error="Account not configured for MFA. Contact admin."))

        totp      = pyotp.TOTP(user.otp_secret)
        otp_match = totp.verify(input_otp, valid_window=1)

        if otp_match:
            session.pop("viewer_otp_pending", None)
            session.pop("viewer_otp_user", None)
            session.pop("viewer_otp_ip", None)

            secure_session_destruct()
            session.permanent    = True
            session["user"]      = username
            session["role"]      = "viewer"
            session["user_id"]   = f"viewer_{user.id}"
            session["login_time"]    = now
            session["last_activity"] = now
            session["session_token"] = secrets.token_hex(32)

            app.config[f"ACTIVE_SESSION_viewer_{user.id}"] = session["session_token"]

            log = CameraLog(
                event="VIEWER_LOGIN_SUCCESSFUL",
                username=username,
                ip_address=client_ip
            )
            db.session.add(log)
            db.session.commit()

            return redirect(url_for("viewer.viewer"))

        else:
            if client_ip not in IP_FAILED_ATTEMPTS:
                IP_FAILED_ATTEMPTS[client_ip] = [1, now]
            else:
                IP_FAILED_ATTEMPTS[client_ip][0] += 1
                IP_FAILED_ATTEMPTS[client_ip][1] = now

            log = CameraLog(
                event=f"INVALID_VIEWER_OTP_ATTEMPT_USER_{username}",
                ip_address=client_ip
            )
            db.session.add(log)
            db.session.commit()

            return make_response(render_template("otp.html",
                error="Invalid or expired code."))

    return render_template("otp.html")