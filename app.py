"""
UISP-Lite — Unified Identity and Signature Platform (scaled-down MVP)
Stack: Python (Flask) + SQLite + HTML/CSS/JS + OpenCV visual crypto codes.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000
"""

import os
import io
import re
import json
import hashlib
import secrets as pysecrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, send_file, abort, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import database as db
import crypto_code

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
QR_DIR = os.path.join(BASE_DIR, "static", "qr")
UPLOAD_DIR = os.path.join(BASE_DIR, "instance", "uploads")
ALLOWED_UPLOAD_EXT = {"png", "jpg", "jpeg"}

os.makedirs(QR_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("UISP_SECRET_KEY", pysecrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 MB upload limit

GENESIS_PREFIX = "UISP-GENESIS::"


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def now_iso():
    return datetime.utcnow().isoformat()


def audit(event_type, user_id=None, metadata=None, success=True):
    conn = db.get_db()
    conn.execute(
        "INSERT INTO audit_logs (event_type, user_id, metadata, success, created_at) VALUES (?, ?, ?, ?, ?)",
        (event_type, user_id, json.dumps(metadata or {}), 1 if success else 0, now_iso()),
    )
    conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    if "user_id" not in session:
        return None
    conn = db.get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return row


def allowed_upload(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_UPLOAD_EXT


def workflow_hash(previous_hash, application_id, actor_uisp_id, action, timestamp, payload=""):
    raw = f"{previous_hash}|{application_id}|{actor_uisp_id}|{action}|{timestamp}|{payload}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def append_workflow(conn, application_id, actor_uisp_id, action, payload="", comment=None):
    last = conn.execute(
        "SELECT signature_hash FROM application_workflows WHERE application_id = ? "
        "ORDER BY id DESC LIMIT 1",
        (application_id,),
    ).fetchone()
    if last:
        previous_hash = last["signature_hash"]
    else:
        previous_hash = hashlib.sha256((GENESIS_PREFIX + application_id).encode("utf-8")).hexdigest()

    ts = now_iso()
    sig = workflow_hash(previous_hash, application_id, actor_uisp_id, action, ts, payload)
    conn.execute(
        """INSERT INTO application_workflows
           (application_id, action_by_uisp_id, action_taken, previous_hash, signature_hash, comment, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (application_id, actor_uisp_id, action, previous_hash, sig, comment, ts),
    )
    return sig


def verify_chain(application_id):
    conn = db.get_db()
    rows = conn.execute(
        "SELECT * FROM application_workflows WHERE application_id = ? ORDER BY id ASC",
        (application_id,),
    ).fetchall()
    conn.close()
    expected_prev = hashlib.sha256((GENESIS_PREFIX + application_id).encode("utf-8")).hexdigest()
    for r in rows:
        if r["previous_hash"] != expected_prev:
            return False, f"Chain broken at workflow #{r['id']} (previous_hash mismatch)."
        expected_prev = r["signature_hash"]
    return True, "Chain intact." if rows else "No workflow events yet."


def user_public_dict(row):
    return {
        "uisp_id": row["uisp_id"],
        "first_name": row["first_name"],
        "last_name": row["last_name"],
        "designation": row["designation"],
        "region": row["region"],
    }


# ----------------------------------------------------------------------
# Auth routes
# ----------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        designation = request.form.get("designation", "Member").strip() or "Member"
        region = request.form.get("region", "").strip()

        errors = []
        if not first_name or not last_name:
            errors.append("First and last name are required.")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            errors.append("Enter a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")

        conn = db.get_db()
        if not errors and conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            errors.append("An account with this email already exists.")

        if errors:
            conn.close()
            for e in errors:
                flash(e, "error")
            return render_template("register.html")

        uisp_id = db.generate_uisp_id()
        org_row = conn.execute("SELECT id FROM organizations LIMIT 1").fetchone()
        conn.execute(
            """INSERT INTO users (uisp_id, first_name, last_name, email, password_hash,
               designation, region, org_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (uisp_id, first_name, last_name, email, generate_password_hash(password),
             designation, region, org_row["id"] if org_row else None, now_iso()),
        )
        conn.commit()
        user_id = conn.execute("SELECT id FROM users WHERE uisp_id = ?", (uisp_id,)).fetchone()["id"]

        # Generate and store this user's permanent 80-bit visual code
        code_path = os.path.join(QR_DIR, f"{uisp_id}.png")
        crypto_code.generate_user_code(uisp_id, code_path)
        conn.execute("UPDATE users SET crypto_code_path = ? WHERE id = ?",
                     (f"qr/{uisp_id}.png", user_id))
        conn.commit()
        conn.close()

        audit("registration", user_id=user_id, metadata={"uisp_id": uisp_id})
        flash(f"Account created. Your UISP_ID is {uisp_id}. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = db.get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            audit("login", user_id=user["id"])
            return redirect(url_for("dashboard"))

        audit("failed_login", metadata={"email": email}, success=False)
        flash("Invalid email or password.", "error")
        return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        audit("logout", user_id=session["user_id"])
    session.clear()
    return redirect(url_for("login"))


# ----------------------------------------------------------------------
# Dashboard (dynamic bento grid driven by ?view=)
# ----------------------------------------------------------------------

VALID_VIEWS = {
    "profile", "new", "pending", "previous", "unknown",
    "reject", "org", "verify", "settings",
}


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    view = request.args.get("view", "profile")
    if view not in VALID_VIEWS:
        view = "profile"

    conn = db.get_db()
    context = {"user": user, "view": view}

    if view == "profile":
        context["own_code_url"] = url_for("static", filename=user["crypto_code_path"]) if user["crypto_code_path"] else None

    elif view == "new":
        context["templates"] = conn.execute("SELECT * FROM application_templates ORDER BY id").fetchall()
        context["org_members"] = conn.execute(
            "SELECT uisp_id, first_name, last_name, email FROM users WHERE id != ? ORDER BY first_name",
            (user["id"],),
        ).fetchall()

    elif view == "pending":
        sent = conn.execute(
            "SELECT * FROM applications WHERE sender_id = ? AND status = 'Pending' ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
        received = conn.execute(
            "SELECT * FROM applications WHERE receiver_id = ? AND status = 'Pending' ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
        context["sent"] = sent
        context["received"] = received

    elif view == "previous":
        rows = conn.execute(
            "SELECT * FROM applications WHERE (sender_id = ? OR receiver_id = ?) AND status != 'Pending' "
            "ORDER BY updated_at DESC",
            (user["id"], user["id"]),
        ).fetchall()
        context["applications"] = rows

    elif view == "unknown":
        # "Unknown" = received from a sender outside this user's organization
        rows = conn.execute(
            """SELECT a.*, u.first_name AS s_first, u.last_name AS s_last, u.uisp_id AS s_uisp,
                      u.designation AS s_designation, u.region AS s_region, o.org_name AS s_org
               FROM applications a
               JOIN users u ON u.id = a.sender_id
               LEFT JOIN organizations o ON o.id = u.org_id
               WHERE a.receiver_id = ? AND (u.org_id IS NULL OR u.org_id != ?)
               ORDER BY a.created_at DESC""",
            (user["id"], user["org_id"]),
        ).fetchall()
        context["applications"] = rows

    elif view == "reject":
        rows = conn.execute(
            "SELECT * FROM applications WHERE (sender_id = ? OR receiver_id = ?) AND status = 'Rejected' "
            "ORDER BY updated_at DESC",
            (user["id"], user["id"]),
        ).fetchall()
        context["applications"] = rows

    elif view == "org":
        members = conn.execute(
            """SELECT u.*, o.org_name FROM users u LEFT JOIN organizations o ON o.id = u.org_id
               WHERE u.org_id = ? ORDER BY u.designation, u.first_name""",
            (user["org_id"],),
        ).fetchall()
        context["members"] = members

    elif view == "settings":
        logs = conn.execute(
            "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT 30",
            (user["id"],),
        ).fetchall()
        context["logs"] = logs

    conn.close()
    return render_template("dashboard.html", **context)


# ----------------------------------------------------------------------
# Global search (header)
# ----------------------------------------------------------------------

@app.route("/api/search")
@login_required
def api_search():
    q = request.args.get("q", "").strip()
    if len(q) < 2:
        return jsonify({"results": []})
    conn = db.get_db()
    like = f"%{q}%"
    users = conn.execute(
        """SELECT uisp_id, first_name, last_name, designation, region FROM users
           WHERE uisp_id LIKE ? OR first_name LIKE ? OR last_name LIKE ? OR region LIKE ?
           LIMIT 10""",
        (like, like, like, like),
    ).fetchall()
    orgs = conn.execute(
        "SELECT org_name, registration_number FROM organizations WHERE org_name LIKE ? LIMIT 10",
        (like,),
    ).fetchall()
    conn.close()
    return jsonify({
        "results": {
            "users": [dict(u) for u in users],
            "organizations": [dict(o) for o in orgs],
        }
    })


# ----------------------------------------------------------------------
# Applications — create / view / approve / reject
# ----------------------------------------------------------------------

CATEGORY_CODE = {
    "Normal": "GEN", "Fund Request": "FIN", "Notices": "NOT",
    "Leave": "LVE", "Approval": "APR", "Custom Application": "CUS",
}


@app.route("/applications/new", methods=["POST"])
@login_required
def create_application():
    user = current_user()
    template_id = request.form.get("template_id")
    title = request.form.get("title", "").strip()
    content_body = request.form.get("content_body", "").strip()
    receiver_uisp_id = request.form.get("receiver_uisp_id", "").strip().upper()

    if not title or not content_body or not receiver_uisp_id:
        flash("Title, content and receiver are required.", "error")
        return redirect(url_for("dashboard", view="new"))

    conn = db.get_db()
    template = conn.execute("SELECT * FROM application_templates WHERE id = ?", (template_id,)).fetchone()
    receiver = conn.execute("SELECT * FROM users WHERE uisp_id = ?", (receiver_uisp_id,)).fetchone()

    if not receiver:
        conn.close()
        flash("No user found with that Receiver UISP_ID.", "error")
        return redirect(url_for("dashboard", view="new"))

    category_code = CATEGORY_CODE.get(template["template_name"] if template else "Normal", "GEN")
    application_id = db.generate_application_id(category_code)
    ts = now_iso()

    conn.execute(
        """INSERT INTO applications
           (application_id, template_id, title, content_body, sender_id, receiver_id,
            receiver_name, receiver_email, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?)""",
        (application_id, template_id, title, content_body, user["id"], receiver["id"],
         f'{receiver["first_name"]} {receiver["last_name"]}', receiver["email"], ts, ts),
    )
    append_workflow(conn, application_id, user["uisp_id"], "Submitted",
                     payload=title, comment=None)
    conn.commit()
    conn.close()

    audit("application_creation", user_id=user["id"], metadata={"application_id": application_id})
    flash(f"Application {application_id} submitted.", "success")
    return redirect(url_for("view_application", application_id=application_id))


@app.route("/applications/<application_id>")
@login_required
def view_application(application_id):
    user = current_user()
    conn = db.get_db()
    application = conn.execute(
        "SELECT * FROM applications WHERE application_id = ?", (application_id,)
    ).fetchone()
    if not application:
        conn.close()
        abort(404)

    # Zero-trust access check: only sender or receiver may view content
    if application["sender_id"] != user["id"] and application["receiver_id"] != user["id"]:
        conn.close()
        audit("unauthorized_access_attempt", user_id=user["id"],
              metadata={"application_id": application_id}, success=False)
        abort(403)

    sender = conn.execute("SELECT * FROM users WHERE id = ?", (application["sender_id"],)).fetchone()
    receiver = conn.execute("SELECT * FROM users WHERE id = ?", (application["receiver_id"],)).fetchone()
    workflow = conn.execute(
        "SELECT * FROM application_workflows WHERE application_id = ? ORDER BY id ASC",
        (application_id,),
    ).fetchall()
    conn.close()

    audit("application_access", user_id=user["id"], metadata={"application_id": application_id})
    chain_ok, chain_msg = verify_chain(application_id)

    return render_template(
        "view_application.html", application=application, sender=sender,
        receiver=receiver, workflow=workflow, chain_ok=chain_ok, chain_msg=chain_msg,
        user=user,
    )


@app.route("/applications/<application_id>/approve", methods=["POST"])
@login_required
def approve_application(application_id):
    user = current_user()
    conn = db.get_db()
    application = conn.execute(
        "SELECT * FROM applications WHERE application_id = ?", (application_id,)
    ).fetchone()
    if not application or application["receiver_id"] != user["id"]:
        conn.close()
        abort(403)
    if application["status"] != "Pending":
        conn.close()
        flash("This application has already been actioned.", "error")
        return redirect(url_for("view_application", application_id=application_id))

    # Backend generates and stamps the approver's visual crypto code — never
    # trust a frontend-supplied "approved" flag.
    code_path = os.path.join(QR_DIR, f"approve_{application_id}_{user['uisp_id']}.png")
    crypto_code.generate_user_code(user["uisp_id"], code_path)
    rel_path = f"qr/approve_{application_id}_{user['uisp_id']}.png"

    conn.execute(
        "UPDATE applications SET status = 'Approved', approver_crypto_code_path = ?, updated_at = ? "
        "WHERE application_id = ?",
        (rel_path, now_iso(), application_id),
    )
    append_workflow(conn, application_id, user["uisp_id"], "Approved", payload=user["uisp_id"])
    conn.commit()
    conn.close()

    audit("application_approval", user_id=user["id"], metadata={"application_id": application_id})
    flash(f"Application {application_id} approved.", "success")
    return redirect(url_for("view_application", application_id=application_id))


@app.route("/applications/<application_id>/reject", methods=["POST"])
@login_required
def reject_application(application_id):
    user = current_user()
    comment = request.form.get("comment", "").strip() or "No reason provided."
    conn = db.get_db()
    application = conn.execute(
        "SELECT * FROM applications WHERE application_id = ?", (application_id,)
    ).fetchone()
    if not application or application["receiver_id"] != user["id"]:
        conn.close()
        abort(403)
    if application["status"] != "Pending":
        conn.close()
        flash("This application has already been actioned.", "error")
        return redirect(url_for("view_application", application_id=application_id))

    conn.execute(
        "UPDATE applications SET status = 'Rejected', rejection_comment = ?, updated_at = ? "
        "WHERE application_id = ?",
        (comment, now_iso(), application_id),
    )
    append_workflow(conn, application_id, user["uisp_id"], "Rejected", payload=comment, comment=comment)
    conn.commit()
    conn.close()

    audit("application_rejection", user_id=user["id"], metadata={"application_id": application_id})
    flash(f"Application {application_id} rejected.", "success")
    return redirect(url_for("view_application", application_id=application_id))


@app.route("/applications/<application_id>/pdf")
@login_required
def application_pdf(application_id):
    user = current_user()
    conn = db.get_db()
    application = conn.execute(
        "SELECT * FROM applications WHERE application_id = ?", (application_id,)
    ).fetchone()
    if not application:
        conn.close()
        abort(404)
    if application["sender_id"] != user["id"] and application["receiver_id"] != user["id"]:
        conn.close()
        abort(403)
    sender = conn.execute("SELECT * FROM users WHERE id = ?", (application["sender_id"],)).fetchone()
    workflow = conn.execute(
        "SELECT * FROM application_workflows WHERE application_id = ? ORDER BY id ASC",
        (application_id,),
    ).fetchall()
    conn.close()

    pdf_bytes = build_application_pdf(application, sender, workflow)
    audit("pdf_generated", user_id=user["id"], metadata={"application_id": application_id})
    return send_file(
        io.BytesIO(pdf_bytes), mimetype="application/pdf",
        as_attachment=True, download_name=f"{application_id}.pdf",
    )


def build_application_pdf(application, sender, workflow):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    y = height - 25 * mm

    c.setFont("Helvetica-Bold", 16)
    c.drawString(20 * mm, y, "UISP — Application Document")
    y -= 10 * mm

    c.setFont("Helvetica", 10)
    c.setFillColor(colors.HexColor("#555555"))
    c.drawString(20 * mm, y, f"Application ID: {application['application_id']}")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"Status: {application['status']}")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"Sender: {sender['first_name']} {sender['last_name']}  ({sender['uisp_id']})")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"Receiver: {application['receiver_name']}")
    y -= 10 * mm

    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, application["title"])
    y -= 8 * mm

    c.setFont("Helvetica", 10)
    body_text = re.sub("<[^<]+?>", "", application["content_body"])  # strip any HTML tags
    for line in wrap_text(body_text, 95):
        if y < 40 * mm:
            c.showPage()
            y = height - 25 * mm
            c.setFont("Helvetica", 10)
        c.drawString(20 * mm, y, line)
        y -= 5.5 * mm

    y -= 6 * mm
    c.setFont("Helvetica-Bold", 11)
    c.drawString(20 * mm, y, "Workflow History")
    y -= 7 * mm
    c.setFont("Helvetica", 9)
    for w in workflow:
        if y < 30 * mm:
            c.showPage()
            y = height - 25 * mm
            c.setFont("Helvetica", 9)
        line = f"{w['created_at']}  -  {w['action_taken']}  by {w['action_by_uisp_id']}"
        c.drawString(20 * mm, y, line[:110])
        y -= 5 * mm

    if application["status"] == "Approved" and application["approver_crypto_code_path"]:
        code_full_path = os.path.join(BASE_DIR, "static", application["approver_crypto_code_path"])
        if os.path.exists(code_full_path):
            if y < 70 * mm:
                c.showPage()
                y = height - 25 * mm
            y -= 5 * mm
            c.setFont("Helvetica-Bold", 10)
            c.drawString(20 * mm, y, "Approver's 80-bit Visual Cryptographic Code:")
            y -= 45 * mm
            c.drawImage(code_full_path, 20 * mm, y, width=55 * mm, height=45 * mm,
                        preserveAspectRatio=True, mask="auto")

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()


def wrap_text(text, width):
    import textwrap
    lines = []
    for paragraph in text.split("\n"):
        wrapped = textwrap.wrap(paragraph, width=width) or [""]
        lines.extend(wrapped)
    return lines


# ----------------------------------------------------------------------
# Verification workflow
# ----------------------------------------------------------------------

@app.route("/verify/upload", methods=["POST"])
@login_required
def verify_upload():
    user = current_user()
    file = request.files.get("code_image")
    if not file or file.filename == "":
        flash("Choose an image to upload.", "error")
        return redirect(url_for("dashboard", view="verify"))
    if not allowed_upload(file.filename):
        flash("Only PNG/JPG images are supported.", "error")
        return redirect(url_for("dashboard", view="verify"))

    filename = secure_filename(f"{pysecrets.token_hex(6)}_{file.filename}")
    save_path = os.path.join(UPLOAD_DIR, filename)
    file.save(save_path)

    conn = db.get_db()
    try:
        vcc = crypto_code.VisualCryptoCode()
        decoded_hex = vcc.read_code(save_path)
    except Exception as e:
        audit("verification_attempt", user_id=user["id"], metadata={"error": str(e)}, success=False)
        conn.close()
        flash(f"Could not read a valid code from that image: {e}", "error")
        return redirect(url_for("dashboard", view="verify"))

    matched_user = conn.execute("SELECT * FROM users WHERE uisp_id = ?", (decoded_hex,)).fetchone()
    conn.close()

    audit("verification_attempt", user_id=user["id"],
          metadata={"decoded_hex": decoded_hex, "matched": bool(matched_user)},
          success=bool(matched_user))

    return render_template(
        "verify_result.html", mode="image", decoded_hex=decoded_hex, matched_user=matched_user
    )


@app.route("/verify/manual", methods=["POST"])
@login_required
def verify_manual():
    user = current_user()
    application_id = request.form.get("application_id", "").strip().upper()
    conn = db.get_db()
    application = conn.execute(
        "SELECT * FROM applications WHERE application_id = ?", (application_id,)
    ).fetchone()
    conn.close()

    if application:
        chain_ok, chain_msg = verify_chain(application_id)
    else:
        chain_ok, chain_msg = False, "Application not found."

    audit("verification_attempt", user_id=user["id"],
          metadata={"application_id": application_id, "found": bool(application)},
          success=bool(application))

    return render_template(
        "verify_result.html", mode="manual", application=application,
        chain_ok=chain_ok, chain_msg=chain_msg, searched_id=application_id,
    )


# ----------------------------------------------------------------------
# Settings — profile update / delete account
# ----------------------------------------------------------------------

@app.route("/settings/update", methods=["POST"])
@login_required
def update_settings():
    user = current_user()
    designation = request.form.get("designation", "").strip()
    region = request.form.get("region", "").strip()
    conn = db.get_db()
    conn.execute("UPDATE users SET designation = ?, region = ? WHERE id = ?",
                 (designation or user["designation"], region or user["region"], user["id"]))
    conn.commit()
    conn.close()
    audit("profile_update", user_id=user["id"])
    flash("Profile updated.", "success")
    return redirect(url_for("dashboard", view="settings"))


@app.route("/settings/delete-account", methods=["POST"])
@login_required
def delete_account():
    user = current_user()
    conn = db.get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    conn.commit()
    conn.close()
    audit("account_deletion", user_id=user["id"])
    session.clear()
    flash("Your account has been deleted.", "success")
    return redirect(url_for("login"))


# ----------------------------------------------------------------------
# Error handlers
# ----------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="You don't have access to this resource."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Not found."), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Something went wrong on our end."), 500


if __name__ == "__main__":
    db.init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
