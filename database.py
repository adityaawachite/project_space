"""
UISP-Lite database layer — plain sqlite3 (no ORM dependency needed).
Creates the schema on first run and seeds demo data (org, templates,
and the default login account).
"""

import sqlite3
import os
import secrets
from datetime import datetime
from werkzeug.security import generate_password_hash

import crypto_code

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "uisp.db")
QR_DIR = os.path.join(BASE_DIR, "static", "qr")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uisp_id TEXT UNIQUE NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    designation TEXT DEFAULT 'Member',
    region TEXT DEFAULT '',
    org_id INTEGER,
    crypto_code_path TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_name TEXT NOT NULL,
    registration_number TEXT UNIQUE NOT NULL,
    org_type TEXT DEFAULT 'General'
);

CREATE TABLE IF NOT EXISTS application_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id TEXT UNIQUE NOT NULL,
    template_id INTEGER,
    title TEXT NOT NULL,
    content_body TEXT NOT NULL,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER,
    receiver_name TEXT,
    receiver_email TEXT,
    status TEXT NOT NULL DEFAULT 'Pending',
    rejection_comment TEXT,
    approver_crypto_code_path TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id),
    FOREIGN KEY (template_id) REFERENCES application_templates(id)
);

CREATE TABLE IF NOT EXISTS application_workflows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id TEXT NOT NULL,
    action_by_uisp_id TEXT NOT NULL,
    action_taken TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    signature_hash TEXT NOT NULL,
    comment TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    user_id INTEGER,
    metadata TEXT,
    success INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
"""

DEFAULT_TEMPLATES = [
    ("Normal", "General", "Plain free-text application"),
    ("Fund Request", "Finance", "Request funds/reimbursement with amount and reason"),
    ("Notices", "Communication", "Broadcast a notice to an organization"),
    ("Leave", "HR", "Leave / time-off request"),
    ("Approval", "Workflow", "Generic multi-step approval request"),
    ("Custom Application", "General", "Free-form custom application"),
]


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def generate_uisp_id() -> str:
    """20-char uppercase hex UISP_ID, collision-checked against the DB."""
    conn = get_db()
    try:
        for _ in range(20):
            candidate = secrets.token_hex(10).upper()  # 10 bytes -> 20 hex chars
            row = conn.execute("SELECT 1 FROM users WHERE uisp_id = ?", (candidate,)).fetchone()
            if not row:
                return candidate
        raise RuntimeError("Could not generate a unique UISP_ID after 20 attempts.")
    finally:
        conn.close()


def generate_application_id(category_code: str = "GEN") -> str:
    """e.g. UISP-GEN-2026-0001A"""
    conn = get_db()
    try:
        year = datetime.utcnow().year
        for _ in range(50):
            n = secrets.randbelow(9000) + 1000
            suffix = secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")
            candidate = f"UISP-{category_code}-{year}-{n}{suffix}"
            row = conn.execute(
                "SELECT 1 FROM applications WHERE application_id = ?", (candidate,)
            ).fetchone()
            if not row:
                return candidate
        raise RuntimeError("Could not generate a unique Application_ID.")
    finally:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()

    # Seed templates once
    count = conn.execute("SELECT COUNT(*) AS c FROM application_templates").fetchone()["c"]
    if count == 0:
        conn.executemany(
            "INSERT INTO application_templates (template_name, category, description) VALUES (?, ?, ?)",
            DEFAULT_TEMPLATES,
        )
        conn.commit()

    # Seed default organization
    org_row = conn.execute("SELECT id FROM organizations LIMIT 1").fetchone()
    if org_row is None:
        conn.execute(
            "INSERT INTO organizations (org_name, registration_number, org_type) VALUES (?, ?, ?)",
            ("UISP Demo Organization", "REG-UISP-0001", "Demo"),
        )
        conn.commit()
    org_id = conn.execute("SELECT id FROM organizations LIMIT 1").fetchone()["id"]

    # Seed default login account (as requested)
    existing = conn.execute(
        "SELECT id FROM users WHERE email = ?", ("adigorkshnathawachite@gmail.com",)
    ).fetchone()
    if existing is None:
        conn.close()
        uisp_id = generate_uisp_id()

        os.makedirs(QR_DIR, exist_ok=True)
        code_path = os.path.join(QR_DIR, f"{uisp_id}.png")
        crypto_code.generate_user_code(uisp_id, code_path)

        conn = get_db()
        conn.execute(
            """INSERT INTO users
               (uisp_id, first_name, last_name, email, password_hash, designation, region, org_id,
                crypto_code_path, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                uisp_id,
                "Aditya Gorkshnath",
                "Awachite",
                "adigorkshnathawachite@gmail.com",
                generate_password_hash("Ad12ya@aw"),
                "Administrator",
                "India",
                org_id,
                f"qr/{uisp_id}.png",
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
    conn.close()
