# UISP-Lite — Unified Identity and Signature Platform (scaled-down MVP)

Python (Flask) + SQLite + HTML/CSS/JS + OpenCV. A single, runnable
web application — not a mockup. Every button in the UI calls a real
backend route, backed by a real SQLite database.

## What this is (and isn't)

The original spec described an enterprise system (ASP.NET Core +
Next.js + PostgreSQL + a separate Python microservice + Docker +
payments + refresh-token rotation, etc.) — realistically weeks of
work. This build is the **same core workflow, in one Python stack**,
scoped to a working MVP:

- Register / Login (hashed passwords, session auth)
- Every user gets a permanent 20-hex-char **UISP_ID** and an 80-bit
  visual cryptographic code (8×10 grid, generated with OpenCV)
- Glassmorphism dashboard: header, left nav, dynamic bento grid, FAB
- New Application (template picker + receiver + rich-ish editor)
- Pending / Previous / Unknown / Reject views
- Organization Control (member directory)
- Application Verification — upload an image of a code **or** look
  up an Application_ID
- Backend-owned approve/reject workflow with a **SHA-256 hash chain**
  (tamper-evident audit trail) + chain verification endpoint
- Real PDF generation (application content + workflow history +
  approver's visual code, via ReportLab)
- Zero-trust access control (only sender/receiver can open an
  application — enforced server-side, not just hidden in the UI)
- Audit log (login, registration, approvals, unauthorized attempts...)
- Global header search (users / organizations) + local bento search

Not included in this MVP (flagged as-is, not silently faked):
payment gateway, real-time notifications/WebSockets, multi-org
membership approval workflow, refresh-token rotation (session-cookie
auth is used instead), Docker/PostgreSQL (SQLite is used for a
zero-setup local run).

## Setup

```bash
cd uisp_lite
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**. The database (`instance/uisp.db`) and
demo data are created automatically on first run.

## Demo login

```
Email:    adigorkshnathawachite@gmail.com
Password: Ad12ya@aw
```

This account is seeded automatically with its own UISP_ID and visual
code. Register a second account from the UI to test the full
sender → receiver → approve/reject workflow.

## Project structure

```
uisp_lite/
├── app.py              # Flask routes: auth, dashboard, applications, verification, PDF
├── database.py          # SQLite schema + seed data (org, templates, demo user)
├── crypto_code.py        # 80-bit visual cryptographic code: generate + OpenCV decode
├── requirements.txt
├── templates/            # Jinja2 HTML (glassmorphism UI)
└── static/
    ├── css/style.css     # Glassmorphism design system
    ├── js/app.js         # Search, editor toolbar, tabs, template picker
    └── qr/                # Generated visual codes land here
```

## Notes on the visual crypto code

`crypto_code.py` encodes a 20-char uppercase hex UISP_ID as 80 bits
into an 8×10 grid (filled circle = 0, hollow ring = 1), with a solid
L-shaped orientation marker so a photographed/rotated copy can still
be read. It was tested end-to-end in this build: 80/80 random codes
round-tripped correctly, including after 90°/180°/270° rotation.

## Known limitations

- SQLite, not PostgreSQL — fine for a local demo, swap for
  production multi-user load.
- Session-cookie auth, not JWT + refresh-token rotation.
- The rich text editor is a lightweight `contenteditable` div with
  bold/italic/underline — not a full WYSIWYG library.
- No payment/notification integrations.
- Single-process Flask dev server — for real deployment, run behind
  gunicorn/uwsgi + a reverse proxy, and set `UISP_SECRET_KEY`.
