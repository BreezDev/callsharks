import csv
import io
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

import urllib.request
import urllib.error
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import stripe
except ImportError:  # optional in local env
    stripe = None

BASE_DIR = Path(__file__).resolve().parent
HTML_FILES = {path.name for path in BASE_DIR.glob("*.html")}
DATA_DIR = BASE_DIR / "data"
DATABASE = DATA_DIR / "callsharks.db"

app = Flask(__name__, template_folder=str(BASE_DIR), static_folder=str(BASE_DIR))
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_SUCCESS_URL = os.getenv("STRIPE_SUCCESS_URL", "http://localhost:5000/dashboard?checkout=success")
STRIPE_CANCEL_URL = os.getenv("STRIPE_CANCEL_URL", "http://localhost:5000/dashboard?checkout=cancel")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "onboarding@resend.dev")
ADMIN_BOOTSTRAP_EMAIL = os.getenv("ADMIN_BOOTSTRAP_EMAIL", "admin@callsharks.com").lower()
ADMIN_BOOTSTRAP_PASSWORD = os.getenv("ADMIN_BOOTSTRAP_PASSWORD", "ChangeMe123!")

if stripe and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY


def now_iso() -> str:
    return datetime.utcnow().isoformat()


def init_db() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    with sqlite3.connect(DATABASE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_type TEXT NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'client',
                company_name TEXT,
                industry TEXT,
                team_size TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lead_preferences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                lead_goals TEXT,
                lead_types TEXT,
                desired_volume TEXT,
                regions TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                stripe_price_id TEXT,
                lead_volume INTEGER,
                monthly_price_cents INTEGER,
                active INTEGER NOT NULL DEFAULT 1,
                trial_days INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS coupons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT NOT NULL UNIQUE,
                discount_percent INTEGER,
                free_trial_days INTEGER NOT NULL DEFAULT 0,
                max_redemptions INTEGER,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan_id INTEGER,
                plan_name TEXT NOT NULL,
                provider TEXT NOT NULL,
                status TEXT NOT NULL,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                coupon_code TEXT,
                trial_ends_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(plan_id) REFERENCES plans(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lead_imports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uploaded_by INTEGER NOT NULL,
                file_name TEXT NOT NULL,
                category TEXT NOT NULL,
                column_mapping TEXT,
                row_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(uploaded_by) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                import_id INTEGER NOT NULL,
                owner_user_id INTEGER,
                category TEXT,
                data_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                created_at TEXT NOT NULL,
                FOREIGN KEY(import_id) REFERENCES lead_imports(id),
                FOREIGN KEY(owner_user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                type TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

        plan_count = conn.execute("SELECT COUNT(*) FROM plans").fetchone()[0]
        if not plan_count:
            seed_time = now_iso()
            conn.executemany(
                """
                INSERT INTO plans (name, lead_volume, monthly_price_cents, trial_days, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    ("Starter", 50, 9900, 7, seed_time, seed_time),
                    ("Growth", 150, 24900, 14, seed_time, seed_time),
                    ("Scale", 300, 49900, 30, seed_time, seed_time),
                ],
            )

        admin = conn.execute("SELECT id FROM users WHERE email = ?", (ADMIN_BOOTSTRAP_EMAIL,)).fetchone()
        if not admin:
            created = now_iso()
            conn.execute(
                """
                INSERT INTO users (account_type, full_name, email, password, role, created_at, updated_at)
                VALUES ('business', 'Platform Admin', ?, ?, 'admin', ?, ?)
                """,
                (
                    ADMIN_BOOTSTRAP_EMAIL,
                    generate_password_hash(ADMIN_BOOTSTRAP_PASSWORD),
                    created,
                    created,
                ),
            )


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def notify(user_id: int | None, notification_type: str, message: str) -> None:
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO notifications (user_id, type, message, created_at) VALUES (?, ?, ?, ?)",
            (user_id, notification_type, message, now_iso()),
        )


def send_email(to_email: str, subject: str, html: str) -> bool:
    if not RESEND_API_KEY:
        return False
    payload = {
        "from": RESEND_FROM_EMAIL,
        "to": [to_email],
        "subject": subject,
        "html": html,
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return 200 <= resp.status < 300
    except urllib.error.URLError:
        return False


def current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT id, full_name, email, role, account_type FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def require_auth(role: str | None = None) -> sqlite3.Row:
    user = current_user()
    if not user:
        abort(401)
    if role and user["role"] != role:
        abort(403)
    return user


@app.context_processor
def inject_nav_state() -> dict[str, Any]:
    return {"active_user": current_user()}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    with get_db_connection() as conn:
        plans = conn.execute(
            "SELECT id, name, lead_volume, monthly_price_cents, trial_days FROM plans WHERE active = 1 ORDER BY monthly_price_cents"
        ).fetchall()

    if request.method == "POST":
        account_type = request.form.get("account_type", "individual")
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or len(full_name) < 2:
            return render_template("signup.html", error="Please enter a valid full name.", plans=plans)
        if "@" not in email:
            return render_template("signup.html", error="Please enter a valid email address.", plans=plans)
        if len(password) < 8:
            return render_template("signup.html", error="Password must be at least 8 characters.", plans=plans)
        if password != confirm_password:
            return render_template("signup.html", error="Passwords do not match.", plans=plans)

        company_name = request.form.get("company_name", "").strip()
        industry = request.form.get("industry", "").strip()
        team_size = request.form.get("team_size", "").strip()
        lead_goals = request.form.get("lead_goals", "").strip()
        lead_types = ", ".join(request.form.getlist("lead_types"))
        desired_volume = request.form.get("desired_volume", "").strip()
        regions = request.form.get("regions", "").strip()
        plan_name = request.form.get("plan", "Growth")
        created_at = now_iso()

        conn = get_db_connection()
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            conn.close()
            return render_template("signup.html", error="That email is already registered.", plans=plans)

        cursor = conn.execute(
            """
            INSERT INTO users (account_type, full_name, email, password, role, company_name, industry, team_size, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'client', ?, ?, ?, ?, ?)
            """,
            (
                account_type,
                full_name,
                email,
                generate_password_hash(password),
                company_name,
                industry,
                team_size,
                created_at,
                created_at,
            ),
        )
        user_id = cursor.lastrowid
        conn.execute(
            "INSERT INTO lead_preferences (user_id, lead_goals, lead_types, desired_volume, regions) VALUES (?, ?, ?, ?, ?)",
            (user_id, lead_goals, lead_types, desired_volume, regions),
        )
        plan = conn.execute("SELECT id, trial_days FROM plans WHERE name = ?", (plan_name,)).fetchone()
        trial_end = None
        if plan and plan["trial_days"]:
            trial_end = datetime.utcnow().timestamp() + (plan["trial_days"] * 24 * 60 * 60)
            trial_end = datetime.utcfromtimestamp(trial_end).isoformat()

        conn.execute(
            """
            INSERT INTO subscriptions (user_id, plan_id, plan_name, provider, status, trial_ends_at, created_at, updated_at)
            VALUES (?, ?, ?, 'Stripe', 'pending_checkout', ?, ?, ?)
            """,
            (user_id, plan["id"] if plan else None, plan_name, trial_end, created_at, created_at),
        )
        conn.commit()
        conn.close()

        session["user_id"] = user_id
        notify(user_id, "welcome", f"Welcome to CallSharks, {full_name}!")
        send_email(
            email,
            "Welcome to CallSharks",
            f"<p>Hi {full_name}, your account is ready. Login anytime to manage your subscription.</p>",
        )
        return redirect(url_for("dashboard"))

    return render_template("signup.html", plans=plans)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT id, full_name, email, role, password FROM users WHERE email = ? AND is_active = 1",
                (email,),
            ).fetchone()

        if not user or not check_password_hash(user["password"], password):
            return render_template("login.html", error="Invalid email or password.")

        session["user_id"] = user["id"]
        notify(user["id"], "auth", "Successful sign in detected.")
        if user["role"] == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    user = require_auth()
    with get_db_connection() as conn:
        subscription = conn.execute(
            """
            SELECT s.*, p.lead_volume, p.monthly_price_cents, p.trial_days
            FROM subscriptions s
            LEFT JOIN plans p ON s.plan_id = p.id
            WHERE s.user_id = ?
            ORDER BY s.created_at DESC
            LIMIT 1
            """,
            (user["id"],),
        ).fetchone()
        notifications = conn.execute(
            "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 12",
            (user["id"],),
        ).fetchall()
        leads = conn.execute(
            "SELECT id, category, status, created_at, data_json FROM leads WHERE owner_user_id = ? ORDER BY created_at DESC LIMIT 25",
            (user["id"],),
        ).fetchall()
    return render_template("client-dashboard.html", user=user, subscription=subscription, notifications=notifications, leads=leads)


@app.route("/subscribe/checkout", methods=["POST"])
def checkout_subscription():
    user = require_auth()
    plan_id = request.form.get("plan_id", type=int)
    coupon_code = request.form.get("coupon_code", "").strip().upper()

    with get_db_connection() as conn:
        plan = conn.execute("SELECT * FROM plans WHERE id = ? AND active = 1", (plan_id,)).fetchone()
        if not plan:
            flash("Selected plan is not available.")
            return redirect(url_for("dashboard"))

        coupon = None
        if coupon_code:
            coupon = conn.execute("SELECT * FROM coupons WHERE code = ? AND active = 1", (coupon_code,)).fetchone()
            if not coupon:
                flash("Coupon code not found or inactive.")
                return redirect(url_for("dashboard"))

        trial_days = plan["trial_days"]
        if coupon and coupon["free_trial_days"]:
            trial_days = max(trial_days, coupon["free_trial_days"])

        created_at = now_iso()
        conn.execute(
            """
            INSERT INTO subscriptions (user_id, plan_id, plan_name, provider, status, coupon_code, trial_ends_at, created_at, updated_at)
            VALUES (?, ?, ?, 'Stripe', 'checkout_started', ?, ?, ?, ?)
            """,
            (
                user["id"],
                plan["id"],
                plan["name"],
                coupon_code or None,
                datetime.utcfromtimestamp(datetime.utcnow().timestamp() + trial_days * 86400).isoformat() if trial_days else None,
                created_at,
                created_at,
            ),
        )
        conn.commit()

    # Real Stripe flow when configured
    if stripe and STRIPE_SECRET_KEY and plan["stripe_price_id"]:
        checkout_args: dict[str, Any] = {
            "mode": "subscription",
            "line_items": [{"price": plan["stripe_price_id"], "quantity": 1}],
            "success_url": STRIPE_SUCCESS_URL,
            "cancel_url": STRIPE_CANCEL_URL,
            "customer_email": user["email"],
            "subscription_data": {"trial_period_days": trial_days} if trial_days else {},
            "metadata": {"user_id": user["id"], "plan_id": plan["id"]},
        }
        if coupon_code:
            checkout_args["allow_promotion_codes"] = True
        checkout_session = stripe.checkout.Session.create(**checkout_args)
        return redirect(checkout_session.url)

    notify(user["id"], "billing", f"Mock checkout started for {plan['name']} plan.")
    flash("Stripe keys are not configured yet, so a mock checkout was created.")
    return redirect(url_for("dashboard"))


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    if not stripe or not STRIPE_WEBHOOK_SECRET:
        return jsonify({"received": False, "reason": "Stripe webhook not configured"}), 200

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception:
        return jsonify({"error": "Invalid webhook signature"}), 400

    if event["type"] == "customer.subscription.updated":
        sub = event["data"]["object"]
        with get_db_connection() as conn:
            conn.execute(
                """
                UPDATE subscriptions
                SET status = ?, stripe_customer_id = ?, stripe_subscription_id = ?, updated_at = ?
                WHERE stripe_subscription_id = ? OR stripe_subscription_id IS NULL
                """,
                (sub.get("status", "active"), sub.get("customer"), sub.get("id"), now_iso(), sub.get("id")),
            )
            conn.commit()
    return jsonify({"received": True})


@app.route("/admin")
def admin_dashboard():
    admin = require_auth("admin")
    with get_db_connection() as conn:
        plans = conn.execute("SELECT * FROM plans ORDER BY monthly_price_cents").fetchall()
        coupons = conn.execute("SELECT * FROM coupons ORDER BY created_at DESC").fetchall()
        imports = conn.execute(
            """
            SELECT li.*, u.full_name AS uploaded_by_name
            FROM lead_imports li
            JOIN users u ON li.uploaded_by = u.id
            ORDER BY li.created_at DESC
            LIMIT 20
            """
        ).fetchall()
        users = conn.execute("SELECT id, full_name, email, role, created_at FROM users ORDER BY created_at DESC LIMIT 20").fetchall()
        notifications = conn.execute("SELECT * FROM notifications ORDER BY created_at DESC LIMIT 20").fetchall()
    return render_template(
        "admin-dashboard.html",
        user=admin,
        plans=plans,
        coupons=coupons,
        imports=imports,
        users=users,
        notifications=notifications,
    )


@app.route("/admin/plans", methods=["POST"])
def admin_save_plan():
    require_auth("admin")
    plan_id = request.form.get("plan_id", type=int)
    payload = (
        request.form.get("name", "").strip(),
        request.form.get("stripe_price_id", "").strip() or None,
        request.form.get("lead_volume", type=int),
        request.form.get("monthly_price_cents", type=int),
        request.form.get("trial_days", type=int, default=0),
        1 if request.form.get("active") == "on" else 0,
        now_iso(),
    )
    with get_db_connection() as conn:
        if plan_id:
            conn.execute(
                """
                UPDATE plans
                SET name=?, stripe_price_id=?, lead_volume=?, monthly_price_cents=?, trial_days=?, active=?, updated_at=?
                WHERE id=?
                """,
                (*payload, plan_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO plans (name, stripe_price_id, lead_volume, monthly_price_cents, trial_days, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*payload[:-1], payload[-1], payload[-1]),
            )
        conn.commit()
    flash("Plan saved.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/coupons", methods=["POST"])
def admin_save_coupon():
    require_auth("admin")
    code = request.form.get("code", "").strip().upper()
    if not code:
        flash("Coupon code is required.")
        return redirect(url_for("admin_dashboard"))

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO coupons (code, discount_percent, free_trial_days, max_redemptions, active, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(code) DO UPDATE SET
              discount_percent=excluded.discount_percent,
              free_trial_days=excluded.free_trial_days,
              max_redemptions=excluded.max_redemptions,
              active=excluded.active
            """,
            (
                code,
                request.form.get("discount_percent", type=int),
                request.form.get("free_trial_days", type=int, default=0),
                request.form.get("max_redemptions", type=int),
                1 if request.form.get("active") == "on" else 0,
                now_iso(),
            ),
        )
        conn.commit()
    flash("Coupon saved.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/upload-leads", methods=["POST"])
def admin_upload_leads():
    admin = require_auth("admin")
    csv_file = request.files.get("csv_file")
    category = request.form.get("category", "uncategorized").strip() or "uncategorized"
    owner_user_id = request.form.get("owner_user_id", type=int)

    if not csv_file:
        flash("Please select a CSV file.")
        return redirect(url_for("admin_dashboard"))

    content = csv_file.stream.read().decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(content)))

    with get_db_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO lead_imports (uploaded_by, file_name, category, row_count, created_at) VALUES (?, ?, ?, ?, ?)",
            (admin["id"], csv_file.filename, category, len(rows), now_iso()),
        )
        import_id = cursor.lastrowid
        for row in rows:
            conn.execute(
                "INSERT INTO leads (import_id, owner_user_id, category, data_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (import_id, owner_user_id, category, json.dumps(row), now_iso()),
            )
        conn.commit()

    notify(None, "leads", f"{len(rows)} leads imported in '{category}' from {csv_file.filename}.")
    flash(f"Imported {len(rows)} leads.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/imports/<int:import_id>/categorize", methods=["POST"])
def admin_categorize_import(import_id: int):
    require_auth("admin")
    category = request.form.get("category", "uncategorized").strip() or "uncategorized"
    mapping = request.form.get("column_mapping", "{}")

    with get_db_connection() as conn:
        conn.execute(
            "UPDATE lead_imports SET category = ?, column_mapping = ? WHERE id = ?",
            (category, mapping, import_id),
        )
        conn.execute("UPDATE leads SET category = ? WHERE import_id = ?", (category, import_id))
        conn.commit()
    flash("Import categorization updated.")
    return redirect(url_for("admin_dashboard"))


@app.route("/api/admin/realtime")
def admin_realtime_api():
    require_auth("admin")
    with get_db_connection() as conn:
        totals = {
            "users": conn.execute("SELECT COUNT(*) FROM users WHERE role='client'").fetchone()[0],
            "active_subscriptions": conn.execute("SELECT COUNT(*) FROM subscriptions WHERE status IN ('active', 'trialing', 'checkout_started')").fetchone()[0],
            "lead_imports": conn.execute("SELECT COUNT(*) FROM lead_imports").fetchone()[0],
        }
        rows = conn.execute(
            """
            SELECT u.full_name, u.email, s.plan_name, s.status, s.updated_at
            FROM users u
            LEFT JOIN subscriptions s ON s.user_id = u.id
            WHERE u.role = 'client'
            ORDER BY COALESCE(s.updated_at, s.created_at) DESC
            LIMIT 10
            """
        ).fetchall()

    return jsonify(
        {
            "totals": totals,
            "subscriptions": [dict(r) for r in rows],
            "generated_at": now_iso(),
        }
    )


@app.route("/<path:page>")
def page(page: str):
    if page in HTML_FILES:
        return render_template(page)
    abort(404)


init_db()

if __name__ == "__main__":
    app.run(debug=True)
