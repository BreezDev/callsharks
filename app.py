from datetime import datetime
from pathlib import Path
import sqlite3

from flask import Flask, abort, render_template, request

BASE_DIR = Path(__file__).resolve().parent
HTML_FILES = {path.name for path in BASE_DIR.glob("*.html")}
DATA_DIR = BASE_DIR / "data"
DATABASE = DATA_DIR / "callsharks.db"

app = Flask(__name__, template_folder=str(BASE_DIR), static_folder=str(BASE_DIR))


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
                company_name TEXT,
                industry TEXT,
                team_size TEXT,
                created_at TEXT NOT NULL
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
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan TEXT NOT NULL,
                provider TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

init_db()


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        account_type = request.form.get("account_type", "individual")
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        company_name = request.form.get("company_name", "").strip()
        industry = request.form.get("industry", "").strip()
        team_size = request.form.get("team_size", "").strip()
        lead_goals = request.form.get("lead_goals", "").strip()
        lead_types = ", ".join(request.form.getlist("lead_types"))
        desired_volume = request.form.get("desired_volume", "").strip()
        regions = request.form.get("regions", "").strip()
        plan = request.form.get("plan", "Growth")
        created_at = datetime.utcnow().isoformat()

        conn = get_db_connection()
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()
        if existing:
            conn.close()
            return render_template(
                "signup.html",
                error="That email is already registered. Try logging in instead.",
            )
        cursor = conn.execute(
            """
            INSERT INTO users (
                account_type, full_name, email, password, company_name,
                industry, team_size, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_type,
                full_name,
                email,
                password,
                company_name,
                industry,
                team_size,
                created_at,
            ),
        )
        user_id = cursor.lastrowid
        conn.execute(
            """
            INSERT INTO lead_preferences (
                user_id, lead_goals, lead_types, desired_volume, regions
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, lead_goals, lead_types, desired_volume, regions),
        )
        conn.execute(
            """
            INSERT INTO subscriptions (user_id, plan, provider, status, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, plan, "Stripe Subscriptions", "pending", created_at),
        )
        conn.commit()
        conn.close()
        return render_template(
            "signup-success.html",
            full_name=full_name,
            plan=plan,
            account_type=account_type,
        )
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn = get_db_connection()
        user = conn.execute(
            "SELECT full_name, account_type FROM users WHERE email = ? AND password = ?",
            (email, password),
        ).fetchone()
        conn.close()
        if user:
            return render_template(
                "login-success.html",
                full_name=user["full_name"],
                account_type=user["account_type"],
            )
        return render_template(
            "login.html",
            error="We couldn't find that account. Double-check your email or password.",
        )
    return render_template("login.html")


@app.route("/subscribe", methods=["POST"])
def subscribe():
    email = request.form.get("email", "").strip().lower()
    plan = request.form.get("plan", "Growth")
    created_at = datetime.utcnow().isoformat()
    conn = get_db_connection()
    user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if user:
        conn.execute(
            """
            INSERT INTO subscriptions (user_id, plan, provider, status, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user["id"], plan, "Stripe Subscriptions", "checkout_started", created_at),
        )
        conn.commit()
    conn.close()
    return render_template("subscribe-success.html", plan=plan, email=email)


@app.route("/<path:page>")
def page(page: str):
    if page in HTML_FILES:
        return render_template(page)
    abort(404)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
