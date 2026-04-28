"""
LSU Banking Portal — Secure Version
Fixes the 8 critical/high vulnerabilities 

VULNERABILITY FIXES:
  #1 Cookie forgery → admin access     → Flask signed sessions (server-side)
  #2 Negative-amount transfer theft    → Server-side amount validation (must be > 0)
  #3 Plaintext password storage        → Werkzeug PBKDF2 hashing
  #4 CSV injection → admin escalation  → SQLite with parameterized queries
  #5 XSS via show_message_page()       → Jinja2 template with auto-escaping
  #6 No CSRF protection                → Flask-WTF CSRF tokens on every POST
  #7 Debug mode = RCE                  → debug=False by default
  #8 Race condition on balance update  → SQLite transactions with BEGIN IMMEDIATE
"""

from flask import Flask, request, redirect, url_for, render_template, make_response, session, flash, g
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from contextlib import contextmanager

app = Flask(__name__, template_folder=".", static_folder=".",
            static_url_path="/static")

# FIX #7 (part): SECRET_KEY is required for signed sessions and CSRF tokens.
# The original app had no SECRET_KEY at all.
app.secret_key = os.environ.get("BANK_SECRET_KEY", secrets.token_hex(32))

# FIX #6: Enable CSRF protection on all POST forms.
csrf = CSRFProtect(app)

# Database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "bank.sqlite3")


# ─── Database Layer ──────────────────────────────────────────────────────
# FIX #4: Replaced flat-file CSV storage (users.txt, accounts.txt,
#         transactions.txt) with SQLite + parameterized queries.
#         This eliminates CSV injection entirely — commas and newlines
#         in user input cannot shift column boundaries.
# FIX #8: SQLite transactions with BEGIN IMMEDIATE prevent the
#         read-check-write race condition on balance updates.

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    full_name     TEXT    NOT NULL,
    email         TEXT    NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS accounts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number TEXT    UNIQUE NOT NULL,
    balance        REAL    NOT NULL DEFAULT 0,
    owner          TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    from_account  TEXT    NOT NULL,
    to_account    TEXT    NOT NULL,
    amount        REAL    NOT NULL,
    description   TEXT    NOT NULL DEFAULT '',
    timestamp     TEXT    NOT NULL
);
"""


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@contextmanager
def db_transaction(db):
    """
    FIX #8: BEGIN IMMEDIATE acquires a write lock immediately,
    preventing the TOCTOU race where two concurrent transfers
    both read the same balance and both succeed.
    """
    db.execute("BEGIN IMMEDIATE;")
    try:
        yield
        db.execute("COMMIT;")
    except Exception:
        db.execute("ROLLBACK;")
        raise


def initialize_database():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    # Seed admin if not exists
    cur = conn.execute("SELECT 1 FROM users WHERE username = 'admin';")
    if cur.fetchone() is None:
        # FIX #3: Hash the admin password instead of storing plaintext.
        admin_pw = os.environ.get("BANK_ADMIN_PASSWORD", "admin123")
        conn.execute(
            "INSERT INTO users (username, password_hash, full_name, email, is_admin) VALUES (?, ?, ?, ?, 1);",
            ("admin", generate_password_hash(admin_pw), "System Administrator", "admin@lsu.edu")
        )
        conn.execute(
            "INSERT INTO accounts (account_number, balance, owner) VALUES (?, ?, ?);",
            ("ACC10000", 1000000.00, "admin")
        )
        conn.commit()
    conn.close()


# ─── Auth Helpers ────────────────────────────────────────────────────────
# FIX #1: Authentication now uses Flask's signed session instead of
#         unsigned client cookies. The session stores only the username;
#         is_admin is ALWAYS re-read from the database, never trusted
#         from the client.

def current_user():
    """Get the current user from the DB based on the signed session."""
    username = session.get("username")
    if not username:
        return None
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username = ?;", (username,)).fetchone()
    return dict(row) if row else None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        # FIX #1: is_admin is checked from the DATABASE, not from a cookie.
        if not user["is_admin"]:
            return render_template("notice.html",
                session=make_session_dict(user),
                message="Access Denied. Admin privileges required.",
                redirect_url="/dashboard",
                redirect_text="Return to Dashboard"), 403
        return f(*args, **kwargs)
    return wrapper


def make_session_dict(user=None):
    """Build the session dict that templates expect (same variable names as original)."""
    if user is None:
        user = current_user()
    if user:
        return {
            "logged_in": True,
            "username": user["username"],
            "is_admin": "true" if user["is_admin"] else "false"
        }
    return {"logged_in": False, "username": "", "is_admin": ""}


# ─── Data Access Functions ───────────────────────────────────────────────

def get_user(username):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username = ?;", (username,)).fetchone()
    if row:
        return {
            "username": row["username"],
            "password_hash": row["password_hash"],
            "full_name": row["full_name"],
            "email": row["email"],
            "is_admin": "true" if row["is_admin"] else "false"
        }
    return None


def get_user_accounts(username):
    db = get_db()
    rows = db.execute("SELECT * FROM accounts WHERE owner = ?;", (username,)).fetchall()
    return [{"account_number": r["account_number"], "balance": r["balance"], "owner": r["owner"]} for r in rows]


def get_all_accounts():
    db = get_db()
    rows = db.execute("SELECT * FROM accounts;").fetchall()
    return [{"account_number": r["account_number"], "balance": r["balance"], "owner": r["owner"]} for r in rows]


def get_all_users_with_balance():
    db = get_db()
    rows = db.execute("""
        SELECT u.username, u.full_name, u.email, u.is_admin,
               COUNT(a.id) AS account_count,
               COALESCE(SUM(a.balance), 0) AS total_balance
        FROM users u LEFT JOIN accounts a ON a.owner = u.username
        GROUP BY u.id;
    """).fetchall()
    return [{
        "username": r["username"], "full_name": r["full_name"],
        "email": r["email"],
        "is_admin": "true" if r["is_admin"] else "false",
        "account_count": r["account_count"],
        "total_balance": r["total_balance"]
    } for r in rows]


def add_transaction(from_acc, to_acc, amount, description):
    db = get_db()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "INSERT INTO transactions (from_account, to_account, amount, description, timestamp) VALUES (?, ?, ?, ?, ?);",
        (from_acc, to_acc, amount, description, timestamp)
    )


def get_user_transactions(username):
    db = get_db()
    accounts = get_user_accounts(username)
    acc_nums = [a["account_number"] for a in accounts]
    if not acc_nums:
        return []
    placeholders = ",".join("?" * len(acc_nums))
    rows = db.execute(f"""
        SELECT * FROM transactions
        WHERE from_account IN ({placeholders}) OR to_account IN ({placeholders})
        ORDER BY timestamp DESC;
    """, acc_nums + acc_nums).fetchall()

    result = []
    for r in rows:
        from_owner = db.execute("SELECT owner FROM accounts WHERE account_number = ?;", (r["from_account"],)).fetchone()
        to_owner = db.execute("SELECT owner FROM accounts WHERE account_number = ?;", (r["to_account"],)).fetchone()
        result.append({
            "from": r["from_account"], "to": r["to_account"],
            "amount": r["amount"], "description": r["description"],
            "timestamp": r["timestamp"],
            "is_sent": r["from_account"] in acc_nums,
            "from_owner": from_owner["owner"] if from_owner else "Unknown",
            "to_owner": to_owner["owner"] if to_owner else "Unknown"
        })
    return result


def get_all_transactions():
    db = get_db()
    rows = db.execute("SELECT * FROM transactions ORDER BY timestamp DESC;").fetchall()
    result = []
    for r in rows:
        from_owner = db.execute("SELECT owner FROM accounts WHERE account_number = ?;", (r["from_account"],)).fetchone()
        to_owner = db.execute("SELECT owner FROM accounts WHERE account_number = ?;", (r["to_account"],)).fetchone()
        result.append({
            "from": r["from_account"], "to": r["to_account"],
            "amount": r["amount"], "description": r["description"],
            "timestamp": r["timestamp"],
            "from_owner": from_owner["owner"] if from_owner else "Unknown",
            "to_owner": to_owner["owner"] if to_owner else "Unknown"
        })
    return result


def generate_account_number():
    db = get_db()
    import random
    while True:
        num = f"ACC{random.randint(10000, 99999)}"
        row = db.execute("SELECT 1 FROM accounts WHERE account_number = ?;", (num,)).fetchone()
        if not row:
            return num


# ─── Initialize ──────────────────────────────────────────────────────────
initialize_database()


# ─── Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", session=make_session_dict())


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        full_name = request.form.get("full_name", "").strip()

        # FIX #4 (part): Reject commas and newlines in all fields.
        # In the vulnerable version these characters shifted CSV columns.
        for field_name, value in [("Username", username), ("Full Name", full_name), ("Email", email)]:
            if "," in value or "\n" in value or "\r" in value:
                return render_template("notice.html",
                    session=make_session_dict(),
                    message=f"{field_name} contains invalid characters (commas/newlines not allowed).",
                    redirect_url="/register",
                    redirect_text="Try Again")

        if not username or not password or not email or not full_name:
            return render_template("notice.html",
                session=make_session_dict(),
                message="All fields are required.",
                redirect_url="/register",
                redirect_text="Try Again")

        if get_user(username):
            return render_template("notice.html",
                session=make_session_dict(),
                message="Username already exists. Please choose a different username.",
                redirect_url="/register",
                redirect_text="Try Again")

        db = get_db()
        # FIX #3: Hash the password before storing it.
        # The vulnerable version wrote raw plaintext to users.txt.
        db.execute(
            "INSERT INTO users (username, password_hash, full_name, email, is_admin) VALUES (?, ?, ?, ?, 0);",
            (username, generate_password_hash(password), full_name, email)
        )

        account_num = generate_account_number()
        db.execute(
            "INSERT INTO accounts (account_number, balance, owner) VALUES (?, ?, ?);",
            (account_num, 1000.00, username)
        )

        return render_template("notice.html",
            session=make_session_dict(),
            message="Account created successfully! You can now log in.",
            redirect_url="/login",
            redirect_text="Proceed to Login")

    return render_template("register.html", session=make_session_dict())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user(username)

        # FIX #3: Use check_password_hash() instead of plaintext comparison.
        # The vulnerable version did: if user['password'] == password
        if user and check_password_hash(user["password_hash"], password):
            # FIX #1: Store user identity in a signed Flask session,
            # not in unsigned client cookies that anyone can edit.
            session.clear()
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            return render_template("notice.html",
                session=make_session_dict(),
                message="Invalid username or password. Please try again.",
                redirect_url="/login",
                redirect_text="Try Again")

    return render_template("login.html", session=make_session_dict())


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    s = make_session_dict(user)
    accounts = get_user_accounts(user["username"])
    transactions = get_user_transactions(user["username"])
    return render_template("dashboard.html",
        session=s, user=user, accounts=accounts, transactions=transactions)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    user = current_user()
    s = make_session_dict(user)
    is_admin = bool(user["is_admin"])

    if is_admin:
        from_accounts = get_all_accounts()
    else:
        from_accounts = get_user_accounts(user["username"])

    if request.method == "POST":
        from_account = request.form.get("from_account", "").strip()
        to_account = request.form.get("to_account", "").strip()
        description = request.form.get("description", "Transfer").strip()

        # FIX #2: Validate that amount is a positive number.
        # The vulnerable version did: amount = float(request.form['amount'])
        # with NO check that amount > 0. Submitting amount=-500 reversed
        # the money flow (attacker gains, victim loses).
        try:
            amount = float(request.form.get("amount", ""))
        except (ValueError, TypeError):
            return render_template("notice.html", session=s,
                message="Invalid amount. Please enter a valid number.",
                redirect_url="/transfer", redirect_text="Go Back")

        if amount <= 0:
            return render_template("notice.html", session=s,
                message="Transfer amount must be greater than zero.",
                redirect_url="/transfer", redirect_text="Go Back")

        if amount > 1000000:
            return render_template("notice.html", session=s,
                message="Transfer amount exceeds maximum limit.",
                redirect_url="/transfer", redirect_text="Go Back")

        if from_account == to_account:
            return render_template("notice.html", session=s,
                message="Source and destination accounts must be different.",
                redirect_url="/transfer", redirect_text="Go Back")

        # Authorization: non-admins can only transfer from their own accounts
        if not is_admin:
            user_account_numbers = [a["account_number"] for a in get_user_accounts(user["username"])]
            if from_account not in user_account_numbers:
                return render_template("notice.html", session=s,
                    message="You don't have permission to transfer from this account.",
                    redirect_url="/transfer", redirect_text="Go Back")

        db = get_db()

        # FIX #8: Wrap the entire read-check-write in a single transaction.
        # The vulnerable version read the balance, checked it, then wrote
        # to the file separately — two concurrent requests could both pass
        # the check and overdraw the account.
        try:
            with db_transaction(db):
                source = db.execute(
                    "SELECT * FROM accounts WHERE account_number = ?;", (from_account,)
                ).fetchone()
                dest = db.execute(
                    "SELECT * FROM accounts WHERE account_number = ?;", (to_account,)
                ).fetchone()

                if not source:
                    raise ValueError("Source account not found.")
                if not dest:
                    raise ValueError("Destination account not found.")
                if source["balance"] < amount:
                    raise ValueError(f"Insufficient funds. Available: ${source['balance']:.2f}")

                db.execute("UPDATE accounts SET balance = balance - ? WHERE account_number = ?;",
                           (amount, from_account))
                db.execute("UPDATE accounts SET balance = balance + ? WHERE account_number = ?;",
                           (amount, to_account))

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                db.execute(
                    "INSERT INTO transactions (from_account, to_account, amount, description, timestamp) VALUES (?, ?, ?, ?, ?);",
                    (from_account, to_account, amount, description, timestamp))

        except ValueError as e:
            return render_template("notice.html", session=s,
                message=str(e), redirect_url="/transfer", redirect_text="Go Back")

        # FIX #5: Use Jinja template (auto-escaped) instead of f-string HTML.
        return render_template("notice.html", session=s,
            message=f"Successfully transferred ${amount:.2f} to {to_account}",
            redirect_url="/transfer", redirect_text="Make Another Transfer")

    return render_template("transfer.html", session=s, accounts=from_accounts, is_admin=is_admin)


@app.route("/transactions")
@login_required
def transactions_page():
    user = current_user()
    s = make_session_dict(user)
    is_admin = bool(user["is_admin"])
    view_type = request.args.get("view", "personal")
    search_query = request.args.get("search", "")

    if is_admin and view_type == "all":
        transactions_list = get_all_transactions()
    else:
        transactions_list = get_user_transactions(user["username"])

    if search_query:
        transactions_list = [t for t in transactions_list if search_query.lower() in t["description"].lower()]

    return render_template("transactions.html",
        session=s, transactions=transactions_list,
        search_query=search_query, is_admin=is_admin, view_type=view_type)


@app.route("/admin")
@admin_required
def admin():
    user = current_user()
    s = make_session_dict(user)
    users = get_all_users_with_balance()
    accounts = get_all_accounts()
    transactions = get_all_transactions()
    total_balance = sum(a["balance"] for a in accounts)
    return render_template("admin.html",
        session=s, users=users, accounts=accounts,
        transactions=transactions, total_balance=total_balance)


@app.route("/admin_transfer", methods=["GET", "POST"])
@admin_required
def admin_transfer():
    user = current_user()
    s = make_session_dict(user)
    all_accounts = get_all_accounts()

    if request.method == "POST":
        from_account = request.form.get("from_account", "").strip()
        to_account = request.form.get("to_account", "").strip()
        description = request.form.get("description", "Admin Transfer").strip()

        # FIX #2: Same positive-amount validation as /transfer
        try:
            amount = float(request.form.get("amount", ""))
        except (ValueError, TypeError):
            return render_template("notice.html", session=s,
                message="Invalid amount.", redirect_url="/admin_transfer", redirect_text="Go Back")

        if amount <= 0:
            return render_template("notice.html", session=s,
                message="Transfer amount must be greater than zero.",
                redirect_url="/admin_transfer", redirect_text="Go Back")

        db = get_db()
        try:
            with db_transaction(db):
                source = db.execute("SELECT * FROM accounts WHERE account_number = ?;", (from_account,)).fetchone()
                dest = db.execute("SELECT * FROM accounts WHERE account_number = ?;", (to_account,)).fetchone()

                if not source:
                    raise ValueError("Source account not found.")
                if not dest:
                    raise ValueError("Destination account not found.")
                if source["balance"] < amount:
                    raise ValueError(f"Insufficient funds. Available: ${source['balance']:.2f}")

                db.execute("UPDATE accounts SET balance = balance - ? WHERE account_number = ?;", (amount, from_account))
                db.execute("UPDATE accounts SET balance = balance + ? WHERE account_number = ?;", (amount, to_account))

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                db.execute(
                    "INSERT INTO transactions (from_account, to_account, amount, description, timestamp) VALUES (?, ?, ?, ?, ?);",
                    (from_account, to_account, amount, description, timestamp))

        except ValueError as e:
            return render_template("notice.html", session=s,
                message=str(e), redirect_url="/admin_transfer", redirect_text="Go Back")

        return render_template("notice.html", session=s,
            message=f"Transferred ${amount:.2f} from {source['owner']} to {dest['owner']}",
            redirect_url="/admin_transfer", redirect_text="Make Another Transfer")

    return render_template("admin_transfer.html", session=s, accounts=all_accounts)


@app.route("/logout")
def logout():
    # FIX #1: Clear the server-side session (not just client cookies).
    session.clear()
    return redirect(url_for("index"))


# FIX #7: Debug mode is OFF by default.
# The vulnerable version had app.run(debug=True), which exposed the
# Werkzeug interactive debugger — giving any attacker a Python shell
# in the browser on any unhandled exception.
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(host="127.0.0.1", port=port, debug=debug)
