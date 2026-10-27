
"""
PSU-ClinicLab - CYS402 Secure Software Development
SQL injection remediation version.

Run only on your local coursework environment.
"""
import os
import sqlite3

from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

DB_PATH = os.environ.get(
    "PSUCLINIC_DB",
    os.path.join(os.path.dirname(__file__), "psuclinic_vuln.db"),
)

app = Flask(
    __name__,
    template_folder=os.path.join(
        os.path.dirname(__file__), "templates"
    ),
)

# Retained for this step; secure secret-key configuration is a separate fix.
app.secret_key = "hardcoded-dev-secret-123"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # Parameterized query: input is treated as data, not SQL.
        row = get_db().execute(
            "SELECT * FROM users WHERE email = ? AND password = ?",
            (email, password),
        ).fetchone()

        if row:
            session["user"] = row["email"]
            session["role"] = row["role"]
            return redirect(url_for("dashboard"))

        error = "Invalid credentials."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    rows = get_db().execute(
        "SELECT * FROM appointments WHERE patient_email = ?",
        (session["user"],),
    ).fetchall()

    return render_template(
        "dashboard.html",
        user=session["user"],
        appts=rows,
    )


@app.route("/search")
def search():
    term = request.args.get("q", "")
    results = []

    if term:
        # Parameterized LIKE query prevents SQL injection in the filter.
        results = get_db().execute(
            "SELECT * FROM appointments WHERE reason LIKE ?",
            (f"%{term}%",),
        ).fetchall()

    return render_template(
        "search.html",
        term=term,
        results=results,
    )


@app.route("/book", methods=["GET", "POST"])
def book():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        reason = request.form.get("reason", "")
        date = request.form.get("date", "")

        # Existing insert already uses parameters.
        get_db().execute(
            "INSERT INTO appointments (patient_email, date, reason) "
            "VALUES (?, ?, ?)",
            (session["user"], date, reason),
        )
        get_db().commit()

        return redirect(url_for("dashboard"))

    return render_template("book.html")


@app.route("/admin")
def admin():
    # Role authorization is a separate remediation task.
    if "user" not in session:
        return redirect(url_for("login"))

    users = get_db().execute(
        "SELECT email, role FROM users"
    ).fetchall()
    appts = get_db().execute(
        "SELECT * FROM appointments"
    ).fetchall()

    return render_template(
        "admin.html",
        users=users,
        appts=appts,
    )


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        from seed import seed

        seed(DB_PATH)

    app.run(host="127.0.0.1", port=5000, debug=True)
