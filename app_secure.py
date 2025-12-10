from flask import Flask, request, session, redirect, render_template_string, escape
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

# 🔒 Secret key قوي
app.secret_key = os.urandom(24)

# 🔒 أمان الكوكيز
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # ضع True إذا استخدمت https
)

DB_NAME = "dictionary.db"

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS words (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            word TEXT,
            meaning TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

init_db()

@app.route("/")
def index():
    if "user" not in session:
        return redirect("/login")
    return redirect("/dictionary")

@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # 🔒 Password policy: طول >= 6
        if not username or not password or len(password) < 6:
            msg = "Username or password too short!"
        else:
            hashed_pw = generate_password_hash(password)
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
                conn.commit()
                conn.close()
                msg = "User registered successfully!"
            except sqlite3.IntegrityError:
                msg = "Username already exists!"

    html = """
    <h2>Register</h2>
    <form method="POST">
        Username: <input name="username"><br>
        Password: <input type="password" name="password"><br>
        <button>Register</button>
    </form>
    <p>{{msg}}</p>
    <a href="/login">Go to Login</a>
    """
    return render_template_string(html, msg=msg)

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user"] = username
            return redirect("/dictionary")
        else:
            msg = "Invalid credentials"

    html = """
    <h2>Login</h2>
    <form method="POST">
        Username: <input name="username"><br>
        Password: <input type="password" name="password"><br>
        <button>Login</button>
    </form>
    <p>{{msg}}</p>
    <a href="/register">Create Account</a>
    """
    return render_template_string(html, msg=msg)

@app.route("/dictionary", methods=["GET", "POST"])
def dictionary():
    if "user" not in session:
        return redirect("/login")

    msg = ""
    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add":
            word = request.form.get("word")
            meaning = request.form.get("meaning")
            # 🔒 منع XSS
            c.execute("INSERT INTO words (word, meaning) VALUES (?, ?)", (word, meaning))
            conn.commit()
            msg = "Word added!"

        elif action == "search":
            search_word = request.form.get("search_word")
            c.execute("SELECT word, meaning FROM words WHERE word = ?", (search_word,))
            rows = c.fetchall()
            if rows:
                # 🔒 Escape user input
                msg = "<br>".join([f"<b>{escape(w['word'])}</b>: {escape(w['meaning'])}" for w in rows])
            else:
                msg = "No results found"

    conn.close()

    html = """
    <h2>Mini Dictionary</h2>

    <p>Logged in as: {{session['user']}}</p>
    <a href="/logout">Logout</a>

    <h3>Add Word</h3>
    <form method="POST">
        Word: <input name="word"><br>
        Meaning: <textarea name="meaning"></textarea><br>
        <button name="action" value="add">Add Word</button>
    </form>

    <h3>Search Word</h3>
    <form method="POST">
        <input name="search_word"><br>
        <button name="action" value="search">Search</button>
    </form>

    <hr>
    <p>{{msg|safe}}</p>
    """
    return render_template_string(html, msg=msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)