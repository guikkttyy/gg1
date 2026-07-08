from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# ========== SQLite 数据库初始化 ==========

def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT
    )''')
    # 插入默认用户
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')")
    conn.commit()
    conn.close()
    print("[init_db] 数据库初始化完成，默认用户已插入")

USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("Admin@123456"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("Alice@2025!Secure"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}
    return render_template("index.html", username=username, user=user_info, search_results=None, keyword="")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    msg = request.args.get("msg", "")
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            # 登录后不将密码传到模板
            user_info = {k: v for k, v in USERS[username].items() if k != "password"}
            return render_template("index.html", username=username, user=user_info, search_results=None, keyword="")
        else:
            error = "用户名或密码错误，请重新输入"
    return render_template("login.html", error=error, msg=msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[register] 执行 SQL: {sql} 参数: ({username}, {password}, {email}, {phone})")
        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
            conn.close()
            return redirect("/login?msg=注册成功，请登录")
        except Exception as e:
            print(f"[register] 错误: {e}")
            conn.close()
            return render_template("register.html", error=f"注册失败: {e}")
    return render_template("register.html")


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    like_param = f"%{keyword}%"
    sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
    print(f"[search] 执行 SQL: {sql} 参数: ('{like_param}', '{like_param}')")
    c.execute(sql, (like_param, like_param))
    results = [dict(row) for row in c.fetchall()]
    conn.close()
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}
    return render_template("index.html", username=username, user=user_info, search_results=results, keyword=keyword)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(host="192.168.139.128", port=5000, debug=True)
