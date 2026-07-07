from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

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
    return render_template("index.html", username=username, user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            # 登录后不将密码传到模板
            user_info = {k: v for k, v in USERS[username].items() if k != "password"}
            return render_template("index.html", username=username, user=user_info)
        else:
            error = "用户名或密码错误，请重新输入"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="192.168.139.128", port=5000, debug=True)
