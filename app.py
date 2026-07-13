from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


@app.context_processor
def inject_current_user_id():
    username = session.get("username")
    uid = None
    if username and username in USERS:
        uid = USERS[username].get("id")
    return dict(current_user_id=uid)

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
    # 插入默认用户（密码哈希存储）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", generate_password_hash("Admin@123456"), "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", generate_password_hash("Alice@2025!Secure"), "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    print("[init_db] 数据库初始化完成，默认用户已插入")

USERS = {
    "admin": {
        "id": 1,
        "username": "admin",
        "password": generate_password_hash("Admin@123456"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 9999900
    },
    "alice": {
        "id": 2,
        "username": "alice",
        "password": generate_password_hash("Alice@2025!Secure"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 10000
    }
}


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}
    return render_template("index.html", username=username, user=user_info, search_results=None, keyword="", page_content=None)


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
            return render_template("index.html", username=username, user=user_info, search_results=None, keyword="", page_content=None)
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
        hashed_pw = generate_password_hash(password)
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[register] 执行 SQL: {sql} 参数: ({username}, [HASHED], {email}, {phone})")
        try:
            c.execute(sql, (username, hashed_pw, email, phone))
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
    if "username" not in session:
        return redirect("/login")
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
    return render_template("index.html", username=username, user=user_info, search_results=results, keyword=keyword, page_content=None)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")
    error = None
    file_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # 1. 路径遍历防护：过滤文件名，只取原始名称，去除路径
            safe_filename = os.path.basename(f.filename)

            # 2. 检查文件扩展名，只允许图片类型
            allowed_extensions = {"jpg", "jpeg", "png", "gif", "webp", "bmp"}
            ext = safe_filename.rsplit(".", 1)[-1].lower() if "." in safe_filename else ""
            if ext not in allowed_extensions:
                error = "仅允许上传图片文件（jpg, jpeg, png, gif, webp, bmp）"
                return render_template("upload.html", error=error, file_url=file_url)

            # 3. 检查 MIME 类型
            allowed_mime = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp"}
            if f.mimetype and f.mimetype not in allowed_mime:
                error = f"不支持的文件类型（MIME: {f.mimetype}）"
                return render_template("upload.html", error=error, file_url=file_url)

            # 4. 读取文件头部检查 magic bytes（文件内容签名）
            magic_bytes = f.read(8)
            f.seek(0)
            is_valid_image = False
            if ext == "jpg" or ext == "jpeg":
                if magic_bytes.startswith(b"\xff\xd8\xff"):
                    is_valid_image = True
            elif ext == "png":
                if magic_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                    is_valid_image = True
            elif ext == "gif":
                if magic_bytes.startswith(b"GIF87a") or magic_bytes.startswith(b"GIF89a"):
                    is_valid_image = True
            elif ext == "webp":
                if magic_bytes.startswith(b"RIFF") and magic_bytes[4:8] == b"WEBP":
                    is_valid_image = True
            elif ext == "bmp":
                if magic_bytes.startswith(b"BM"):
                    is_valid_image = True
            if not is_valid_image:
                error = "文件内容与扩展名不匹配，请上传真实图片文件"
                return render_template("upload.html", error=error, file_url=file_url)

            # 5. 使用 UUID 重命名文件，防止文件名冲突和覆盖
            import uuid
            new_filename = f"{uuid.uuid4().hex}.{ext}"
            upload_dir = os.path.join(app.root_path, "static", "uploads")
            os.makedirs(upload_dir, exist_ok=True)
            save_path = os.path.join(upload_dir, new_filename)
            f.save(save_path)
            file_url = f"/static/uploads/{new_filename}"
        else:
            error = "请选择一个文件"
    return render_template("upload.html", error=error, file_url=file_url)


@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect("/login")
    login_username = session.get("username")
    login_user = USERS.get(login_username)
    if not login_user:
        return redirect("/login")

    # 只允许查看自己的资料，拒绝越权访问
    user_id = request.args.get("user_id", type=int)
    if not user_id or user_id != login_user["id"]:
        return redirect(f"/profile?user_id={login_user['id']}")

    user_data = {k: v for k, v in login_user.items() if k != "password"}
    return render_template("profile.html", user=user_data, msg=request.args.get("msg"), error=request.args.get("error"))


@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect("/login")
    login_username = session.get("username")
    login_user = USERS.get(login_username)
    if not login_user:
        return redirect("/login")

    # 只能给自己的账号充值，从 session 获取 user_id
    user_id = login_user["id"]
    amount_yuan = request.form.get("amount", type=float, default=0)

    # 校验金额必须为正数
    if amount_yuan <= 0:
        return redirect(f"/profile?user_id={user_id}&error=金额必须大于0")

    # 转换为整数分，避免浮点数精度问题
    amount_cents = int(round(amount_yuan * 100))

    for u in USERS.values():
        if u["id"] == user_id:
            u["balance"] = u["balance"] + amount_cents
            break
    return redirect(f"/profile?user_id={user_id}&msg=充值成功")


@app.route("/page")
def page():
    name = request.args.get("name", "")
    if not name:
        return redirect("/")

    # 白名单校验 + 路径规范化，防止文件包含漏洞
    allowed_pages = {"help", "about", "contact"}
    page_name = name.replace(".html", "")
    if page_name not in allowed_pages:
        content = "<h2>页面不存在</h2><p>抱歉，您请求的页面未找到。</p>"
    else:
        file_path = os.path.join("pages", page_name + ".html")
        # 规范化路径后检查是否仍在 pages/ 目录内
        real_path = os.path.realpath(file_path)
        pages_dir = os.path.realpath("pages")
        if not real_path.startswith(pages_dir + os.sep) and real_path != pages_dir:
            content = "<h2>页面不存在</h2><p>抱歉，您请求的页面未找到。</p>"
        elif os.path.isfile(real_path):
            with open(real_path, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = "<h2>页面不存在</h2><p>抱歉，您请求的页面未找到。</p>"
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}
    return render_template("index.html", username=username, user=user_info, search_results=None, keyword="", page_content=content)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
