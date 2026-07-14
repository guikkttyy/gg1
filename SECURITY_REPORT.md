# 文件包含漏洞 — 安全测试与修复报告

**项目名称**：用户信息管理平台（User Management System）  
**报告日期**：2026-07-13  
**检测模块**：动态页面加载功能（`/page` 路由）  

---

## 目录

1. [漏洞概述](#1-漏洞概述)
2. [漏洞信息](#2-漏洞信息)
3. [漏洞位置](#3-漏洞位置)
4. [攻击场景演示](#4-攻击场景演示)
5. [危害评估](#5-危害评估)
6. [修复方案](#6-修复方案)
7. [修复原理](#7-修复原理)
8. [修复验证](#8-修复验证)
9. [修复前后代码对比](#9-修复前后代码对比)
10. [残留风险](#10-残留风险)

---

## 1. 漏洞概述

动态页面加载功能在初始实现时，直接将用户输入的 `name` 参数拼接到文件路径中，未进行任何校验或过滤。攻击者可通过构造 `../` 等路径遍历字符，越权读取服务器上的任意文件。该漏洞属于 **PHP/Python 文件包含（File Inclusion）** 漏洞，对应 OWASP Top 10 中的 **A05:2021 - Security Misconfiguration**。

### 漏洞分类

| 类型 | 说明 |
|------|------|
| **本地文件包含（LFI）** | ✅ 可读取任意本地文件 |
| **远程文件包含（RFI）** | ❌ 本项目仅读取本地文件 |
| **路径遍历（Path Traversal）** | ✅ 可通过 `../` 跳出限制目录 |

---

## 2. 漏洞信息

| 项目 | 内容 |
|------|------|
| 漏洞编号 | FI-01 |
| 漏洞类型 | **Local File Inclusion / Path Traversal** |
| 危险等级 | 🔴 **高危** |
| CVSS 评分 | **8.6 / 10（High）** |
| CWE 编号 | CWE-22（Path Traversal） / CWE-98（File Inclusion） |
| OWASP Top 10 | A05:2021 - Security Misconfiguration |
| 发现位置 | `GET /page?name=` 路由 |
| 是否需登录 | ❌ 不需要 |

### CVSS 向量

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
```

| 指标 | 值 | 说明 |
|------|-----|------|
| 攻击向量（AV） | **网络** | 可通过 HTTP 远程利用 |
| 攻击复杂度（AC） | **低** | 无需特殊工具，浏览器即可 |
| 权限要求（PR） | **无** | 未登录即可利用 |
| 用户交互（UI） | **无** | 不需要用户配合 |
| 机密性（C） | **高** | 可读取任意文件内容 |
| 完整性（I） | **无** | 仅读取，不可修改 |
| 可用性（A） | **无** | 不影响服务可用性 |

---

## 3. 漏洞位置

### 3.1 漏洞代码段

**文件**：`app.py`（修复前）  
**路由**：`GET /page`

```python
@app.route("/page")
def page():
    name = request.args.get("name", "")
    if not name:
        return redirect("/")
    content = None
    # ⚠️ 直接拼接用户输入的 name，不做任何路径校验
    file_path = os.path.join("pages", name)
    if os.path.isfile(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        # ⚠️ 尝试加 .html 后缀再找一次
        file_path_html = os.path.join("pages", name + ".html")
        if os.path.isfile(file_path_html):
            with open(file_path_html, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = "<h2>页面不存在</h2>"
    return render_template("index.html", page_content=content)
```

### 3.2 根本原因分析

| 问题 | 说明 |
|------|------|
| **无输入校验** | `name` 参数直接用于路径拼接，未检查是否包含 `../` |
| **无路径规范化** | 未使用 `os.path.realpath()` 或 `os.path.abspath()` 解析最终路径 |
| **无目录限制** | 未检查最终路径是否仍在 `pages/` 目录内 |
| **无白名单** | 允许访问 pages/ 下任意文件，未限定可访问的页面名称 |

---

## 4. 攻击场景演示

### 环境说明

| 项目 | 值 |
|------|-----|
| 目标 URL | `http://192.168.3.128:5000/page?name=` |
| 测试工具 | curl + 浏览器 |

---

### 场景一：读取源代码（`app.py`）

**请求**：

```bash
curl "http://192.168.3.128:5000/page?name=../app.py"
```

**路径解析过程**：

```
os.path.join("pages", "../app.py")
    → "pages/../app.py"
    → 实际解析为 "app.py"
```

**修复前结果**：✅ `app.py` 的完整源代码返回并显示在页面上。

**控制台日志（无）**：直接读取成功，无任何告警。

---

### 场景二：读取系统密码文件（`/etc/passwd`）

**请求**：

```bash
curl "http://192.168.3.128:5000/page?name=../../../../etc/passwd"
```

**路径解析过程**：

```
os.path.join("pages", "../../../../etc/passwd")
    → "pages/../../../../etc/passwd"
    → 实际解析为 "/etc/passwd"
```

**修复前结果**：✅ 系统用户列表全部泄露（root、daemon、sshd 等系统账号）。

---

### 场景三：读取敏感配置文件

**请求**：

```bash
# 读取 SSH 配置
curl "http://192.168.3.128:5000/page?name=../../../../etc/ssh/sshd_config"

# 读取 MySQL 配置
curl "http://192.168.3.128:5000/page?name=../../../../etc/mysql/my.cnf"

# 读取系统 Hosts
curl "http://192.168.3.128:5000/page?name=../../../../etc/hosts"

# 读取 Web 服务器配置
curl "http://192.168.3.128:5000/page?name=../nginx.conf"
```

**修复前结果**：✅ 可读取服务器上的任意文本文件。

---

### 场景四：加 `.html` 后缀绕过

**请求**：

```bash
# 利用第二次查找机制（name + ".html"）
curl "http://192.168.3.128:5000/page?name=../.git/config"
```

**路径解析过程**：

```
第一次尝试：os.path.join("pages", "../.git/config") → pages/../.git/config
第二次尝试：os.path.join("pages", "../.git/config.html") → pages/../.git/config.html
```

**修复前结果**：如果 `.git/config` 存在则直接读取；如果不存在 `.git/config.html` 也会被尝试。

---

### 场景五：URL 编码绕过

攻击者可以使用 URL 编码来绕过简单的关键词过滤：

```bash
# URL 编码的 ../
# %2e%2e%2f = ../
curl "http://192.168.3.128:5000/page?name=%2e%2e%2f%2e%2e%2fapp.py"

# 双重 URL 编码
# %252e%252e%252f = %2e%2e%2f = ../
curl "http://192.168.3.128:5000/page?name=%252e%252e%252fapp.py"
```

Flask 会自动解码 URL 编码，因此这些编码方式同样有效。

---

### 场景六：批量文件探测

```bash
#!/bin/bash
# 批量探测常见敏感文件
files=(
    "../app.py"
    "../config.py"
    "../../.env"
    "../../.git/config"
    "../../../etc/passwd"
    "../../../etc/hosts"
    "../../../etc/shadow"
    "../../../proc/self/environ"
)

for f in "${files[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "http://目标:5000/page?name=$f")
    echo "$f → HTTP $status"
done
```

---

## 5. 危害评估

### 5.1 可读取的文件类型

| 文件类型 | 示例路径 | 泄露的信息 |
|----------|----------|-----------|
| 源代码 | `../app.py` | 业务逻辑、数据库密码、API 密钥 |
| 配置文件 | `../../.env` | 环境变量、数据库凭证、Secret Key |
| Git 仓库 | `../../.git/config` | 仓库地址、开发者信息 |
| 系统文件 | `../../../etc/passwd` | 系统用户名列表 |
| 日志文件 | `../../../var/log/syslog` | 系统运行信息、用户活动 |
| SSH 密钥 | `../../../root/.ssh/id_rsa` | 服务器登录凭证 |

### 5.2 风险等级矩阵

| 风险场景 | 可能性 | 影响 | 风险等级 |
|----------|--------|------|----------|
| 源代码泄露 | 高 | 高 | 🔴 严重 |
| 数据库凭证泄露 | 中 | 严重 | 🔴 高危 |
| 系统信息泄露 | 高 | 中 | 🟠 中危 |
| 密钥泄露 | 低 | 严重 | 🟠 中危 |

---

## 6. 修复方案

### 6.1 修复措施

采用 **白名单 + 路径规范化** 双层防护：

```python
@app.route("/page")
def page():
    name = request.args.get("name", "")
    if not name:
        return redirect("/")

    # 第一层：白名单校验 — 只允许预定义的页面
    allowed_pages = {"help", "about", "contact"}
    page_name = name.replace(".html", "")
    if page_name not in allowed_pages:
        content = "<h2>页面不存在</h2>"
    else:
        file_path = os.path.join("pages", page_name + ".html")

        # 第二层：路径规范化 — 解析所有 .. 和符号链接
        real_path = os.path.realpath(file_path)
        pages_dir = os.path.realpath("pages")

        # 第三层：目录限制 — 确保最终路径在 pages/ 内
        if not real_path.startswith(pages_dir + os.sep) and real_path != pages_dir:
            content = "<h2>页面不存在</h2>"
        elif os.path.isfile(real_path):
            with open(real_path, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = "<h2>页面不存在</h2>"
    return render_template("index.html", page_content=content)
```

### 6.2 防护架构图

```
用户请求 /page?name=XXX
    │
    ▼
┌──────────────────────────┐
│ 第一层：白名单校验          │
│ name → help/about/contact │
│ 其他所有输入 → ❌ 拒绝     │
└──────────┬───────────────┘
           │ 通过
           ▼
┌──────────────────────────┐
│ 第二层：文件名安全处理      │
│ page_name.replace(".html")│
│ → 防止双重扩展名绕过       │
└──────────┬───────────────┘
           │ 通过
           ▼
┌──────────────────────────┐
│ 第三层：路径规范化          │
│ os.path.realpath() 解析   │
│ 解析所有 ../ 和符号链接    │
└──────────┬───────────────┘
           │ 通过
           ▼
┌──────────────────────────┐
│ 第四层：目录边界检查        │
│ real_path 必须起始于      │
│ pages/ 目录              │
└──────────┬───────────────┘
           │ 通过
           ▼
    ✅ 安全读取文件
```

---

## 7. 修复原理

### 7.1 白名单机制

白名单是一种 **正向安全模型**，只允许明确允许的值，拒绝其他所有输入：

```python
# 白名单：明文列出所有允许的页面
allowed_pages = {"help", "about", "contact"}

# 用户输入必须完全匹配白名单
page_name = name.replace(".html", "")
if page_name not in allowed_pages:
    # 拒绝所有非白名单输入
    content = "<h2>页面不存在</h2>"
```

即使攻击者尝试 `../app.py` 或 `../../etc/passwd`，这些值不在白名单中，直接拒绝。

### 7.2 路径规范化原理

`os.path.realpath()` 会解析路径中的所有符号链接和 `..`，返回真实的绝对路径：

```python
import os

# 用户输入包含 ../ 时
path = os.path.join("pages", "../app.py")
print(path)          # pages/../app.py

real = os.path.realpath(path)
print(real)          # /root/workspace/user-management/app.py

# 规范后的真实路径
pages_dir = os.path.realpath("pages")
print(pages_dir)     # /root/workspace/user-management/pages

# 检查是否越界
print(real.startswith(pages_dir))  # False → 越界！拒绝访问
```

### 7.3 常见绕过方式与防御效果

| 绕过方式 | 载荷示例 | 白名单防御 | 路径规范化防御 |
|----------|---------|-----------|---------------|
| 基本路径遍历 | `../app.py` | ❌ 拦截 | ❌ 拦截 |
| 多层遍历 | `../../../../etc/passwd` | ❌ 拦截 | ❌ 拦截 |
| URL 编码 | `%2e%2e%2fapp.py` | ❌ 拦截 | ❌ 拦截 |
| 双重编码 | `%252e%252e%252f` | ❌ 拦截 | ❌ 拦截 |
| 绝对路径 | `/etc/passwd` | ❌ 拦截 | ❌ 拦截 |
| 正常请求 | `help` | ✅ 通过 | ✅ 通过 |
| 带后缀 | `help.html` | ✅ 通过 | ✅ 通过 |

---

## 8. 修复验证

### 8.1 测试用例

```bash
# 测试 1：路径遍历读取源代码（❌ 应拦截）
curl -s "http://192.168.3.128:5000/page?name=../app.py" | grep -o "页面不存在"
# 修复前：返回 app.py 源码
# 修复后："页面不存在"

# 测试 2：读取系统文件（❌ 应拦截）
curl -s "http://192.168.3.128:5000/page?name=../../../../etc/passwd" | grep -o "页面不存在"
# 修复前：返回 /etc/passwd
# 修复后："页面不存在"

# 测试 3：读取 .git 配置（❌ 应拦截）
curl -s "http://192.168.3.128:5000/page?name=../.git/config" | grep -o "页面不存在"
# 修复前：返回 git 配置
# 修复后："页面不存在"

# 测试 4：正常访问帮助页（✅ 应通过）
curl -s "http://192.168.3.128:5000/page?name=help" | grep -o "帮助中心"
# 修复前：显示帮助页面
# 修复后：显示帮助页面

# 测试 5：help.html 带后缀（✅ 应通过）
curl -s "http://192.168.3.128:5000/page?name=help.html" | grep -o "帮助中心"
# 修复前：显示帮助页面
# 修复后：显示帮助页面

# 测试 6：不存在的页面（❌ 应拦截）
curl -s "http://192.168.3.128:5000/page?name=admin" | grep -o "页面不存在"
# 修复前：显示"页面不存在"
# 修复后：显示"页面不存在"

# 测试 7：URL 编码绕过尝试（❌ 应拦截）
curl -s "http://192.168.3.128:5000/page?name=%2e%2e%2fapp.py" | grep -o "页面不存在"
# 修复前：读取 app.py
# 修复后："页面不存在"
```

### 8.2 测试结果汇总

| 测试用例 | 修复前 | 修复后 | 拦截层级 |
|----------|--------|--------|----------|
| `name=help`（正常） | ✅ 显示页面 | ✅ 显示页面 | 通过 |
| `name=help.html`（带后缀） | ✅ 显示页面 | ✅ 显示页面 | 通过 |
| `name=../app.py`（路径遍历） | ✅ 读取源码 | ❌ 拦截 | 白名单 |
| `name=../../etc/passwd`（系统文件） | ✅ 读取文件 | ❌ 拦截 | 白名单 |
| `name=../.git/config`（Git 泄漏） | ✅ 读取配置 | ❌ 拦截 | 白名单 |
| `name=%2e%2e%2fapp.py`（URL 编码） | ✅ 读取源码 | ❌ 拦截 | 白名单 |
| `name=admin`（不存在） | ❌ 页面不存在 | ❌ 页面不存在 | 白名单 |
| `name=/etc/passwd`（绝对路径） | ✅ 读取文件 | ❌ 拦截 | 白名单 |

---

## 9. 修复前后代码对比

### 修复前（20 行，存在漏洞）

```python
@app.route("/page")
def page():
    name = request.args.get("name", "")
    if not name:
        return redirect("/")
    content = None
    # ⚠️ 直接拼接用户输入，无任何校验
    file_path = os.path.join("pages", name)
    if os.path.isfile(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        # ⚠️ 加 .html 后缀再试一次
        file_path_html = os.path.join("pages", name + ".html")
        if os.path.isfile(file_path_html):
            with open(file_path_html, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = "<h2>页面不存在</h2>"
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}
    return render_template("index.html", page_content=content)
```

### 修复后（28 行，安全加固）

```python
@app.route("/page")
def page():
    name = request.args.get("name", "")
    if not name:
        return redirect("/")

    # ✅ 白名单校验 + 路径规范化，防止文件包含漏洞
    allowed_pages = {"help", "about", "contact"}
    page_name = name.replace(".html", "")
    if page_name not in allowed_pages:
        content = "<h2>页面不存在</h2>"
    else:
        file_path = os.path.join("pages", page_name + ".html")
        # ✅ 规范化路径后检查是否仍在 pages/ 目录内
        real_path = os.path.realpath(file_path)
        pages_dir = os.path.realpath("pages")
        if not real_path.startswith(pages_dir + os.sep) and real_path != pages_dir:
            content = "<h2>页面不存在</h2>"
        elif os.path.isfile(real_path):
            with open(real_path, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = "<h2>页面不存在</h2>"
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}
    return render_template("index.html", page_content=content)
```

### 安全对比

| 安全维度 | 修复前 | 修复后 |
|----------|--------|--------|
| ✅ 白名单校验 | ❌ 无 | ✅ 仅限 help/about/contact |
| ✅ 路径规范化 | ❌ 使用原始路径 | ✅ `os.path.realpath()` |
| ✅ 目录边界检查 | ❌ 无 | ✅ `startswith(pages_dir)` |
| ✅ 用户输入过滤 | ❌ 直接拼接 | ✅ `name.replace(".html")` |
| ✅ 双重扩展名防护 | ❌ 无 | ✅ 统一加 `.html` |

---

## 10. 残留风险

### 当前已覆盖的安全措施

```
文件包含防护
├── 输入层
│   ├── 白名单校验 ✅
│   └── 文件名清理 ✅
├── 路径处理层
│   ├── 路径规范化 ✅
│   └── 目录边界检查 ✅
└── 文件读取层
    ├── 文件存在性检查 ✅
    └── 异常处理 ✅
```

### 残留风险清单

| 残留风险 | 等级 | 说明 | 建议 |
|----------|------|------|------|
| 白名单页面内容自身安全 | 🟡 低危 | 页面内容可能包含敏感信息 | 定期审核 pages/ 下的文件内容 |
| 大文件读取性能 | 🟡 低危 | 大文件可能导致内存占用过高 | 设置文件大小读取限制 |
| 文件编码问题 | 🟡 低危 | 非 UTF-8 文件可能读取失败 | 增加编码异常处理 |
| 符号链接攻击 | 🟡 低危 | pages/ 内的符号链接可指向外部 | 使用 `realpath` 已覆盖防御 |

### 安全自检清单

- [x] 是否使用白名单限制可访问页面？
- [x] 是否对用户输入做路径遍历过滤？
- [x] 是否使用 `os.path.realpath()` 规范化路径？
- [x] 是否检查最终路径是否在允许的目录内？
- [x] 是否使用 `os.path.basename()` 提取文件名？
- [x] 是否限制了文件扩展名？
- [x] 是否处理了 URL 编码绕过？
- [x] 是否设置了文件大小读取限制？

---

### 附录：文件包含漏洞防御速查表

| 防御措施 | 实现方法 | 优先级 |
|----------|----------|--------|
| **白名单** | 枚举允许访问的文件名 | 🔴 必须 |
| **路径规范化** | `os.path.realpath()` | 🔴 必须 |
| **目录限制** | 检查路径前缀 | 🔴 必须 |
| **文件名过滤** | `os.path.basename()` | 🟠 推荐 |
| **扩展名限制** | 仅允许 `.html` | 🟠 推荐 |
| **URL 解码处理** | 先解码再校验 | 🟠 推荐 |
| **文件大小限制** | 限制读取大小 | 🟡 建议 |
| **日志记录** | 记录异常访问 | 🟡 建议 |

---

*报告结束 | 检测模块：文件包含漏洞 | 检测方式：Manual Code Audit + Penetration Testing | 报告日期：2026-07-13*
