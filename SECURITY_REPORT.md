# SQL 注入漏洞修复报告

## 项目名称：用户信息管理平台

**报告日期**：2026-07-08  
**项目版本**：v1.0  

---

## 1. 漏洞概述

本项目在用户注册和用户搜索两个接口中使用了 **f-string 字符串拼接** 的方式构建 SQL 语句，未对用户输入做任何过滤或转义处理，存在严重的 SQL 注入漏洞。

---

## 2. 漏洞位置

### 漏洞一：注册接口 — `/register`

**文件**：`app.py` 第 85 行（修复前）

```python
# ❌ 有注入（f-string 直接拼接用户输入）
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
c.execute(sql)
```

所有表单字段（用户名、密码、邮箱、手机号）未经任何处理直接拼接到 INSERT 语句中。

---

### 漏洞二：搜索接口 — `/search`

**文件**：`app.py` 第 105 行（修复前）

```python
# ❌ 有注入（f-string 直接拼接关键词）
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)
```

URL 参数 `keyword` 未经任何处理直接拼接到 LIKE 查询中。

---

## 3. 攻击场景演示

### 场景一：万能查询 — 泄露全部用户数据

在搜索框输入以下内容：

```
' OR 1=1 --
```

实际执行的 SQL：

```sql
SELECT id, username, email, phone FROM users 
WHERE username LIKE '%' OR 1=1 --%' OR email LIKE '%' OR 1=1 --%'
```

**结果**：`OR 1=1` 永远为真，`--` 注释掉后续 SQL，**所有用户的 ID、用户名、邮箱、手机号全部泄露**。

---

### 场景二：联合查询 — 窃取密码字段

在搜索框输入：

```
' UNION SELECT id, password, username, email FROM users --
```

实际执行的 SQL：

```sql
SELECT id, username, email, phone FROM users 
WHERE username LIKE '%' 
UNION SELECT id, password, username, email FROM users --%'
```

**结果**：通过 `UNION` 将 `password` 列映射到原本显示邮箱/手机号的列，**所有用户的密码直接显示在前端表格中**。

---

### 场景三：注册注入 — 插入伪造管理员

在注册页的用户名输入框中输入：

```
admin', 'hacked', 'hack@x.com', '10086') --
```

实际执行的 SQL：

```sql
INSERT INTO users (username, password, email, phone) 
VALUES ('admin', 'hacked', 'hack@x.com', '10086') -- ', '任意密码', '邮箱', '手机')
```

**结果**：`--` 注释掉后面的内容，成功插入一条密码已知的伪造数据。

---

### 场景四：注册注入 — 删除整个用户表

在用户名输入框中输入：

```
test'); DELETE FROM users; --
```

实际执行的 SQL：

```sql
INSERT INTO users (username, password, email, phone) 
VALUES ('test'); DELETE FROM users; --', 'xxx', 'xxx', 'xxx')
```

**结果**：先执行 INSERT，再执行 DELETE FROM users，**整个用户表被清空，所有用户数据永久丢失**。

---

## 4. 控制台日志演示

搜索接口会在后台打印实际执行的 SQL 语句，攻击过程一览无余：

```
# 正常搜索
[search] 执行 SQL: SELECT ... WHERE username LIKE '%admin%' OR email LIKE '%admin%'

# 注入攻击 — 万能查询
[search] 执行 SQL: SELECT ... WHERE username LIKE '%' OR 1=1 --%' OR email LIKE '%' OR 1=1 --%'

# 注入攻击 — 窃取密码
[search] 执行 SQL: SELECT ... WHERE username LIKE '%' UNION SELECT id, password, username, email FROM users --%'
```

---

## 5. 漏洞危害评估

| 评估项 | 评级 |
|--------|------|
| CVSS 评分 | **9.8 / 10（Critical）** |
| 攻击向量 | 网络 |
| 攻击复杂度 | **低**（无需特殊工具，浏览器即可） |
| 攻击权限要求 | **无**（未登录即可发起） |
| 机密性影响 | **完全丧失**（可读取全部数据） |
| 完整性影响 | **完全丧失**（可插入/修改/删除数据） |
| 可用性影响 | **完全丧失**（可删除表/库） |

---

## 6. 修复方案

将 **f-string 字符串拼接** 改为 **参数化查询**（Prepared Statement），使用 `?` 占位符 + 参数元组执行 SQL。

### 注册接口修复

```python
# ✅ 修复后：参数化查询
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(sql, (username, password, email, phone))
```

### 搜索接口修复

```python
# ✅ 修复后：参数化查询
like_param = f"%{keyword}%"
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(sql, (like_param, like_param))
```

---

## 7. 修复原理

参数化查询之所以能防御 SQL 注入，是因为：

| 对比项 | f-string 拼接（❌） | 参数化查询（✅） |
|--------|-------------------|-----------------|
| 用户输入处理 | 直接拼入 SQL 语句 | 通过 `?` 占位符分离 |
| 特殊字符 | 成为 SQL 语法的一部分 | 被自动转义为普通数据 |
| `' OR 1=1 --` | 变成 `LIKE '%' OR 1=1 --%'`（执行注入） | 变成 `LIKE '%\' OR 1=1 --%'`（当作普通字符串） |
| 数据库处理 | 不区分代码和数据 | 严格区分 SQL 语句和数据值 |

> 简单说：**参数化查询告诉数据库"这个位置只能是数据，不能是代码"**，从根本上杜绝了注入的可能性。

---

## 8. 修复前后代码对比

| 对比项 | 修复前 | 修复后 |
|--------|--------|--------|
| 注册 SQL | `f"VALUES ('{username}', ...)"` | `"VALUES (?, ?, ?, ?)"` + 传参 |
| 搜索 SQL | `f"LIKE '%{keyword}%'"` | `"LIKE ?"` + 传参 |
| 用户输入 `admin'--` | SQL 语法被破坏/注入成功 | 当作普通字符串 `admin'--` 安全处理 |
| 控制台日志 | 打印完整 SQL（含注入语句） | 打印 SQL 模板 + 参数（安全） |

---

## 9. 修复验证

修复后，以下攻击全部失效：

| 攻击载荷 | 修复前 | 修复后 |
|----------|--------|--------|
| `' OR 1=1 --` | 返回全部用户 | 搜索"\' OR 1=1 --"这个字符串本身 |
| `' UNION SELECT ...` | 窃取密码字段 | UNION 作为普通文本搜索，不执行 |
| `'); DELETE FROM users; --` | 清空数据库 | 插入包含特殊字符的正常用户名 |

---

## 10. 安全建议

1. **所有 SQL 语句**都应使用参数化查询，不要信任任何用户输入
2. 避免在日志中打印完整的 SQL 语句，防止敏感信息泄露
3. 定期进行代码安全审计，使用自动化工具扫描 SQL 注入
4. 遵循最小权限原则，数据库账号仅授予必要的操作权限

---

*报告结束 | 项目：用户信息管理平台 | 审核日期：2026-07-08*
