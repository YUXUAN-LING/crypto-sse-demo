# SSE 可搜索对称加密演示系统（Python + FastAPI）

本项目实现一个可运行的 **可搜索对称加密（Searchable Symmetric Encryption, SSE）** 原型系统：  
客户端将文档**加密后上传**到不可信服务器，之后仍可按关键字搜索，而服务器**看不到明文文档与明文关键字**。

> 核心思想：服务器通过匹配“查询 token”完成检索，但 token 由客户端用密钥生成，服务器无法反推关键字，也无法解密文档。

---

## 1. 项目功能

- 客户端对 `.txt` 文档进行 **AES-GCM（AEAD）加密** 后上传
- 客户端对关键字生成 **HMAC-SHA256 token（PRF）**，用于加密检索
- 服务端保存：
  - 密文文档库：`doc_id -> ciphertext`
  - 倒排索引：`token -> [doc_id...]`
- 客户端命令行（CLI）支持：
  - `init`：初始化本地密钥（keyfile / passphrase）
  - `upload`：上传目录下全部 `.txt` 文档
  - `search`：单关键字搜索并解密展示命中文档片段
  - `show`：按 `doc_id` 获取并解密展示
- 服务端数据持久化：重启不丢（`data/` 目录）
- 测试：密码学单元测试 + API 集成测试

---

## 2. 威胁模型与安全目标

### 2.1 威胁模型（Threat Model）

- 服务器被视为 **诚实但好奇（honest-but-curious）**：
  - 会按协议正常返回结果
  - 但可能试图从存储数据与查询中推断信息
- 攻击者可能完全获取服务器存储（密文 + 索引）

### 2.2 安全目标（Security Goals）

- **文档机密性**：服务器无法读取文档明文
- **关键字机密性**：服务器无法从 token 推断明文关键字
- **完整性/防篡改**：服务端篡改密文会导致客户端解密失败（AES-GCM 认证失败）

### 2.3 MVP 不覆盖的内容

- 防止恶意服务器“漏返回/拒绝服务”（MVP 不做）
- 强泄露控制（ORAM / forward-private SSE 等高级方案不做）
- 复杂查询（短语、模糊匹配、多关键字布尔检索等不做或仅作为扩展）

---

## 3. 密码学设计（原理 + 为什么这么做）

### 3.1 主密钥与密钥分离（Key Separation）

客户端维护一个主密钥 `K_master`，有两种方式：

- **口令模式（passphrase）**：passphrase → `K_master`（Scrypt / PBKDF2），salt 存本地配置
- **密钥文件模式（keyfile）**：随机生成 `K_master` 并保存到本地 keyfile（推荐录屏更省事）

然后使用 HKDF 从 `K_master` 派生子密钥：

- `K_w`：用于 HMAC 生成 token（索引/查询密钥）
- `K_f`：用于 AES-GCM 加密文档（内容加密密钥）

为什么这样做？  
同一个密钥不要同时用于不同用途（HMAC + AES），否则会破坏安全边界。HKDF 能保证**用途隔离、密钥独立**。

---

### 3.2 Token 生成（SSE 核心）

对关键字进行归一化（小写、去标点、去多余空白），然后：

token = HMAC_SHA256(K_w, normalize(keyword))
token 以 base64url 字符串形式传输/存储。

为什么用 HMAC 而不是 SHA256(keyword)？
如果用 SHA256(keyword)，服务器可以枚举常见词做字典攻击。
HMAC 使用密钥 K_w，没有密钥就无法反推关键字，token 看起来像随机串（PRF 性质）。

为什么需要 normalize？
保证 Cryptography、cryptography、cryptography. 这类输入能一致匹配，提升可用性。

### 3.3 文档加密（AES-GCM / AEAD）

文档内容使用 AES-GCM 加密：
每个文档随机生成 12 bytes nonce
使用 doc_id 作为 AAD（绑定身份，防替换）

ciphertext = AESGCM(K_f).encrypt(nonce, plaintext, aad=doc_id)

为什么选 AES-GCM？
AES-GCM 属于 AEAD：同时提供机密性 + 完整性。
任何篡改都会触发解密失败（InvalidTag），避免“密文被改你却不知道”的问题。

为什么绑定 AAD=doc_id？
防止服务器把 A 文档密文“冒充”为 B 文档密文。绑定后 AAD 不一致会认证失败。

## 4. SSE 泄露分析

基础 SSE 一般不可避免泄露以下信息：

Search Pattern（搜索模式泄露）
同一关键字重复搜索会产生同一个 token
→ 服务器知道“这是重复查询”，但不知道查询词是什么。

Access Pattern（访问模式泄露）
服务器知道 token 对应哪些 doc_id 被返回
→ 可能推断文档之间的相关性（统计信息）。

为什么系统仍然有意义？
因为我们保护了两件最关键的信息：
文档明文内容
明文关键字
而泄露的更多是“统计模式”，这在实际场景仍然具备很大隐私提升价值。

## 5. 项目结构
sse-demo/
  README.md
  requirements.txt
  .gitignore

  common/
    __init__.py
    crypto.py
    utils.py

  server/
    __init__.py
    app.py
    models.py
    settings.py
    storage.py

  client/
    __init__.py
    api.py
    cli.py
    config.py
    indexer.py

  data_samples/
    doc1.txt
    doc2.txt

  tests/
    test_crypto.py
    test_integration.py

## 6. 从 0 到跑通

### 6.1 创建 venv + 安装依赖（Windows PowerShell）
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

如果 PowerShell 报“禁止运行脚本”，执行一次：
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

### 6.2 启动 Server
uvicorn server.app:app --reload
打开 API 文档（Swagger）：
http://127.0.0.1:8000/docs

### 6.3 初始化 Client（推荐 keyfile 模式，最省事）
python -m client.cli init --mode keyfile --server-url http://127.0.0.1:8000
（可选）口令模式：
python -m client.cli init --mode passphrase --server-url http://127.0.0.1:8000

### 6.4 上传示例文档
python -m client.cli upload --dir data_samples

### 6.5 搜索关键字
python -m client.cli search --kw cryptography
python -m client.cli search --kw "cryptography."
python -m client.cli search --kw "  cryptography  "
python -m client.cli search --kw privacy
python -m client.cli search --kw security
python -m client.cli search --kw nonexistkeyword

## 7. 预期输出（示例）
客户端（Client）会打印
归一化后的关键字
token（base64url，看起来像随机串）
命中文档数量、文件名、解密后的 snippet

示例：
[info] keyword(normalized) = 'cryptography'
[info] token(base64url)    = g0DHutdyLNw6u7D...
[ok] hits: 2
- doc_id=... filename=doc1.txt snippet='...'
- doc_id=... filename=doc2.txt snippet='...'

服务端（Server）会打印
upload：doc_id、token 数量、密文长度
search：token、命中数量
不会出现明文正文（因为服务端没有密钥，无法解密）

## 8. 测试

运行测试：
pytest -q

## 9. 常见问题排查

### 9.1 端口占用（8000）
换端口启动：
uvicorn server.app:app --reload --port 8001
并在 client init 指向新端口：
python -m client.cli init --mode keyfile --server-url http://127.0.0.1:8001

### 9.2 解密失败 InvalidTag

常见原因：
passphrase 模式口令输入错误
AAD 不匹配（绑定了 doc_id）
nonce/ciphertext 被改动
派生 key 不一致（配置不一致）

### 9.3 python client/cli.py 导入失败

请使用模块方式运行：
✅ 推荐：
python -m client.cli --help
❌ 不推荐：
python client/cli.py --help

## 10. 演示视频（B 站）

Bilibili 链接：（粘贴你的链接）
https://www.bilibili.com/video/XXXXXXXXXXXX/
建议 3–5 分钟演示结构：
介绍 SSE 背景：云上存储但不信任服务器
架构：Client 持钥，Server 存密文 + token 索引
Demo：init → upload → search（强调 token 随机串、服务器无明文）
泄露分析：search/access pattern
扩展方向：动态更新、padding、forward privacy

## 11. 可扩展方向
支持删除/更新文档（动态 SSE）
padding / dummy entries 降低频率泄露
forward-private SSE（高级）
多关键字 AND/OR（客户端求交并集）
索引完整性校验（如客户端存 root hash）

## 12.个人信息
凌宇轩
学号：3125354064