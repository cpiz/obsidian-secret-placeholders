# Provider setup

Secret Placeholders talks to a password manager you run. Enable the
backends you use under *Settings → Secret Placeholders → Providers*;
disabled backends contribute no UI at all.

- [OpenBao / HashiCorp Vault](#openbao--hashicorp-vault)
- [1Password Connect](#1password-connect)
- [Bitwarden / Vaultwarden](#bitwarden--vaultwarden)
- [Placeholder syntax](#placeholder-syntax)

---

## OpenBao / HashiCorp Vault

The plugin uses the **KV v2** secrets engine.

**Settings** (*Settings → Secret Placeholders → OpenBao / Vault*):

| Field | Meaning |
|---|---|
| Server address | Base URL of your OpenBao/Vault server, e.g. `https://openbao.example.com` |
| OIDC role | The `oidc` auth role to use for browser login |
| Default mount | KV mount name (default `kv`) |
| Default path prefix | Prepended to suggested paths when saving (default `obsidian/`) |
| Cache TTL | Seconds a resolved secret stays in memory |
| Remember token | Encrypt the token on disk behind a passphrase |

**Logging in:**

- **Desktop** — click *Log in*. The plugin opens your identity provider
  in the system browser, captures the callback on `127.0.0.1`, and
  exchanges it for a Vault token. This is the same loopback flow the
  `bao`/`vault` CLI uses. The listener binds port **8250**, falling back
  through **8251-8254** if a port is taken — both the OIDC auth role's
  `allowed_redirect_uris` **and your identity provider's redirect-URI
  allowlist** must include `http://localhost:<port>/oidc/callback` for
  every port you want usable; an IdP that only allows 8250 will reject
  the fallback ports in the browser before the plugin ever sees the
  callback.
- **Mobile**, or as a fallback — click *Paste token* and paste a token
  obtained from `bao login` or the Vault web UI.

Server-side you need a KV v2 mount and (for browser login) an `oidc`
auth role whose policy permits read/write on your secret paths:

```bash
bao secrets enable -path=kv -version=2 kv

bao policy write obsidian - <<'EOF'
path "kv/data/obsidian/*"     { capabilities = ["create","read","update","delete","list"] }
path "kv/metadata/obsidian/*" { capabilities = ["read","list","delete"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
EOF
```

---

## 1Password Connect

1Password Connect is a **self-hosted API gateway** in front of your
1Password account. It requires a 1Password **Business or Teams** plan —
Connect is not available on personal/family plans, and the plugin cannot
talk to 1Password without a Connect server.

1. In the 1Password admin: *Integrations → 1Password Connect Server →
   set up a new server*. Grant it access to the vaults you want to
   expose. Download `1password-credentials.json` and copy the **access
   token** shown on the same screen.
2. Run a Connect server with that credentials file (`connect-api` +
   `connect-sync` containers — see `dev/docker-compose.1p.yaml` in the
   repo).
3. In the plugin's **1Password Connect** settings, set the **Connect
   server URL**, a **default vault** name, and paste the **access
   token**.

Connect only sees the vaults you granted during setup.

---

## Bitwarden / Vaultwarden

One provider serves three things, differing only by server URL:

| Target | Server URL |
|---|---|
| Vaultwarden (self-hosted) | your instance, e.g. `https://vw.example.com` |
| Bitwarden cloud (US) | `https://vault.bitwarden.com` |
| Bitwarden cloud (EU) | `https://vault.bitwarden.eu` |

**Settings** (*Settings → Secret Placeholders → Bitwarden / Vaultwarden*):

| Field | Meaning |
|---|---|
| Server URL | as above |
| Email | your Bitwarden account email |
| Cache TTL | seconds the decrypted item list stays in memory |
| Remember session | persist the session encrypted on disk (see below) |

**Logging in:** click *Log in*, enter your email and master password.
The master password is used **locally** to derive your keys — only a
derived hash is sent to the server, never the password itself.

First login from a new device may trigger two extra prompts:

- **New-device verification** — Bitwarden cloud emails a 6-digit code.
- **Two-factor (TOTP)** — if 2FA is enabled, enter the code from your
  authenticator app.

**使用设备登录（自托管 Vaultwarden）**：配置 HTTPS 地址。若 Vaultwarden 尚未识别当前 Obsidian 安装，先用主密码登录一次。之后可在插件登录窗口选择「使用设备登录」。在已登录同一账号的 Bitwarden 客户端核对两边的指纹短语，一致时才批准。如果没收到推送，可在客户端的待处理登录请求里查看。服务器要求两步验证时，仍需输入 TOTP。取消或超时后可重新发起，也可继续使用主密码。

指纹短语使用电子前哨基金会的 [EFF 长词表](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt)，按 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) 授权使用。词表去掉了骰子编号，保留原始词序。

**Remember session:** when on, the plugin encrypts your account's
encryption key and refresh token on disk under a passphrase you choose.
On the next Obsidian start it asks for that passphrase instead of your
master password. Off by default.

Obsidian 保持运行时，插件会在访问令牌到期后按需续期。
网络故障或服务器错误会提示密钥加载失败，连接恢复后可重新打开插入窗口。
服务器拒绝会话续期时，状态栏会更新，插入窗口会提示重新登录。
关闭「记住会话」时，重启 Obsidian 后需要重新登录。

**Organizations:** items owned by a Bitwarden organization are supported
— the plugin unwraps each organization's key (via your RSA private key)
and decrypts org ciphers with it. New items you create still go to your
personal vault.

---

## Placeholder syntax

Every placeholder is `{{<prefix>:<reference>}}`. The reference shape
depends on the provider.

| Provider | Syntax | Example |
|---|---|---|
| OpenBao | `{{bao:<mount>/<path>#<key>}}` | `{{bao:kv/obsidian/github#token}}` |
| 1Password | `{{1p:<vault>/<item>#<field>}}` | `{{1p:Personal/GitHub#password}}` |
| Bitwarden | `{{vw:[<folder>/]<item>#<field>}}` | `{{vw:Work/CI#password}}` or `{{vw:GitHub#password}}` |
| Bitwarden | `{{vw://<uuid>#<field>}}` | `{{vw://550e8400-e29b-41d4-a716-446655440000#password}}` |

Notes:

- The Bitwarden **folder** segment is optional — `{{vw:GitHub#password}}`
  works for a root-level item.
- The **field** part selects which value on the item to show: `password`,
  `username`, `notes`, or any custom field label.
- References are matched **case-insensitively** but otherwise exactly. An
  item titled `GitHub - Personal` is not matched by `{{vw:GitHub#...}}`.
- A `/` inside an item title breaks the syntax (the first `/` is the
  folder separator). Rename the item, or reference it by its provider
  UUID instead of its name.

### 1Password Connect 同名项目

同一保险库内的项目名称按大小写不敏感的方式匹配。名称唯一时，浏览插入和自动补全沿用 `{{1p:保险库名/项目名#password}}`。发生冲突时，候选按创建时间从旧到新排列，创建时间缺失的项目排在最后，选择任意一条都会插入 `{{1p:保险库ID/项目ID#password}}`。
已有名称占位符匹配到多条时，读写都会提示重新选择。

### Bitwarden 同名项目

名称匹配忽略大小写。名称占位符指定目录时，在该目录内匹配；省略目录时，跨目录匹配。
浏览和自动补全按创建时间从旧到新显示同名项目。创建时间缺失的项目排在最后。
如果同名项目可以用目录区分，插入时保留名称格式。发生冲突时，选择其中任意项目都会插入 ID 占位符。
旧的名称占位符有多个匹配时会提示重新选择。

回收站项目不会出现在浏览和自动补全候选中，也不会被名称或 ID 占位符匹配。

### Bitwarden 安全笔记的自定义密码

在安全笔记中添加名为 `Password` 的自定义字段后，可用 `{{vw:项目名#password}}` 引用。同名冲突时，使用浏览插入生成的 ID 占位符。字段名忽略大小写。
登录项目中的 `#password` 读取内置密码。安全笔记的自定义 `Password` 可以在 Obsidian 中读取和复制，修改请到 Bitwarden 或 Vaultwarden 网页密码库。
