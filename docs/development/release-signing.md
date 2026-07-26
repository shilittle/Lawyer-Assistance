# Windows 发布签名 / Windows release signing

本文说明 Lawyer Assistance 的稳定 Windows 发布流程。发布凭据必须来自独立的
release secret store，不得提交到仓库、Release 资产、日志或构建清单。

## 发布类型

- `release:installer:unsigned`：生成明确标注为未签名的技术预发布安装包，不生成
  updater 签名或 `latest.json`。
- `release:signed`：要求有效的 Authenticode 代码签名证书和 Tauri updater 私钥，
  生成可信发布者安装包、updater 签名、`latest.json` 与签名 portable 包。

未签名安装包不得改名为签名安装包，也不得发布 updater 元数据。

## 正式签名发布

在干净、已提交的 release commit 上设置凭据引用：

```powershell
$env:LAWYER_ASSISTANCE_CODE_SIGNING_THUMBPRINT = "<CODE_SIGNING_CERT_THUMBPRINT>"
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "<UPDATER_KEY_PASSWORD>"
```

updater 私钥默认位于忽略目录：

```text
.release-secrets/lawyer-assistance-updater.key
```

先运行预检：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\release\release_preflight.ps1 `
  -Mode Preflight -Check All
```

预检成功后构建并复验：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\release\release_preflight.ps1 `
  -Mode Run -Check All
```

脚本会核对干净工作树、证书有效期和私钥可读性、updater 凭据、固定仓库与版本、
Authenticode、installer/updater 绑定及 portable SHA-256。它不会输出证书私钥、
updater 私钥或密码。

失败后只清理固定的生成物：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File scripts\release\release_preflight.ps1 `
  -Mode Cleanup
```

清理流程不会删除或轮换证书、私钥和源文件。

## English

Run releases only from a clean, committed source tree. The unsigned workflow
produces an explicitly unsigned technical-prerelease installer and never emits
updater metadata. The signed workflow requires a valid Authenticode certificate
with a readable private key plus the Tauri updater private key and password.

Use `scripts/release/release_preflight.ps1` with `Preflight`, then `Run`. Release
credentials must stay in an external secret store and must never be committed,
uploaded, logged, or embedded in manifests. `Cleanup` removes only fixed build
outputs and transient signing configuration.
