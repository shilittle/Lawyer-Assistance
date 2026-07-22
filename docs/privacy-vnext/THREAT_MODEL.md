# 脱敏系统 vNext 威胁模型

## 1. 保护资产

- 原始案卷 bytes、原路径、原文件名。
- OCR 原始文本、页面图像、中间产物。
- 真实主体词典、redaction mapping、cluster private values。
- per-case data key、receipt/manifest signing key。
- 待复核和未批准内容。
- approved material 的完整性、版本和撤销状态。
- WorkBuddy 生成的匿名 work products。
- hash-only audit chain 和 qualification evidence。

## 2. 信任主体

### 高信任

- Windows Vault Broker 或当前阶段的 App native backend。
- 受控本地 MinerU worker 的 exact qualified binary/model/config。
- Workspace Publisher。

### 受限信任

- Tauri WebView：可查看用户当前复核所需内容，但不得持有 key、vault path 或长期 receipt。
- Approved MCP：只读 approved、读写 work-products，不得读 vault。
- WorkBuddy/Provider：只能收到 MCP 当前调用返回的 approved redacted content。

### 不信任

- 任意用户粘贴、附件、标签或口头“已脱敏”声明。
- 任意路径、URI、symlink、junction、reparse point、云盘占位文件。
- 任意网络 OCR、SSH、远程 MinerU、Provider 回退。
- 未签名或 hash 不匹配的 worker/model/manifest/qualification。
- 与 formal App 未成对绑定、仅复制 sibling 文件名/版本/canary 行为的 MCP 二进制。
- 同用户恶意进程；在没有独立服务身份时属于明确剩余风险。

## 3. 信任边界

1. 文件选择器 → Vault import。
2. Vault decrypt stream → extraction/OCR job root。
3. OCR result → completeness validator。
4. private finding payload → redacted public draft。
5. review state → unified approval publisher。
6. signed approved generation → MCP verifier。
7. MCP output → WorkBuddy/Provider。
8. Provider work product → MCP write validator。

任何边界失败均返回匿名错误码，不能回显正文、路径、文件名或候选值。

## 4. 主要攻击与控制

### 4.1 原件窃取

攻击：WorkBuddy、宿主文件工具、同用户进程或索引服务读取 vault。

控制：

- vault 不在 WorkBuddy 授权根内。
- 随机对象名和 AES-256-GCM。
- Windows 服务 SID/DACL 为目标强隔离。
- 当前用户边界模式显示准确警告。
- NOT_CONTENT_INDEXED、云盘/reparse/网络盘检测。
- MCP schema 不暴露路径。

剩余风险：DPAPI CurrentUser 与同用户 ACL 不能防御恶意同用户进程；只有独立服务身份资格可以关闭此风险。

### 4.2 密文替换与 nonce 重用

攻击：跨 case/object 交换密文、截断、修改 header、重复 nonce。

控制：

- AAD 绑定 workspace、case、object、kind、version、chunk。
- 每对象随机 nonce；导入记录 nonce digest 并拒绝重复。
- tag 校验失败一律匿名阻断。
- source metadata 和 ciphertext hash 在私有 manifest 交叉绑定。

### 4.3 OCR 外发与逃逸

攻击：worker 联网、读取任意文件、隐式下载、启动子进程树、在临时目录遗留原件。

控制：

- worker 只接受授权 job root 内 opaque 相对对象。
- env clear、offline flags、禁止 URL/SSH/LLM aid。
- OS isolation evidence 绑定 exact worker/model/config hash 与 TTL。
- Windows Job Object kill-on-close。
- managed cache/temp 全部置于 vault worker root。
- 启动残留扫描、取消/超时强杀树和删除验证。

当前机器边界：2026-07-22 的 direct GPU diagnostic 未在完整 App Firewall/Job Object chain 中执行；两次 Firewall 提权均被 UAC 取消。组件签名、install/re-measure 或 direct worker 成功不补足 OS 网络隔离证据。

### 4.3.1 组件供应链与 Windows 路径兼容

攻击：篡改/回滚 catalog 或分片，在 package 中增删文件，利用长路径让原生 Python/MinerU 依赖在安装后不可导入，或把“可安装”误报为“已资格化”。

控制：

- detached Minisign、catalog 高水位、package/manifest/part exact size 与 SHA-256、安装后 exact-tree 复测。
- staging + atomic activation；拒绝额外文件、path traversal、reparse/cloud/hardlink 和未声明 executable。
- final installed path 按普通 Win32 spelling 计算，任何文件超过 259 UTF-16 code units 时在 extraction 前以 `component_runtime_path_too_long` 阻断。
- catalog/组件验证状态与 Firewall、model/runtime trust、production authorization 各自独立，不互相推导。
- 仓库为 private；推荐在 App 外通过 GitHub 认证下载完整 catalog/signature/descriptor/parts 后本地导入。未认证 App 不把 private asset URL 可达性当作安全或可用性事实，也不接收 GitHub token。
- cryptographic signature 不证明第三方内容可再分发；provenance/licensing audit 未完成的 candidate 禁止发布。

验收边界：历史 v3/v5 candidate 的 install/re-measure 与 synthetic diagnostic 仅作为路径兼容和本地运行诊断，两者永久禁止发布。v4 provenance 源码门禁与 25/25 builder tests 已完成，但 clean commit A 后仍须确定性重建、显式审批、签名、短根安装/remeasure、GPU probe 与 App Firewall/Job/canary/restart qualification；当前没有 final v4 artifact/hash。

### 4.4 OCR 不完整导致漏脱敏

攻击：丢页、错序、低覆盖、bbox 越界、视觉区域未识别、原生层与视觉层冲突。

控制：

- 页数、页序、尺寸、rotation、page hash、block order 全量验证。
- 缺 confidence 不得静默视为安全。
- unknown visual、stamp、signature、handwriting、screenshot、complex table 形成 hard gate。
- worker success 不等于 document complete。

### 4.5 脱敏漏检与 alias 漂移

攻击：Unicode/全半角/零宽字符、OCR 混淆、跨页拆分、跨文档简称、破损占位符。

控制：

- 确定性校验规则 + case dictionary + 可选 qualified local NER。
- private cluster ledger 和案件内稳定 replacement。
- detector disagreement 形成 P1/P0。
- 独立 residual scanner 使用与主检测不同的规则集。
- mapping revision 变化使旧批准失效。

### 4.6 readiness 分数绕过 hard gate

攻击：前端篡改 score 或只用平均分掩盖一个 P0。

控制：

- hard gate 只在后端计算。
- score 只解释和排序。
- P0、未解决 P1、低 OCR、视觉风险、qualification mismatch 均直接拒绝 automatic。
- shadow mode 永远发布为 shadow_human。

### 4.7 半发布与 TOCTOU

攻击：正文已发布但 manifest 未发布，或验证后内容被替换。

控制：

- 完整 generation 在 staging 中写完、sync、验签后原子 rename。
- current pointer 最后更新。
- MCP 打开句柄后再次核验 metadata/hash/revocation。
- symlink/reparse/hardlink 和非普通文件拒绝。
- 启动恢复只接受 committed journal + valid pointer。

### 4.8 Receipt replay 与撤销竞态

攻击：跨 workspace/connector/purpose 重放，list 后撤销、read 前继续使用。

控制：

- v2 receipt 绑定 workspace instance、case/material/version、destination、purpose、nonce、revocation epoch。
- durable manifest 与短期 access grant 分离。
- 每次 read 最终检查撤销和 expiry。
- 被拒调用也记录 hash-only audit。

### 4.8.1 Approved MCP sibling 替换

攻击：恶意同名 executable 复制预期版本或 canary 响应，在运行时自我测量后骗过 qualification。

控制：formal 构建先产生 exact MCP sibling，再把其 SHA-256 编译进 App；运行时同时复测 sibling canonical path/file identity/hash/version/behavior，资格与 session 再绑定 App/workspace/server key/transport/revocation epoch。无 compile-time anchor 的 ordinary development build、hash 缺失/格式错误/不匹配和运行前后替换都 fail closed。实际 sibling binary 的 stdio/HTTP 合成 E2E 只证明这条绑定链可运行，不赋予任何静态宿主或真实案件通用授权。

### 4.9 Work-product 注入

攻击：Provider 输出真实身份、路径、密钥、破损占位符，或覆盖 approved/vault。

控制：

- 工具无路径字段。
- 服务端生成 work-product ID/version。
- residual scan、placeholder validator、source references 和 optimistic concurrency。
- immutable version，目标根固定为 work-products。
- 日志只记录 hash、count、reason code。

### 4.10 Skill 绕过

攻击：用户要求读取附件、粘贴原文、调用浏览器/文件/OCR/其他 MCP 或恢复实名。

控制：

- Skill 只信任当前 MCP 直接返回内容。
- 后端 ACL、schema、manifest 和 egress gate 是主防线。
- 宿主在 Skill 加载前可能已读取附件，发现时立即停止并提示删除任务/附件。
- 禁止 memory、子智能体、其他 Skill、邮件、网盘和搜索。

## 5. 日志与错误规则

允许：

- opaque ID、hash、版本、状态、数量、reason code、耗时、匿名错误码。

禁止：

- 原文、OCR 文本、候选值、路径、文件名、mapping、真实主体、work product 全文、key/token。

panic、Python logging、Rust tracing、frontend console、MCP JSON-RPC、HTTP access log、安装器日志和 CI artifact 必须使用同一策略。

## 6. 明确不声称

- 未取得独立服务 SID/DACL 资格时，不声称 WorkBuddy 在 OS 层无法读取 vault。
- 未取得 exact MinerU qualification 时，不声称扫描件 OCR 已生产启用。
- 未完成 calibration 时，不声称 automatic approval 已启用。
- 重建式安全 PDF 不声称保留原始版式、印章、签名或证据外观。
- Skill 不声称能撤回宿主在加载前已经上传的数据。
- v3 六分片签名组件、`1/1` install/re-measure、RTX 5090 direct GPU diagnostic 和 catalog 验签均不声称当前机器 production OCR qualified。
- 历史 v3/v5 candidate 永久禁止发布；v4 在 clean-commit 重建、显式 provenance approval、签名、短根安装/remeasure、GPU probe 与 App qualification 完成前不声称可发布；private catalog URL 不声称对未认证客户端可下载。
- 当前机器仍为 `networkIsolationEnforced=false`、`modelManifestTrustEstablished=false`、`appAutoEnableAuthorized=false`、`productionCaseOcrAuthorized=false`。
- 新增 259 UTF-16 路径门禁后的短根完整 v5 重测与 installed-tree synthetic diagnostic 已 `PASS`，但不得引用它们替代 App Firewall/Job production qualification。

