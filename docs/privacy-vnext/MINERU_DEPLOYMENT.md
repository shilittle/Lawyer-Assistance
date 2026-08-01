# 本地 MinerU Worker v1 部署与运维规范

> `auto_local` / `force_local` 仅在签名资格、精确 worker/config/runtime/model
> inventory、Windows Firewall 复测、固定合成 canary、执行前后 identity 校验和
> 进程树 containment 全部有效时运行。历史候选构件不得用于生产或发布；最终组件必须
> 从固定源码确定性重建、审查、签名、短路径安装、复测并由 App 完成资格化。当前公开
> 发布状态见 [`docs/release-status.md`](../release-status.md)。

## 1. 目标与边界

本规范只允许在用户设备上运行、使用本地模型且经过精确资格校验的 MinerU OCR。生产案件材料不得发送到 SSH 主机、远程 MinerU、云 OCR、Provider 或任何联网回退路径。

v0.3.1 只有 CLI runner 的描述是历史基线。beta.2 已有自包含 worker/component、App/host 协议与生命周期实现；“资产存在、签名有效、安装复测通过、worker 诊断通过、当前机器资格有效”仍是五件不同的事。只有本文件列出的生产 worker、协议、完整性、隔离、生命周期和资格门对 exact 当前环境全部通过后，应用才会把视觉页交给 worker；否则返回匿名阻断码，且不使用 SSH、云 OCR、Provider 或任何远程回退。

## 2. 组件布局

托管组件根目录必须位于应用私有的本地固定磁盘，且不得是云盘、网络盘、重解析点、符号链接或宿主可自由指定的路径：

- `components/mineru/<component-version>/worker/`
- `components/mineru/<component-version>/python/`
- `components/mineru/<component-version>/models/`
- `components/mineru/<component-version>/config/`
- `components/mineru/<component-version>/manifest.json`
- `components/mineru/current.json`
- `worker-jobs/<opaque-job-id>/input/`
- `worker-jobs/<opaque-job-id>/output/`
- `worker-jobs/<opaque-job-id>/temp/`

`current.json` 只保存版本、manifest hash 和状态，不保存原文件名、原路径或材料正文。升级先写入新的完整版本目录，验证通过后原子切换 current；旧版本保留到回滚窗口结束。

## 3. Worker 协议

协议名称固定为 `la-mineru-worker-v1`，采用逐行 JSON 或等价的长度前缀本地 IPC。消息必须有 `protocol_version`、`request_id`、`message_type`，所有对象拒绝未知字段。支持：

- `hello`：报告协议、worker、Python、MinerU、PyTorch、CUDA、GPU 和模型版本。
- `health`：只执行本地自检，不加载案件材料。
- `ocr`：仅接收 job root 内的 opaque 相对输入 ID、参数 hash 和期望输出 ID。
- `progress`：页级进度、阶段、耗时和匿名 reason code，不含正文。
- `cancel`：取消单个 job，并终止完整进程树。
- `shutdown`：受控退出，不接受任意命令或脚本。

禁止字段包括绝对路径、URI、URL、SSH 参数、任意环境变量、任意命令、自由 metadata、Provider key 和网络回退开关。

## 4. 离线安装、升级、回滚与卸载

### 安装

1. 推荐用户先在 App 外从项目公开 GitHub Release 下载完整 catalog、同名 `.minisig`、`.laocrparts` descriptor 与全部 parts，再选择本地离线导入；也可先导入并验证签名的固定项目 catalog，再在界面核对固定 URL、大小和 hash 后显式选择 App 下载。公开可达只说明资产可下载，不证明签名、完整性、来源审批或当前机器资格。应用不接受任意 URL，也不接收 GitHub token 或案件数据。
2. 在 staging 中校验签名或受信发布 key、包 hash、manifest schema、exact file set、每个文件的大小和 SHA-256。
3. 拒绝额外文件、链接、重解析点、稀疏/占位文件、非本地固定磁盘和可执行入口漂移。
4. 安装到新的不可变版本目录，执行无材料 health check。
5. 记录 hash-only 安装审计后，原子切换 current。

### 升级与回滚

升级不原地覆盖。新版本必须单独完成资格校验；旧资格报告不得迁移。回滚只能指向仍完整、仍受信且未撤销的版本，回滚后自动批准保持关闭，直到该 exact tuple 的资格重新有效。

### 卸载

先停止接收任务、取消并终止 worker 进程树、清理 job roots、验证无明文残留，再移除组件版本。若删除验证失败，状态标记为 `quarantined` 并阻断后续 OCR，不把残留路径写入普通日志。

## 5. 运行隔离

最低运行要求：

- `env_clear` 后只注入固定白名单环境变量和离线标志。
- worker 只能访问由 Broker 创建的单个 job root。
- 输入从 vault 解密到受控 job root，使用随机对象名；不得暴露原路径和原文件名。
- 禁止 URL、网络共享、云盘占位文件、SSH、LLM aid 和自动模型下载。
- 使用 Windows Job Object `KILL_ON_JOB_CLOSE` 或等价机制覆盖完整进程树。
- 超时、取消、崩溃和应用退出都必须触发进程树终止与明文残留扫描。
- temp/cache/model 路径必须显式固定；不得落入系统或 Python 默认临时目录。

环境变量形式的离线标志不等于 OS 网络隔离。`networkIsolationEnforced` 只有在防火墙/令牌/沙箱等可验证控制实际生效并产生绑定 exact worker 的证据后才能为 true。

## 6. 输出完整性

worker 返回的成功退出码不等于文档完整。后端必须独立验证：

- 输入未修改 hash、来源 hash、页数和连续页序。
- 每页尺寸、旋转、页面图像 hash、状态和覆盖率。
- block ID 唯一、reading order 连续、bbox/polygon 有限且不越界。
- OCR 与 layout confidence 的存在性和范围；缺失不得默认为安全。
- 空白页有可验证证据；未知视觉块不得静默丢弃。
- 印章、签名、手写、截图、复杂表格和未知视觉区域进入视觉风险 gate。
- 输出 canonical hash 与 provenance 完整。

任何丢页、越界、未知 block、非法置信度、provenance 缺失或输出树逃逸均使任务 `blocked`，并销毁该 job 的可发布产物。

## 7. 资格 tuple

资格报告绑定以下 exact tuple：

- worker version/hash 与协议版本
- Python、MinerU、PyTorch、CUDA runtime、GPU driver/device
- model version 与完整 model manifest hash
- config hash 与处理参数 hash
- isolation evidence ID/hash
- 应用版本、OS build 与资格策略版本

任一成员变化，旧资格立即失效。资格报告具有短 TTL 和撤销状态；应用每次真实 OCR 前后都校验一次，以防运行期间漂移。

## 8. 日志与遥测

允许记录 opaque job/material ID、组件版本/hash、阶段、页数、计数、耗时、GPU 型号、匿名 reason code 和资格状态。禁止记录正文、OCR 文本、原文件名、原路径、bbox 对应文本、候选实体、密钥、token 或完整命令行。默认不发送任何遥测。

## 9. 当前交付状态

- Worker 协议、输出 completeness、页面/顺序/尺寸/bbox/confidence 上限、
  超时/取消与进程树控制已实现，并由合成 fixtures 回归。
- App `auto_local` / `force_local`、签名 qualification 持久化、重启加载、
  撤销/过期/epoch 与环境漂移失效已实现。
- exact worker/config/runtime/model inventory、受信注册、确定性 packager 和
  provenance/licensing 门禁已实现。
- 历史候选组件不满足最终 v4 发布门禁，永久不能改名或重新发布。
- 最终 v4 必须绑定固定依赖闭包、wheel `RECORD`、许可证、模型 revision 和逐文件
  hash，并经过显式审批与全量重测。
- Windows Firewall outbound 规则安装、ActiveStore 验证和 rollback 已实现；只有
  exact 规则对当前 worker 进程树实际生效时 `networkIsolationEnforced=true`。
- 安装器限制 final installed path 不超过 259 UTF-16 code units，超限在解包前返回
  `component_runtime_path_too_long`。
- 真实扫描案件 OCR 只有在 current exact tuple 的 App/Firewall/Job/qualification
  全部有效后才可条件启用。组件安装与 synthetic diagnostics 不替代这些门。
- SSH/远程 MinerU、自动模型下载和联网 OCR 回退在生产路径永久禁止。

### v3 六分片清单

| Part | Bytes | SHA-256 |
|---:|---:|---|
| 1 | 1,992,294,400 | `2a71547e2076d389a42d48f084784edb2adda2f8e970a082e6dd92f69685f00d` |
| 2 | 1,992,294,400 | `f0a7a140c0fbe1b5ced626c856dc694efe69518b678d3268f1c585f0eae29794` |
| 3 | 1,992,294,400 | `f523569409232b3dd2f28ddc936bf6ac75d38bb26df1401236fc7684315ea38b` |
| 4 | 1,992,294,400 | `45310b9d48c2cffb5aca3cfb356bcceb54ce6fc64083e32cd39fc2be4f30c9e5` |
| 5 | 1,992,294,400 | `7120a480caf83bd68fe746c6ce6068e4a923594c4dfeae66e753592c4fecb4b4` |
| 6 | 1,832,146,181 | `ab87625f730eafcdd4a7378284a31198405eded47ef816fbe00b4d2844e1d9f3` |

## 10. 应用托管组件的可信生命周期

应用不执行隐式下载，也不允许用户输入任意下载地址。用户可选择两种显式安装方式：导入本机 `.laocrpkg`，或者先导入受发布密钥签名的组件目录，再在界面完整查看固定 HTTPS 来源、精确字节数、包 SHA-256 与 manifest SHA-256 后点击下载。联网命令的输入只有目录内的 `packageId`；它没有案件 ID、材料路径、正文、附件、OCR 文本、Provider 凭证或删除防火墙规则的字段。

受信目录只接受项目公开 GitHub Release 的固定命名 URL，并限制跳转到 GitHub 发布资产域名。仓库公开并不把 URL 可达性变成完整性或资格证据；catalog 中存在合法固定 URL，也不证明完整签名集已发布、已通过 provenance/licensing 审批或适用于当前机器。推荐使用浏览器或 `gh` 在 App 外下载 catalog、detached signature、descriptor 与全部 parts，再走 App 本地导入。App 自动下载也只能从已经本地导入并验签的固定 catalog 选择 `packageId`；不需要、也不得把 GitHub token 填入 catalog、组件配置、案件 metadata 或普通日志。目录原文与 detached minisign 签名被保存在同一个原子 envelope 中；`issuedAt` 高水位由 DPAPI 保护的本机密钥进行 HMAC 认证，拒绝回滚以及同一 epoch 的不同内容。组件下载采用流式写入，要求响应 `Content-Length`、最终字节数和 SHA-256 全部精确匹配；任何失败都只清理本次随机 `.download-<UUID>` 暂存目录。

`.laocrpkg` 是严格的流式包格式：固定 magic、长度前缀 JSON manifest、按 manifest 顺序拼接的 payload。manifest 拒绝未知字段，绑定 package/component/MinerU/protocol/platform、worker、运行时可执行文件、pipeline/vlm 模型目录以及每个文件的精确大小和 SHA-256。安装拒绝绝对路径、`..`、反斜杠、ADS、Windows 保留名、大小写折叠重复、额外文件、symlink/reparse point、hardlink、cloud recall/offline 占位文件和非固定本机磁盘。worker 与运行时入口必须是 PE/MZ `.exe`。安装前同时检查包上限与可用磁盘空间。

安装与升级先写入私有 `.staging-<UUID>`，逐文件复测和生成只含绝对本机路径的最小 tools JSON，再把完整版本目录原子落位；绝不原地覆盖旧版本。`current.json` 由 DPAPI 保护的本机密钥进行域分离 HMAC 认证，绑定 generation、active/previous version、manifest hash 和 lifecycle state。回滚只允许仍在当前受信目录、未撤销且 exact tree 完整的已安装版本。卸载先停用 active binding，再只删除目标版本的声明树；删除失败会标记 `quarantined` 并阻断 OCR。卸载永远不删除 Windows Firewall 隔离规则。

组件目录导入、安装、升级、回滚和卸载均在任何文件或状态变更前撤销旧 qualification，结束后再次撤销，并通过 owned RAII mutation guard 阻止并行组件变更、资格签发和生产 OCR 配置生成。资格签发在持久化前后检查该 guard；若发生竞态，立即撤销刚写入的资格并返回 `qualification_component_mutation_race`。因此旧版本资格不能迁移到新版本，也不能在失败或取消路径中恢复。

应用内组件面板展示：安装与 active version、MinerU/Python/PyTorch/CUDA runtime/GPU driver、GPU 选择与 `nvidia-smi` 实测显存、worker/protocol identity/health evidence hash、模型 manifest/hash 与双重完整性、OCR mode、qualification 和真实案卷 OCR 显式授权。版本与 GPU 字段只显示真实 worker `hello`/`health`、signed qualification 和本机复测结果；缺失时明确显示“未取得真实证据”并保持 fail closed。显存低于 6144 MiB 或运行时 CUDA OOM 均阻断任务、终止 worker 进程树并清理作业明文，不得切换云 OCR、SSH、HTTP OCR 或其他远程回退。

组件联网和案件处理是两条不可混淆的通道：组件下载状态固定声明 `remoteOcrAllowed=false` 与 `caseMaterialDownloadedOrUploaded=false`。案件 PDF、扫描图片、OCR 中间产物和脱敏前正文只允许进入经当前 exact tuple 资格化的本机 worker job root；组件管理 API 从结构上不能接收它们。

### 运维顺序

1. 先在 App 外从项目公开 GitHub Release 下载完整签名资产集：catalog、同名 `.minisig`、`.laocrparts` descriptor 和全部 parts。缺少任一成员时不得导入或拼接其他来源的同名文件。
2. 在 App 内先导入 catalog 与 signature，再选择本地 descriptor 安装；也可在验签后的 catalog 中核对 URL、大小和两个 SHA-256 后显式使用自动下载。等待 staging、exact-tree 校验和原子激活完成。公开下载成功本身不代表组件受信或已取得 OCR 资格。
3. 在“设置 → 本地处理环境与 OCR 组件”中选择 `auto_local`、`force_local` 和目标 `cuda:<index>`；保存后建立安装信任、安装并复测防火墙规则、运行无案件材料的 canary，再显式授权生产案卷 OCR。
4. 升级或回滚后必须重新执行第 3 步。资格未重新建立前，App 与 approved MCP 都不得处理真实扫描案卷。
5. 卸载前勾选明确确认；卸载完成后保留防火墙规则。若状态为 `drifted`、`quarantined` 或出现签名/HMAC/目录/hash 错误，先保留现场并按 reason code 排查，不得绕过门禁。

### 可复现组件资产生成

`scripts/build_mineru_component_package.py` 只打包预先准备好的本机隔离环境，不下载模型、不接收案件材料、不读取或内置签名私钥。它按大小写折叠后的确定顺序枚举 `worker/`、`python/`、`runtime/`、`models/` 和 `licenses/` allowlist，拒绝路径穿越、重复/保留路径、reparse/cloud/hardlink、未声明可执行文件、非 MZ 入口、缺失模型目录、超限包和 create-new 输出覆盖，并在写入期间再次计算每个 payload hash。包内全量文件 inventory 的 canonical JSON 最多 16 MiB；该上限可容纳当前约四万文件的固定 MinerU/CUDA 组件，同时仍在构建器与 App 两端独立实施硬边界。

发布负责人必须显式给出固定 epoch；下面的占位符必须替换为真实、非案件的组件环境与计划发布版本：

```powershell
python scripts/build_mineru_component_package.py `
  --source C:\absolute\prepared-mineru-runtime `
  --output C:\absolute\release\lawyer-assistance-mineru-<semver>-windows-x86_64.laocrpkg `
  --catalog-output C:\absolute\release\mineru-component-catalog.json `
  --package-id mineru-windows-<release-id> --catalog-id mineru-windows-stable-v1 `
  --component-version <semver> --mineru-version <mineru-version> `
  --worker worker/mineru-worker.exe `
  --pipeline-model-directory models/pipeline --vlm-model-directory models/vlm `
  --issued-at <unix-seconds> --expires-at <unix-seconds>
```

`worker` 始终必需；`--runtime-executable` 仅用于 worker 之外确实会启动的额外 EXE，可重复零到 32 次。组件中每个额外 EXE 都必须声明，且 App 会把 worker 与全部已声明额外 EXE 一并纳入防火墙和资格 inventory。成功输出同时给出包 SHA-256、manifest SHA-256、精确字节数、catalog SHA-256 和绑定 exact catalog 文件名/epoch 的 PowerShell minisign 命令。catalog 此时明确是 **unsigned**。候选资产必须同时满足：外部保管的对应私钥完成离线签名、App 内置公钥验证通过、provenance/third-party licensing audit 完成、路径/安装/资格 release gates 通过，之后才可上传固定公开 `mineru-components-v<semver>` Release。没有私钥时不得生成占位签名；没有 provenance/licensing approval 时即使签名有效也不得发布；不得把合成测试包或空模型冒充发布资产。发布新 epoch 时应传 `--previous-catalog` 做本地 rollback/equivocation 预检。
