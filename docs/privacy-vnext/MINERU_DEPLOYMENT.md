# 本地 MinerU Worker v1 部署与运维规范

## 1. 目标与边界

本规范只允许在用户设备上运行、使用本地模型且经过精确资格校验的 MinerU OCR。生产案件材料不得发送到 SSH 主机、远程 MinerU、云 OCR、Provider 或任何联网回退路径。

当前 v0.3.1 的 CLI runner 是可复用的安全基础，但尚不具备生产扫描件 OCR 资格。只有本文件列出的协议、完整性、隔离、生命周期和资格门全部通过后，应用才可把真实材料交给 worker；否则必须返回匿名阻断码并允许用户改用原生文本层或人工离线流程。

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

1. 用户选择离线组件包；应用不提供隐式下载。
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

- CLI runner 基础完整性控制：`implemented`，但协议和输出 completeness 尚需升级。
- 托管安装/升级/回滚/卸载：`planned`，完成测试前不可标记 enabled。
- OS 网络隔离：`not qualified`。
- exact model manifest trust：`not qualified`。
- 真实扫描案件 OCR：`blocked`。
- SSH/远程 MinerU：只可用于非案件研发参考，本产品生产路径永久禁止。

