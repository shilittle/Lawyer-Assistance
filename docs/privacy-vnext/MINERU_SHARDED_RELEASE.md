# MinerU 分片发布

大型本地 MinerU 组件不得以单个超过 GitHub Release 资产上限的文件发布。构建器可以直接流式生成分片，不会先在磁盘落一个同等大小的临时整包。

## 供应链与再分发门禁

生产 stage 不能从“环境里碰巧存在的全部包”复制运行时。`scripts/build_production_mineru_worker.py provenance-draft` 从 `mineru==3.4.3` 的 `pipeline`、`vlm` extras 出发解析 Windows / CPython 3.12 marker，计算传递闭包；当前固定环境得到 86 个 distribution，另有 62 个 Gradio、LMDeploy、Ray、S3 等闭包外 distribution 被明确排除。对最终会打包的每个 `RECORD` 声明文件，构建器复算 SHA-256 与大小；每个 distribution 的原始内容 inventory、安装 `RECORD`、复制后内容 inventory、许可证声明与许可证文件都写入 canonical provenance。缺少 `RECORD`、哈希漂移、未知许可证或 `NOASSERTION` 均 fail closed。

关键上游固定值为：

- `torch==2.8.0+cu128`：`torch-2.8.0+cu128-cp312-cp312-win_amd64.whl`，SHA-256 `0ad925202387f4e7314302a1b4f8860fa824357f9b1466d7992bf276370ebcff`；
- `torchvision==0.23.0+cu128`：`torchvision-0.23.0+cu128-cp312-cp312-win_amd64.whl`，SHA-256 `20fa9c7362a006776630b00b8a01919fedcf504a202b81358d32c5aef39956fe`；
- `mineru==3.4.3`：保留上游原始 `LicenseRef-MinerU-Open-Source-License`，`LICENSE.md` SHA-256 `2d9aeb5d15159329a20dd804f251c64860ba954fbd26ec02f802220e6d71cf5c`，不得错误改写为 Apache-2.0；
- pipeline 模型 `opendatalab/PDF-Extract-Kit-1.0@ed6b654c018d742e65a17671e379c5e6ecc87ec9`：只复制逐文件核验的 15 个文件，许可证证据 README SHA-256 `96da5ddde73c3f578b9eab235ac59cbb5f512755090779a14461863767b70f34`；
- VLM 模型 `opendatalab/MinerU2.5-Pro-2605-1.2B@bff20d4ae2bf202df9f45284b4d43681555a97ed`：只复制逐文件核验的 11 个文件，许可证证据 README SHA-256 `8f829b69be518375b02023f795b3898adec98f5ac37208239884ad88e9a21cb7`。本地不匹配的 `.gitattributes`、`README.md` 和无上游对应的 `configuration.json` 不进入组件。

`provenance-draft` 始终输出 `approvedForRedistribution=false`。完成法律/许可证审查后，发布负责人必须单独执行 `provenance-approve`，提供非空 reviewer 与固定 UTC Unix 时间；该命令只接受未批准的 canonical draft、拒绝未知字段和覆盖已有输出。随后 `stage` 会在 clean Git commit 上重新测量全部运行时、模型、构建脚本与 worker source；任何差异都会使批准输入失效。不能用 dirty worktree、旧 draft 或旧 v3 组件绕过此门。

```powershell
python scripts/build_production_mineru_worker.py provenance-approve `
  --draft C:\absolute\mineru-provenance-draft.json `
  --reviewer "<release-owner>" --reviewed-at <unix-seconds> `
  --output C:\absolute\mineru-provenance-approved.json

python scripts/build_production_mineru_worker.py stage `
  --python-home C:\absolute\cpython-3.12.13 `
  --site-packages C:\absolute\mineru\Lib\site-packages `
  --pipeline-model C:\absolute\models\pipeline `
  --vlm-model C:\absolute\models\vlm `
  --worker-source workers\mineru --repository-root . --repository-license LICENSE `
  --provenance-input C:\absolute\mineru-provenance-approved.json `
  --output C:\absolute\prepared-mineru-runtime
```

组件包 manifest 绑定 `licenses/mineru-component-provenance.json` 的路径、大小和 SHA-256；同一值再进入签名 catalog 与独立 provenance Release asset。App 使用 `deny_unknown_fields` 解析 manifest、catalog 和 provenance，并在安装前、落盘后与每次重启 re-measure 时复核 provenance、distribution `RECORD`/license、模型 exact file set 与 package manifest。Minisign 只证明 catalog 的来源和完整性，不替代再分发审批。

```powershell
python scripts/build_mineru_component_package.py `
  --source C:\absolute\prepared-mineru-runtime `
  --output C:\absolute\offline-set\lawyer-assistance-mineru-<semver>-windows-x86_64.laocrpkg `
  --catalog-output C:\absolute\release\mineru-component-catalog.json `
  --package-id mineru-windows-<release-id> --catalog-id mineru-windows-stable-v1 `
  --component-version <semver> --mineru-version 3.4.3 `
  --worker worker/mineru-worker.exe `
  --pipeline-model-directory models/pipeline --vlm-model-directory models/vlm `
  --issued-at <unix-seconds> --expires-at <unix-seconds> `
  --part-size-bytes 1992294400
```

省略 `--part-size-bytes` 时仍生成兼容 schema v1 的单文件 `.laocrpkg`。启用分片时生成 canonical `.laocrparts` 描述文件和有序 part 文件；每个 part 必须非空且严格小于 2 GiB，最多 128 片。签名后的 schema v2 catalog 同时绑定整包大小与 SHA-256、内层 package manifest SHA-256、part-set 描述文件大小与 SHA-256，以及每个 part 的序号、文件名、大小、SHA-256 和 Release URL。

桌面 App 只接受通过内置生产 Minisign 公钥验证的 catalog。离线导入会严格拒绝额外文件、缺片、乱序、链接和任何哈希漂移；下载会复用已经完整验证的分片。所有分片验证完成后，App 在固定私有目录以 create-new 方式组装，通过整包与内层 manifest 的再次校验后才原子安装。catalog 或 descriptor 在下载期间发生变化会 fail closed。

`shilittle/Lawyer-Assistance` 实际为 private repository。catalog 中的固定 GitHub asset URL 对未认证客户端不可用，也不证明对应 Release 已发布。推荐先使用已认证的 GitHub browser/CLI 在 App 外下载 catalog、同名 `.minisig`、`.laocrparts` 与全部 part，再走 App 本地导入；App 自动下载只适用于运行环境已经能访问该 private Release 的情况。不得把 GitHub token 写进 catalog、组件配置、案件 metadata 或日志。

断点续传的粒度是“完整分片”，不是单片内部 HTTP Range。网络中断时保留已验证分片供下次复用；成功安装或确定性的完整性失败会精确清理本次 incoming/assembly 状态。

构建器只产生待签名 candidate，不读取案件材料、不联网，也不包含生产私钥。catalog 必须在隔离的发布环境使用 Minisign 私钥离线签名；密钥只通过发布流程的 `LAWYER_ASSISTANCE_MINISIGN_SECRET_KEY` 环境引用提供，禁止写入仓库、命令输出或构建日志。签名只证明来源/完整性，不证明第三方内容可再分发；provenance 与 third-party licensing audit 完成前，即使签名验证通过也不得上传 Release。
