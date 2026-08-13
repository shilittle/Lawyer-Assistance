# ADR-0002：v0.3.1 升级原态回滚、收据与谱系协议

- 状态：Accepted / Frozen
- 决策日期：2026-08-01
- 适用迁移：`v0.3.1 → v0.4.0`
- 固定迁移 ID：`v0.3.1-to-v0.4.0-user-schema-v1`
- 关联计划：
  - `docs/plans/2026-08-01-v0.4.0-upgrade-release-and-publication.md`

## 背景与边界

冻结计划已经确定原态五槽回滚点、十阶段升级状态机、recovery-only
`apply-and-exit` 和 R2/R3/R7 提交边界，但没有把部分 wire encoding、路径闭包和
自引用规避规则展开到可互操作实现所需的精度。本 ADR 只冻结这些实现级细节。

本澄清来自上位计划规定的数据安全、既有用户数据兼容和最小影响面优先级。它不改变
冻结计划的阶段、先后顺序、提交分层、schema 版本或完成判定；如本 ADR 与计划正文的
执行顺序发生冲突，以计划正文的顺序为准并 fail closed。

普通 V3 application backup/restore 的 wire contract 不变。下文 V2 专指
`v0.3.1` 原态 migration-only envelope；它不成为普通 restore 的兼容入口。

## 规范编码基础

除非某节另有规定，协议中的 hash 均为 SHA-256，序列化为恰好 64 个小写十六进制
ASCII 字符。`\0` 表示一个 `0x00` 字节，不是反斜杠和字符 `0`。`u64be(n)` 是
无符号 64 位大端整数；`i64be(n)` 是有符号 64 位二进制补码的大端表示。

本 ADR 使用以下唯一字段框架：

```text
field(tag, value) = one-byte tag || u64be(byte_length(value)) || value
```

tag 不得复用，字符串按本节指定的 ASCII 或 UTF-8 原始字节编码，不做 Unicode、换行、
SQL 或路径归一化。要求为 hash 的输入必须先验证为规范 64 位小写十六进制，再解码成
32 个原始字节。

## 原态五槽 V2

五个槽位及顺序固定为：

1. `user_database`：present，自包含 raw SQLite，source schema 10；
2. `privacy_store`：present，自包含 raw SQLite，source schema 1；
3. `vault_store`：authenticated absent；
4. `approved_workspace`：authenticated absent；
5. `work_products`：authenticated absent。

present 槽的 plaintext 是 SQLite Backup API 生成的数据库文件原始字节。absent 槽的
plaintext 必须分别是以下 exact ASCII bytes，并包含末尾 NUL：

```text
lawyer-assistance\0v031-original-rollback\0authenticated-absent-v1\0vault_store\0
lawyer-assistance\0v031-original-rollback\0authenticated-absent-v1\0approved_workspace\0
lawyer-assistance\0v031-original-rollback\0authenticated-absent-v1\0work_products\0
```

通式是
`lawyer-assistance\0v031-original-rollback\0authenticated-absent-v1\0<slot>\0`，
其中 `<slot>` 只能替换为上述三个 ASCII 槽名。sentinel 的长度和 hash 都进入已认证
identity；sentinel 不得写成空文件、空目录、JSON `null` 或同一通用常量。

每个 lineage 目录中的 V2 文件名固定为：

```text
v031-original-rollback-v2.identity.dpapi
v031-original-rollback-v2.identity.dpapi.incoming
v031-original-rollback-v2.bundle
v031-original-rollback-v2.bundle.incoming
user_database.snapshot.sqlite.incoming
privacy_store.snapshot.sqlite.incoming
```

最后两个 SQLite image 只允许存在于两个源 read transaction 同时存活的构建窗口；必须由
SQLite Backup API 生成并回读验证。identity 和 bundle 完成安装、回读和槽位验证后才可清理；
崩溃恢复只能认证并续作唯一匹配的 image，不能猜测删除或用 UUID 临时文件替代。

identity plaintext 是拒绝 unknown field 的 canonical UTF-8 JSON，schema 固定为
`lawyer-assistance-v031-original-rollback-identity-v2`，并至少精确包含：
`schemaVersion`、`formatVersion=2`、`migrationId`、`creatorAppVersion=0.4.0`、
`sourceProfile=v0.3.1-exact`、source profile/user/Privacy logical 与 business proof hash、
`sourceUserPhysicalFileSetSha256`、`sourcePrivacyPhysicalFileSetSha256`、
`envelopeBindingId`、`lineageId`、创建时间、固定过期时间、固定 bundle basename/size/hash、
wrapped key hash 和恰好五项有序 slot identity。每项 slot identity 固定包含 ordinal、名称、
`present|authenticated_absent`、`raw_sqlite|authenticated_absent_sentinel_v1`、source schema
version（absent 时为 JSON `null`）、plaintext size/hash、logical/business hash（absent 时为
JSON `null`）和 chunk count。identity plaintext 使用 DPAPI CurrentUser 独立保护。

两个 physical file-set hash 都是无路径的 canonical JSON 证据，schema 固定为
`lawyer-assistance-v031-source-physical-file-set-v1`。对象固定包含 `sourceKind`
（分别为 `user-v10`/`privacy-v1`）以及 `database`、`wal`、`shm`、`journal` 四个固定槽；
不存在的 sidecar 编码为 JSON `null`，存在的普通单链接文件精确绑定
`identitySha256`、`length`、`modifiedUnixNanos` 和 `sha256`。绝对路径、文件名和用户信息均
不得进入 wire。相同的两个 hash 必须同时出现在 identity、metadata、envelope 和 base AAD，
任何一侧缺失、错配，或只重绑 outer bundle hash 而没有原 AEAD tag，均 fail closed。

bundle envelope schema 固定为 `lawyer-assistance-v031-original-rollback-envelope-v2`，crypto
suite 固定为 `aes-256-gcm-five-slot-chunked-dpapi-current-user-v2`，AAD schema 固定为
`lawyer-assistance-v031-original-rollback-aad-v2`，chunk size 固定为 8 MiB。它使用同一份有序
slot identity、source proof、binding、lineage、时间和 fixed expiry，并包含 DPAPI-wrapped 的
每包新 AES-256-GCM key、wrapped key hash 以及每槽的有序 encrypted chunks。每个 chunk 固定
保存 slot ordinal、index、plaintext size/hash、nonce、ciphertext、ciphertext hash 和 tag；
base AAD 是除 wrapped-key bytes 与 chunk ciphertext 集合之外的完整 canonical envelope header，
chunk AAD 再域分离绑定 slot ordinal/name/index/count。bundle 不保存 identity hash；DPAPI
identity 单向绑定 exact final bundle hash，避免 identity/bundle 自引用。

V2 identity/envelope 的过期时间固定为 Unix `253402300799`，并与 format version、
migration ID、五槽顺序、每槽 presence/encoding/长度/hash、source proof、logical
manifest、bundle hash、`envelopeBindingId` 和 lineage 一起被 AEAD/DPAPI 认证。只有已经
通过 V2 identity、bundle、槽位和 receipt-chain 全部认证的 migration recovery 可以忽略
当前 wall clock；它仍必须要求该固定 expiry 精确匹配。ordinal 1 的 canonical live evidence
还必须以独立顶层字段 `sourceUserPhysicalFileSetSha256` 和
`sourcePrivacyPhysicalFileSetSha256` 显式绑定这两个已经由 V2 认证的锚点；不得只通过
`protectedIdentitySha256` 间接引用。普通 restore 必须在任何暂存或
组件写入前拒绝所有 V2 包，不得依据未过期时间放行。V3 的时间语义不变。

## 独立 envelope binding

在 source proof 完成后，从操作系统 CSPRNG 读取独立的 32 个字节 `bindingRandom`，计算：

```text
bindingDigest = SHA-256(
  ASCII("lawyer-assistance\0v031-original-rollback\0envelope-binding-v1\0")
  || bindingRandom
)
envelopeBindingId = ASCII("ws_") || first_32_chars(lowercase_hex(bindingDigest))
```

`envelopeBindingId` 因而恰好满足 `ws_` 加 32 位小写十六进制的 V3 语法，只为复用已经
审计的 AEAD/AAD 组件边界。V2 字段名固定为 `envelopeBindingId`，不得称为或序列化为
`workspaceInstanceId`/`workspaceId`。它不表示 target workspace identity，不得从
ProjectId、PrivacyCaseId、source hash 或机器属性推导，也不得创建、加载为 V2 密钥或覆盖
任何 Credential Manager 项。source preflight 只能用非写入查询证明下文固定 target 不存在；
该查询不得创建 credential。`bindingRandom` 在 ID 形成后清零且不持久化。

## 升级 lineage

source proof 完成后另取独立的 32 CSPRNG 字节 `lineageRandom`。lineage preimage 固定为：

```text
ASCII("lawyer-assistance\0v031-to-v040-upgrade\0lineage-v1\0")
|| field(0x01, lineageRandom)
|| field(0x02, ASCII("v0.3.1-to-v0.4.0-user-schema-v1"))
|| field(0x03, hex_decode(sourceProfileProofSha256))
|| field(0x04, hex_decode(sourceUserLogicalManifestSha256))
|| field(0x05, hex_decode(sourcePrivacyLogicalManifestSha256))
|| field(0x06, ASCII(envelopeBindingId))
```

`lineageId = lowercase_hex(SHA-256(preimage))`，所以它恰好是 64 个小写十六进制字符。
`lineageRandom` 和完整 preimage 必须在计算后清零且永不持久化；只有最终 `lineageId`
作为共同关联值写入 identity、所有十个 receipt、Privacy lineage ledger 和 user
operation audit。source/target/identity/component hash 仍按计划作为独立审计证据保存，
但不得另存一份可重放的 lineage seed 或 preimage。

`sourceProfileProofSha256` 必须覆盖 peeled tag/commit provenance、两个 exact schema 与
marker 证明、主文件及已有 WAL/SHM/journal 的文件身份/长度/hash、下节 logical/business
manifest、protected payload manifest、三个 authenticated-absent 证明、完整 target-absence
闭包和验证器版本。
证明对象只含固定标识、hash、计数和匿名错误码，不含路径、案件内容或 secret。

## SQLite 快照和 canonical logical manifest

### 同一只读源快照

源 `user.sqlite` 的 WAL、SHM 或 journal，以及源 Privacy 数据库的同类 sidecar，可以存在；
存在性、文件对象身份、长度、mtime 和逐字节 hash 必须在前后证明中保持不变。验证器不得
以 sidecar 存在为失败理由，也不得删除、truncate、checkpoint、recover 或写入它们。

在单实例 migration gate 内，以 read-only/no-create 和 `query_only=ON` 同时打开 user 与
Privacy 连接；两个连接都执行 `BEGIN DEFERRED` 并通过第一次 schema/data 读取固定 read
snapshot 后，才运行 exact validator 和 manifest。两个事务必须同时保持到两个 present 槽
都构建、回读并验证完成。每个 present 槽都从对应仍存活的源事务通过 SQLite Backup API
写入新建的固定本地、普通、单链接临时数据库，再把临时数据库作为自包含 SQLite image
回读验证。禁止复制 source main file，禁止用 `VACUUM INTO`，禁止在源连接执行 WAL
checkpoint 或任何写 SQL。

离开两个 read transaction 后，必须重新证明 source main/sidecar 的路径绑定、文件身份、
长度、mtime、字节 hash、schema 和业务 manifest 均未变。任一变化都使本次 proof、临时
image、lineage 和尚未安装的 receipt 失效；不得继续安装或自动重试覆盖已有证据。

### Logical/business manifest wire encoding

canonical logical manifest 的流以以下 exact domain 开始：

```text
lawyer-assistance\0sqlite-canonical-logical-manifest-v1\0
```

business manifest 使用相同编码，但 domain 精确替换为：

```text
lawyer-assistance\0sqlite-canonical-business-manifest-v1\0
```

每种数据库/schema 的 logical table allowlist 是其 exact canonical schema 中的全部应用表。
business allowlist 只能从 logical allowlist 作以下固定排除：user 排除
`user_database_metadata`；Privacy 排除 `privacy_schema_metadata`，并在存在时排除
`application_upgrade_lineage`。除此以外的全部应用表都必须保留，包括既有 operation audit、
material migration ledger 和其他审计 ledger。allowlist 按表名 UTF-8 原始字节升序排列；
出现未列入 exact schema 的应用表必须 fail closed，不得通过忽略它来得到相同 hash。
`sqlite_%` 内部实现表不属于应用表；schema version、marker 和 canonical schema object
manifest 由 source proof 单独绑定。

domain 后的 transient byte stream 固定为：

```text
u64be(table_count)
for each table:
  0x10
  field(0x11, UTF8(table_name))
  field(0x12, UTF8(manifest-normalized sqlite_schema CREATE TABLE sql))
  u64be(column_count)
  for each column by ascending cid:
    0x13
    u64be(cid)
    field(0x14, UTF8(column_name))
    field(0x15, UTF8(exact declared_type))
    one byte not_null (0x00 or 0x01)
    one byte default_present (0x00 or 0x01)
    if present: field(0x16, UTF8(exact dflt_value SQL text))
    u64be(primary_key_ordinal)
    u64be(hidden_flag)
  u64be(row_count)
  for each sorted row:
    0x20
    u64be(column_count)
    encoded value for every column by ascending cid
```

表 metadata 必须与 `PRAGMA table_xinfo` 和 exact `sqlite_schema` 一致。上面的
manifest-normalized CREATE TABLE SQL 使用冻结 schema manifest 的同一 normalizer：把每个
maximal SQL whitespace 序列替换为一个 ASCII space `0x20`，再移除首尾 whitespace；不得把
`sqlite_schema.sql` 的原始排版 bytes 直接写入 logical stream。空 declared type 编码为空
字节串，SQL `NULL` default 与没有 default 必须通过 `default_present` 区分。
generated/hidden column 的 `hidden_flag` 按 SQLite 返回的无符号整数编码。

每个 SQLite value 只能使用以下 type tag 与编码：

```text
0x00                                  SQL NULL
0x01 || i64be(value)                  INTEGER
0x02 || u64be(IEEE-754 f64 bits)      REAL
0x03 || u64be(length) || raw bytes    TEXT
0x04 || u64be(length) || raw bytes    BLOB
```

TEXT 是 SQLite 值返回的原始 UTF-8 bytes，不做 Unicode normalization；BLOB 完全按原字节。
REAL 保留 IEEE-754 bit pattern，包括 `-0.0`，不得转十进制文本。数字、长度、cid、PK ordinal、
hidden flag 和计数一律 big-endian。

有声明 PRIMARY KEY 的表按 PK ordinal 依次连接各 PK value 的上述完整编码得到 sort key，按
无符号字节字典序排列；只有没有任何声明 PK 的表才允许用整行所有列的完整编码作为 fallback
sort key。sort key 相同的行再按整行编码排序；完全相同的重复行可交换而不改变流。不得用
`rowid`、查询返回顺序、locale collation 或文件页顺序排序。

实现可以流式或外部排序，但 canonical bytes 只能短暂存在于受控内存/临时空间。持久化的
manifest 输出只允许 overall SHA-256、每表 SHA-256、每表 row count 和 total row count；
不得输出 schema SQL、表/列值、PK、原始文本或 BLOB。

## Exact target-absence 闭包

首次 source preflight 中必须证明以下 target-only 状态全部不存在：

- 以下四个 Credential Manager target（account 均固定为 `user-boundary-v1`）：
  - `LawyerAssistanceApprovedMcp/provider/approved-manifest/account/user-boundary-v1`；
  - `LawyerAssistanceApprovedMcp/provider/work-product-manifest/account/user-boundary-v1`；
  - `LawyerAssistanceApprovedMcp/provider/mcp-access-ticket/account/user-boundary-v1`；
  - `LawyerAssistanceApprovedMcp/provider/mcp-qualification-revocation-epoch/account/user-boundary-v1`；
- `<app_local_data_dir>/case-vault-v2`；
- `<app_local_data_dir>/privacy/approved-mcp` 整个父目录，因此也包括
  `approved-generations`、`work-products`、`ticket-sessions` 和 `qualification`；
- app-root `application-restore-pending.dpapi`；
- app-root `v031-migration-recovery-pending.dpapi`。该名称专属于显式 migration
  recovery，不能与普通应用恢复 marker 互换；
- `user.sqlite.application-restore-incoming`、`user.sqlite.application-restore-rollback`、
  `user.sqlite.restore-incoming`、`user.sqlite.restore-pending.json` 和
  `user.sqlite.restore-rollback`；
- `privacy/privacy-workflow.sqlite.application-restore-incoming`、
  `privacy/privacy-workflow.sqlite.application-restore-rollback`、
  `privacy/privacy-workflow.sqlite.restore-incoming`、
  `privacy/privacy-workflow.sqlite.restore-pending.dpapi` 和
  `privacy/privacy-workflow.sqlite.restore-rollback`；
- `case-vault-v2.application-restore-incoming` 和
  `case-vault-v2.application-restore-rollback`；
- `privacy/approved-mcp/approved-generations.application-restore-incoming`、
  `privacy/approved-mcp/approved-generations.application-restore-rollback`、
  `privacy/approved-mcp/work-products.application-restore-incoming` 和
  `privacy/approved-mcp/work-products.application-restore-rollback`；
- 上述 target 组件的任何 `.incoming`、`.rollback`、`.staging`、`.restore-*` 或 pending
  同级 marker。已知名称必须 absent；发现不在上述 allowlist 的近似或未知 sibling marker
不能忽略、删除或猜测归属，必须 fail closed。

R2 只冻结并枚举 `v031-migration-recovery-pending.dpapi` 这个 basename。由于 R3 才交付其
规范 DPAPI codec、认证 gate 和五槽 `apply-and-exit`，R2 启动观察只能把 absent 判为
`Absent`；该路径任意形式 present 均判为 `UnknownOrInvalid` 并停止启动，不得按路径存在将其
冒充为已认证 recovery，也不得创建、解析、删除或应用它。R3 必须在保持同一 basename 与
启动优先级的前提下，以认证 observer/gate 替换该 fail-closed 分支。

`<app_local_data_dir>` 本身、`privacy` 父目录、两个 source database 及其既有 sidecar、
以及已经认证的 `migration-backups` 回滚证据不属于 target-only absence。不得为了证明 target
absence 删除它们。初次没有回滚证据时，只有完整 source proof 已在两个 read transaction
内成立后，才允许创建 `migration-backups` 审计/回滚目录；该创建是 Step 1 receipt 持久化，
不是 target component 初始化。

## 十文件 append-only receipt chain

每次升级尝试使用 `<app_local_data_dir>/migration-backups/<lineageId>/`；动态目录名必须是本
ADR 定义的 64 位 lowercase-hex lineage。这样 downgrade 后的显式 re-upgrade 可以使用新
lineage，而不覆盖第一次升级的审计证据。该目录内十个 final receipt 的 basename 和 ordinal
固定为：

```text
00-source_preflight_verified.receipt.dpapi
01-original_rollback_verified.receipt.dpapi
02-target_components_prepared.receipt.dpapi
03-case_migration_backups_verified.receipt.dpapi
04-privacy_v5_verified.receipt.dpapi
05-binding_materials_verified.receipt.dpapi
06-projection_backup_verified.receipt.dpapi
07-privacy_v6_verified.receipt.dpapi
08-user_v11_verified.receipt.dpapi
09-upgrade_complete.receipt.dpapi
```

ordinal 是十进制 `0..9`，stage 字符串是去掉两位 ordinal、连字符和
`.receipt.dpapi` 后的 exact literal。每个 staging sibling 的 exact 名称是在 final basename
后追加 `.incoming`，例如
`00-source_preflight_verified.receipt.dpapi.incoming`。不得使用临时 UUID 名、替代扩展名或
共享 pending 文件。

receipt plaintext 是拒绝 unknown field 的 canonical UTF-8 JSON，至少固定保存
`schemaVersion`、`migrationId`、`lineageId`、`ordinal`、`stage`、
`previousReceiptSha256`、本阶段 evidence hash/计数、`createdAtUnix` 和匿名结果码；不得保存
案件内容、路径、文件名、credential、token、ticket、PrivacyCaseId 或 secret。ordinal 0 的
`previousReceiptSha256` 为 JSON `null`；其余 ordinal 必须等于前一 final receipt 的 exact
DPAPI-protected file bytes 的 SHA-256。每个 receipt 使用 Windows DPAPI CurrentUser 单独保护，
并在 plaintext 内绑定 exact lineage、ordinal 和 stage。

本迁移的 receipt schema 固定为 `lawyer-assistance-v031-upgrade-receipt-v1`。十个 receipt
统一使用以下 exact 字段集合，不得增删：`schemaVersion`、`migrationId`、`lineageId`、
`envelopeBindingId`、`ordinal`、`stage`、`previousReceiptSha256`、
`sourceProfileProofSha256`、`evidenceSchemaVersion`、`evidenceSha256`、`counts`、
`createdAtUnix`、`resultCode`。`counts` 是按 key 字典序编码的非负整数 map；每个 stage 的 key
allowlist 与 evidence schema 一一对应，未知 key fail closed。`resultCode` 只允许 exact `ok`。
`envelopeBindingId` 从 ordinal 0 开始沿整条链重复认证，但始终不表示 target workspace。

安装必须以 create-new/no-replacement 打开 `.incoming`，写入、flush、sync、关闭、回读、
DPAPI 解封和完整链验证后，再以不替换既有目标的原子安装形成 final 文件，并 sync 父目录。
final receipt 永不修改、替换、删除或重编号。final 已存在时只能认证并证明它与磁盘组件状态
一致后作为幂等 no-op；不一致即 fail closed。已认证且精确属于下一 stage 的 `.incoming`
可以续作安装；任何其他 incoming、重复 final、断链、跳号、未知文件或未知 sibling marker
都必须在目标写入前 fail closed。

Windows 的父目录 durability adapter 必须以
`FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` 打开并 pin exact parent，使用 handle
identity 复核它仍是同一 plain、非 reparse directory。Win32 不为 directory handle 提供
`FlushFileBuffers` 语义，因此 Windows 上的 durable install 由已 flush/sync 的 create-new file 与
不带 replacement 的 `MoveFileExW(..., MOVEFILE_WRITE_THROUGH)` 共同完成；后者返回前完成磁盘
移动。不得把 Rust `File::sync_all` 对 directory 的恒定 `AccessDenied` 当作协议失败，也不得吞掉
open、handle identity、plain-directory validation 或 write-through rename 的任何错误。非 Windows
平台仍必须执行真实 parent-directory fsync。

## Identity、bundle 和启动顺序

V2 identity 和其精确 bundle 都使用 no-replacement 安装。identity 必须先安装；随后只能从
已认证 identity 中读取 bundle filename/hash，恢复一个精确匹配的已 staged bundle，再安装
bundle。bundle 先于 identity、一个 identity 不是恰好对应一个匹配 bundle、同名不同 bytes、
hardlink/reparse 或任何替换请求均 fail closed。崩溃恢复不得清理唯一有效 identity/bundle。

启动顺序固定为：

1. 获取单实例锁和 migration operation gate；
2. 在 current manager、current schema validator、Credential 创建、maintenance、UI 或后台
   writer 前，只读枚举并认证 pending full restore、migration rollback、V2 identity/bundle、
   receipt chain 和所有已知 marker；
3. 先仲裁显式 recovery，再按 receipt 与五槽实态的唯一匹配恢复中断升级；未知或不一致状态
   fail closed；
4. 没有可恢复状态时，在两个 simultaneous deferred/query-only transaction 中完成 exact
   source proof；
5. 生成 envelope binding/lineage，持久化 ordinal 0；构建、安装并回读 V2，重新证明 source
   未变后才持久化 ordinal 1；
6. 只有 ordinal 1 final receipt 已认证且与磁盘一致，才允许创建 target Credential、Vault、
   approved workspace、work-products 或打开会迁移 current schema 的 manager；
7. 此后严格按 ordinal 2..9 和冻结计划 Step 3..8 前进。每阶段重跑只能 no-op 或完成该阶段
   已认证的唯一续作，禁止改 marker、删 receipt 或跳阶段。

进程重启后重建 ordinal-1 capability 时，必须先从 DPAPI/AEAD 认证的 V2 identity 恢复上述
两个 physical 锚点。active user 仍为 schema 10 时，无论 Privacy 已推进到哪个后续阶段，均
重新计算并精确匹配 user physical file-set；active Privacy 仍为 schema 1 时同样重新计算并匹配
Privacy 锚点。Privacy schema 5/6 只能在相应连续 receipt 前缀和 exact-final checkpoint inventory
均已认证后改用 strict current manifest；user schema 11 只能在 ordinal 7 已认证、三个 checkpoint
均 exact-final 且 Privacy 已为 strict schema 6 时改用 current-schema/原 V2 semantic proof。
任何阶段都不得因为另一数据库已经迁移而跳过仍处原 schema 的 physical 锚点验证。

源 proof 和 ordinal 0 之间创建 `migration-backups` 是唯一的目录写例外；两个 active source
database、其 sidecar 和三个 absent 槽在 ordinal 1 提交前必须始终保持原态。

## Schema 6/11 的 lineage 记录

Privacy canonical schema 6 必须包含专用 append-only 表
`application_upgrade_lineage` 及其 exact index/trigger 契约。不得把 application upgrade
lineage 写入或伪装成 material migration ledger。该表至少规范保存 final `lineage_id`、固定
migration ID、source profile proof hash、source user/Privacy logical hash、原态 V2 identity
hash、target user/Privacy pre-audit logical/business hash、前序 receipt hash、匿名结果和时间；
`lineage_id` 唯一，普通 `UPDATE`、`DELETE`、`INSERT OR REPLACE` 和可改写的 upsert 均由
schema 与应用层同时拒绝。该表是 Privacy schema 6 的组成部分，不把 schema 升为 7。

user v10→v11 的同一 immediate transaction 必须在 exact v11 validation 成立后插入一条
`operation_audit` 成功记录：

- `origin = 'desktop'`；
- `operation = 'v031_to_v040_upgrade'`；
- `project_id IS NULL`；
- `idempotency_key_hash = lineageId`；
- `request_hash = sourceProfileProofSha256`；
- `status = 'succeeded'`；
- `details_json` 只含 migration ID、lineage 和上述证据 hash/计数，不含业务正文或路径。

这使用既有 canonical user schema 11，不把 schema 升为 12。重跑按
`(origin, operation, idempotency_key_hash)` 读取同一行；字段不一致必须 fail closed，不得产生
第二行或覆盖第一行。

为避免 hash 自引用，`targetUserLogicalSha256`、`targetPrivacyLogicalSha256` 及对应 business
hash 必须在目标 schema/业务迁移全部完成、但在插入本次 user operation audit 与 Privacy
`application_upgrade_lineage` 行之前，从固定只读 snapshot 计算。除 business allowlist 明确
排除的表外，既有 audit/ledger 行仍正常进入 manifest；本次尚不存在的 lineage 行自然不在
pre-audit logical hash 中。

两行提交并完成 exact schema/FK/`quick_check` 后，再从 post-audit 五组件 snapshot 计算独立
final component manifest。final manifest 不回写到其所 hash 的数据库；它写入后继 DPAPI
receipt，并通过 receipt predecessor hash 和两边共同的 immutable `lineageId` 绑定数据库
ledger。这样 ledger、receipt 和 final manifest 形成单向 append-only 链，不要求寻找
cryptographic fixed point，也不以 pre-audit logical hash冒充 post-audit component hash。

计数必须与各自证据阶段一致：exact source user v10 固定为 27 张 application table；完成
canonical migration 后的 post-audit exact user v11 固定为 29 张 application table，其中新增
`legal_answer_records` 与 `document_generation_records`。`user_v11_verified` receipt 记录后者；
计数只作冻结的结构约束，不能替代完整 schema/object 与 logical/business manifest 验证。

## Step 8、终态证据与历史授权

ordinal 8 的 `08-user_v11_verified.receipt.dpapi` 必须由一次启动的只读观察器看到，才能授权
Step 8；在当前进程内新写出的 ordinal 8 不得立即授权 maintenance。升级因此在 ordinal 8 后
固定要求一次协调重启。跨越该边界的唯一能力是进程启动时取得的 opaque gate，不接受调用者
传入路径、receipt hash 或重新扫描得到的普通结构体作为替代。

Step 8 首先安装同 lineage 的
`08-step8-predecessor.evidence.dpapi`（staging sibling 固定为追加 `.incoming`）。其 plaintext
是拒绝 unknown field 的 canonical JSON，并由 Windows DPAPI CurrentUser 保护；安装仍使用
create-new、回读认证、no-replacement rename 和父目录 durability。证据必须完整冻结 ordinal 8
evidence、ordinal 7/8 protected-file hash、user audit hash、Privacy lineage hash、ordinal 8
计数、五槽 final component manifest，以及六个 checkpoint 文件的 exact basename、长度和
SHA-256。缺失、重复 final/incoming、非 canonical、不同 payload 的续作或任何不一致均 fail
closed。

解封 predecessor 后，认证器必须重新读取并精确验证 V2 identity/bundle、十文件 receipt 前缀、
六个 checkpoint、user operation audit 和 Privacy application lineage；历史 ordinal-8 loader
只接受这个已认证 opaque predecessor。攻击者即使在篡改后重新扫描并取得一组彼此一致的 raw
hash，也不能据此获得历史授权。升级完成后的普通业务行变化可以继续发生，但 V2、receipt、
checkpoint、两个 append-only upgrade anchor 或 sidecar 的变化必须拒绝。

Step 8 的唯一 cutoff 是 ordinal 8 ledger 的正 `createdAtUnix`。两个 cleanup ID 固定为
`cln_` 加 `SHA-256(domain, lineageId, action)` 的前 32 个 lowercase-hex：一个用于 Privacy
retention cleanup，一个用于 Vault expired cleanup。missing、prepared、committed、purged
状态都必须以相同 ID 和 cutoff run-or-resume；已存在 journal 只能认证或完成唯一续作，不同
ID/cutoff 或语义不一致均 fail closed。写 ordinal 9 前，pending project deletion、retention、
Vault prepared/committed、assistant run/tool、assistant artifact export 与 document export
计数必须全部为零。

Receipt 8 与 Step 8 后的五槽重捕获不得复用 Step 3 的零库存 target gate。Approved 与
work-products 必须处于完整 `ApprovedAndWorkProducts` current lifecycle，四个已认证 archive /
manifest hash 必须全部存在，且 current Approved、Privacy 与 Vault 的 workspace 必须精确等于
receipt 链冻结的 target workspace。Current Vault 可以合法非空并保留 WAL；其 schema、语义行数
和 main/WAL source hash 必须来自同一次私有只读快照，源 main/WAL 前后不变。SHM 只包含易变的
锁与 read-mark 状态，只验证它是固定本地、普通、单链接文件，不把 SHM bytes 或 hash 写入耐久
manifest。Step 3 的 immutable main-only、零库存验证仍保持不变。

完成五个 maintenance action 和四个迁移 no-op proof 后，安装
`09-upgrade_complete.evidence.dpapi`（staging sibling 同样固定为追加 `.incoming`）。其 canonical
payload 必须保存 predecessor/post-maintenance 五槽 manifest、前序 receipt/evidence、audit 与
lineage hash、固定 cutoff/cleanup ID、四个 no-op 结果和五个带类型的 semantic action 结果。
为避免 Receipt 9 与其证据自引用，Receipt 9 的 `evidenceSha256` 不是单独的 plaintext hash，
而是 canonical payload hash 与受保护 sidecar 文件 bytes hash 的规范 binding hash；因此替换
DPAPI ciphertext 即使能解出相同 JSON 也不能通过。

终态 lineage 必须精确拥有十个连续 final receipt、V2 identity/bundle、六个 exact-final
checkpoint、Step-8 predecessor sidecar 和 Receipt-9 evidence sidecar，且没有 incoming 或未知
文件。终态历史认证必须先认证 predecessor，再真正解封和校验 Receipt-9 sidecar 与 ordinal 9；
只检查 basename 存在不构成授权。普通启动仍需重新捕获当前五槽 manifest 与四个 no-op 状态，
允许业务数据在终态之后正常变化，但所有冻结锚点的篡改均停止启动。两个 sidecar 的 incoming
只可在 payload 与预期完全相等时续作；incoming 与 final 同时存在必败。receipt 时间戳必须
单调不减，允许相邻 receipt 时间相等，不允许回退。

## R3 显式恢复 wire 与提交边界

### 命名空间与用户意图

R3 保留 R2 已冻结的正式 marker basename
`<app-root>/v031-migration-recovery-pending.dpapi`。它的两级安装 basename 固定为
`v031-migration-recovery-pending.dpapi.incoming.staging` 与
`v031-migration-recovery-pending.dpapi.incoming`，不得使用随机临时名或其他扩展名。
用户只能在已经通过普通完成态启动 gate 的 v0.4.0 UI 中输入精确确认短语
`恢复到 v0.3.1 并退出当前应用` 后调用 `stage_v031_migration_recovery`。该命令不接受路径、
lineage、workspace、Privacy CaseId、credential 或 backup bytes；后端从 user audit、Privacy
lineage 和完整 terminal history 中重新认证与当前 workspace 唯一匹配的完成态 lineage。

每次意图创建一个 `rcv_` 加 32 位 CSPRNG lowercase hex 的 `recoveryId`，并使用：

```text
<app-root>/v031-migration-recovery-audit/<recoveryId>/
  current-v040-safety-v3.lavbackup
  current-v040-credentials.dpapi
  abort-to-current.evidence.dpapi
  five-slot-commit.evidence.dpapi
  applied-downgrade.report.dpapi
  aborted-current-restored.report.dpapi
```

四个 evidence/report final 文件各自只有两级固定安装路径 `<final>.incoming.staging` 与
`<final>.incoming`。安装链严格为 create-new inner staging、回读 canonical/DPAPI payload、
no-replacement rename 到 incoming、再次回读，再 no-replacement rename 到 final 并回读；只有
经过认证的 final 是对应 commit、abort intent 或 report 的权威证据。单独或伴随 final 出现的
incoming/inner staging 都只是安装 residue，不得授权提交、反向恢复或完成报告；它们必须按当前
正式 marker 与 authenticated final 状态确定性清理，并在终态证明 absent。正式 marker absent
时，即使审计目录中存在 authenticated final，它也只作为审计材料保留，不授予 active mutation。
正式 marker 存在且仍在 commit 前时，任一 evidence/report residue 都按持久化中断处理：不能继续
正向 swap，必须先安装/认证 abort intent，再恢复 stage 时完整 current 五槽。

该目录不属于 `migration-backups` terminal lineage；普通启动不得把已经完成或在正式 marker
安装前中断的 audit 目录当作升级 receipt。安全备份复用普通 V3 wire，但其构建使用同一个
application-backup write barrier：在 barrier 内捕获五个 active 物理槽位的 exact fingerprint、
user/Privacy/Vault/Approved/WorkProducts component identity 和备份内容，并在释放 barrier 前重捕
五槽、证明前后逐项相等。Safety proof 除普通 V3 metadata/bundle hash/长度外，固定增加
`componentIdentitySha256` 与五槽 canonical inventory 的 `stageSlotInventorySha256`；marker 必须
绑定整个 proof。这样 safety 内容、component identity 和将被交换的五个物理槽位属于同一写屏障，
不能以只认证 bundle metadata 代替该绑定。

Safety 的固定三段安装路径是：

```text
current-v040-safety-v3.lavbackup.incoming.staging
current-v040-safety-v3.lavbackup.incoming
current-v040-safety-v3.lavbackup
```

必须 create-new 写 inner staging 并认证回读，no-replacement rename 到 incoming、同步 audit directory
并再次认证回读，再 no-replacement rename 到 final、同步目录并最终认证回读；创建 marker 前必须
证明两个中间路径 absent。任何中断只发生在正式 marker 创建前，残留 safety inner staging/incoming
都没有 mutation authority，普通 startup 不得据此进入 recovery-only。

credential archive 是独立 canonical JSON + DPAPI CurrentUser 文件，按
固定顺序恰好保存 ApprovedManifest、WorkProductManifest、McpTicket、
QualificationRevocationEpoch 四个 32-byte value。明文使用 zeroizing buffer，外层 marker 只绑定
protected file 的 basename、长度和 SHA-256。

安装顺序固定为：创建并回读 V3 safety、创建并回读 credential archive、重验当前五槽与完整
terminal anchors、create-new 写 marker inner staging 并回读认证、以 no-replacement/write-through
rename 提升为 `.incoming` 并再次回读、把 exit coordinator 从 Idle 原子转为 Draining、关闭新的
MCP/standalone provisioning 准入、等待 embedded MCP 请求结束、撤销全部仍 active 的
authenticated standalone descriptor、取得 User、Privacy/Vault、Approved/Work-Products 写屏障
（其取得必须线性化在既有业务写入及跨进程 Approved operation lock 之后，并从此拒绝新的五槽
写入）、在屏障内最终重验 terminal/V2/Safety/
四凭据/current 五槽，最后才以 no-replacement/write-through rename 把 `.incoming` 提升为正式
marker。正式 marker absent 时，`.incoming` 和 inner staging 一律没有 mutation authority；R3
startup observer 必须直接返回 absent，普通启动继续，且不得解析、提升、删除或因损坏 residue
而阻断。只有后续新的显式 staging 请求可以先清理二者，再重新认证并建立意图。前两项完成而正式
marker 尚未出现时也没有 mutation authority；可保留为审计材料，当前 profile 未改变。
Idle→Draining 转换失败、任一排空超时或最终复证失败时必须保持正式 marker absent，删除并回读
证明 `.incoming` 与 inner staging absent，再仅请求普通受控 restart。正式 marker 提升后，三类
写屏障与 migration mutex 保留到进程退出，命令请求 restart，不再返回可继续业务操作的正常 UI
状态。该顺序是数据安全澄清：exit coordinator 本身不等价于 MCP/standalone 排空，正式 authority
不得早于实际 quiescence。

### Marker canonical payload

`V031MigrationRecoveryPendingV1` 使用 `camelCase`、`deny_unknown_fields`、canonical UTF-8 JSON、
DPAPI CurrentUser 和 64 KiB protected-file 上限；解封后重编码必须逐字节相等，`Debug` 不显示
案件内容、ID、路径或 secret。schema 固定为
`lawyer-assistance-v031-migration-recovery-pending-v1`，`formatVersion = 1`，creator/target 固定为
`0.4.0`/`0.3.1`。Payload 至少绑定 migration/recovery/lineage/envelope/source-profile、Receipt 9
protected/evidence、Step-8 predecessor 与 Receipt-9 sidecar protected hash、V2 identity/bundle、
V2 user v10/Privacy v1 的长度与 hash、workspace、stage 时 fresh five-slot manifest、V3 safety
metadata/bundle hash/长度、credential archive protected hash/长度、固定 slot count 5、phase 和
该 phase 已完成的精确 rename/cleanup prefix；不保存绝对路径、正文、文件原名、token、ticket、
key 或 Privacy CaseId。

Marker phase 的唯一顺序为：`requested`、`user_v10_staged`、`sources_staged`、`commit_ready`、
`user_moved_to_rollback`、`user_installed`、`privacy_moved_to_rollback`、`privacy_installed`、
`vault_moved_to_rollback`、`approved_moved_to_rollback`、`work_products_moved_to_rollback`、
`five_slot_committed`、五个固定 rollback-cleanup prefix、两个 auxiliary-cleanup prefix、四个固定
credential-delete prefix、`target_verified`、`report_installed`。每次更新必须 create-new 写
inner staging，回读后 no-replacement rename 为 `.incoming`，认证它是现 marker 的唯一直接后继，
再用同卷 write-through atomic replace。正式 main 单独存在，或 main 加其精确直接后继时才能
确定性续作；正式 main absent 始终按上述 R3 absent 规则处理，incoming-only 不可提升。其他
duplicate、skipped、stale、unknown phase 或 payload 漂移均 fail closed。若 main 与唯一直接后继
`.incoming` 并存，且 main 所绑定 recovery 已有 authenticated abort intent，则 main 保持权威；
observer 必须绑定两代 protected hash、验证直接后继关系并丢弃 `.incoming`，不得把正向后继提升。
没有 abort intent 时才把已认证直接后继 atomic replace 为正式 main。Inner staging 从不构成
后继 authority；commit 前存在时强制走 authenticated abort，且在提升或丢弃 `.incoming` 前必须
先证明 inner staging absent。

### Startup observer 与五槽交换

生产 startup 先运行 R3 observer；R3 present 时认证恢复 authority 后立即独占返回，不得再由普通
observer 读取已经交换或正在交换的槽位。R3 absent 时才认证 terminal history，并运行普通 full、legacy
与 Privacy restore observer；R3 present 时由 R3 observer 自行证明这些普通 marker absent 并独占
ADR 已冻结的十个 application-restore slots。它保留 marker protected proof、terminal inventory、
offline predecessor/Receipt-9 anchors、解封后的 V2 source image capability、V3 safety proof、
credential archive proof、phase 与 exact slot inventory；对路由层只暴露
`AuthenticatedPresence::Authenticated`，summary 不构成 mutation authority。

受控 restart 已关闭 manager 后，首次 swap 前必须证明 user/Privacy active、incoming、rollback
各自所有 `-wal`、`-shm`、`-journal` sidecar absent。两个 incoming main file 分别从已认证 V2
user v10 与 Privacy v1 create-new 写入固定 `<incoming>.staging`，用 exact validator/fingerprint
回读后，才以 no-replacement rename 提升为 incoming。固定 inner staging 为
`user.sqlite.application-restore-incoming.staging` 与
`privacy/privacy-workflow.sqlite.application-restore-incoming.staging`；它们从不构成 source
authority，incoming 接受前和第一次 active rename 前都必须 absent。第一次 rename 前再次认证
全部静态 anchors、stage 时 current manifest、V3 safety、credential archive、两个 incoming image
和七次 rename 尚未开始；不允许只移动 SQLite main 而忽略存在的 sidecar。

正式 marker 存在时，任一 user/Privacy `<incoming>.staging` 也只表示中断安装，不得当作 source
image；commit 前它与 marker/evidence inner staging 一样强制进入 authenticated abort-to-current。

七次 rename 严格为：

1. user active → user rollback；
2. user incoming → user active；
3. Privacy active → Privacy rollback；
4. Privacy incoming → Privacy active；
5. Vault active → Vault rollback；
6. Approved active → Approved rollback；
7. WorkProducts active → WorkProducts rollback。

每次 rename 前后都要重观察对应 phase、fixed path、ordinary/single-link/reparse proof，并在 rename
后先持久化下一 phase 才进行下一次。完成七次 rename 并重新证明 canonical user v10、Privacy
v1 与三个 target active absent 后，安装/回读
`five-slot-commit.evidence.dpapi`，再进入 `five_slot_committed`。该 evidence 是不可逆提交点；
`abort-to-current.evidence.dpapi` 是与它互斥的 authenticated abort intent。提交证据出现前一旦
决定反向恢复，必须先 create-new 安装并回读认证 abort intent，使其绑定 recovery/lineage、
stage 时 current manifest、V3 safety、credential archive、commit evidence authenticated-absent
证明以及当时的 exact phase/slot inventory；此后任何 restart 只能继续反向恢复，不能恢复正向
swap 或安装 commit evidence：

- commit evidence 之前的任何执行错误或 crash prefix，安装上述 abort intent 后逆序恢复五个原 v0.4 active
  槽、清理两个 incoming，恢复/回读四凭据并证明 stage 时 current manifest，写
  `aborted-current-restored.report.dpapi` 后删除 marker；abort intent 作为审计证据保留；
- commit evidence 之后 active source profile 已完整，不得因 cleanup 中断而反向恢复；保留 marker，按
  phase 单调续作，直到所有 residue 清理完毕。这样 cleanup 故障不会产生可启动的混合状态。

提交后的 rollback 清理顺序固定为 WorkProducts、Approved、Vault、Privacy、user。前三个目录
不得直接递归删除 rollback；必须先认证 rollback 与 stage 时 current fingerprint 相等，再以
no-replacement/write-through rename 分别移入固定 tombstone：

```text
privacy/approved-mcp/work-products.application-restore-cleanup
privacy/approved-mcp/approved-generations.application-restore-cleanup
case-vault-v2.application-restore-cleanup
```

每次 tombstone rename 完成后先持久化对应 cleanup phase；重启允许 tombstone 已部分删除，但只可
幂等续删该固定、ordinary、非 reparse 目录，并须在开始下一目录前证明 rollback 与 tombstone
同时 absent。Privacy/user 普通文件 rollback 仍按固定槽位删除并回读 absent。随后只删除
V3 明确排除的 `ticket-sessions`、`qualification` 两个固定 auxiliary directory，并按
QualificationRevocationEpoch、McpTicket、WorkProductManifest、ApprovedManifest 顺序删除、
回读四个 credential。不得递归猜测或删除未知目录；`privacy/approved-mcp` 只有在所有已知 target、
auxiliary 和 restore residue absent 且目录为空时才可移除。最后认证 user v10/marker、Privacy v1、
后三组件、四凭据、十个 swap slot、marker inner staging/`.incoming` 与全部 evidence/report
install residue 都处于目标状态，安装/回读
`applied-downgrade.report.dpapi`，再删除正式 marker。

`AppliedDowngrade { target_app_version: "0.3.1" }` 的构造器只存在于上述最终 proof 之后。
Production startup 消耗它后释放 migration guard、把 exit coordinator 标记为 Finalizing 并调用
`app.exit(0)`；不调用 restart，且本进程 current manager、migration、maintenance、UI 和后台任务
调用数必须为零。原 V2、V3 safety、credential archive、abort/commit/report 和迁移报告保留审计；
这些文件不得进入 exact-source target absence 或 terminal-lineage 阻断集合，因而后续显式 v0.4
启动可以新建不同 lineage 并重新完整升级。

## R2、R3 与 R7 验收归属

R2 只交付并测试原态 V2、identity/bundle 安装恢复、十 receipt chain、启动仲裁/升级 resume
和这些边界的故障注入。R2 可以把 V2 解密到隔离验证区并证明五槽内容，但不得宣称 active
components 已降级、recovery 已完成、v0.3.1 已重开或 `AppliedDowngrade` 已成立。

R3 才实现 active 五槽 downgrade swap、三个 present→rollback→authenticated-absent 的可逆
提交、失败时恢复完整 v0.4 五组件、成功清理已知 residue、返回
`AppliedDowngrade { target_app_version: "0.3.1" }` 后当前进程零初始化 `apply-and-exit`，以及
真实 v0.3.1 binary reopen 和再次 v0.4 upgrade harness。R2 测试不得以 mock 或仅解密覆盖
替代这些 R3 验收。

DPAPI 单元/集成测试只覆盖当前 Windows 用户下 round-trip、篡改、错 identity/AAD、断链和
不可恢复状态。不同 Windows 账户不能解封、干净机器不能复用原用户保护材料，以及真实
clean-machine 安装/升级/回滚属于 R7 外部门禁，必须使用多账户/clean-machine harness；不得
由 current-user 单元测试推断或宣称已经通过。

## 影响

该协议在创建任何 target identity 前留下可认证的旧态回滚证据；允许 WAL 模式源库而不写
source；为中断、篡改、显式降级和再次升级提供唯一可审计路径。代价是新增独立 V2 parser、
canonical manifest encoder、append-only receipt chain 和外部 Windows DPAPI 验收，但普通
V3 restore、Privacy/Vault 身份边界和冻结计划顺序不因此放宽。
