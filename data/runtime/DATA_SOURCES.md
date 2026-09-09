# 法律数据来源说明

随应用分发的 `legal_core.sqlite` 是只读法律资料库。其纳入范围、排除范围、来源类型、构建日期和审计口径见项目 `data/sources/coverage.md`；逐来源记录及哈希由 source manifest 管理。

应用展示的资料仅用于辅助检索和律师复核，不替代对官方现行文本、案件事实及专业判断的核验。发布包必须通过正式库 strict audit，并让发布清单记录数据库版本、文件哈希和 source manifest hash。
