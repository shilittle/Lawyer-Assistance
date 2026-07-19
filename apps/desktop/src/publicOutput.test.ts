import { describe, expect, it } from "vitest";

import {
  hasInternalEngineeringDetail,
  publicContentSummary,
  publicErrorMessage,
  publicTitle,
  sanitizePublicGeneratedText,
} from "./publicOutput";

describe("public output boundary", () => {
  it("never renders raw IPC messages or diagnostic paths as errors", () => {
    const raw = new Error(
      "failed at C:\\Users\\someone\\AppData\\Local\\app\\user.sqlite; document_id=doc-1",
    );
    expect(publicErrorMessage(raw)).toBe(
      "操作未完成，请重试；如仍失败，请导出诊断报告。",
    );
    expect(publicErrorMessage({ errorType: "not_found", message: raw.message })).toBe(
      "未找到所需内容，请刷新后重试。",
    );
    expect(
      publicErrorMessage({
        errorType: "legal_paragraph_unresolved",
        message:
          "legal source lacks an explicit paragraph; source_id=law-secret",
      }),
    ).toBe(
      "该条文包含多款，当前资料不能准确确定款次；请另选能够明确定位至具体款次的条文。",
    );
  });

  it("recognizes paths, identifiers, hashes, and machine fields", () => {
    expect(hasInternalEngineeringDetail("file:///C:/private/case.json")).toBe(true);
    expect(hasInternalEngineeringDetail("article_id: a-1")).toBe(true);
    expect(hasInternalEngineeringDetail("request_uuid: opaque-request")).toBe(true);
    expect(hasInternalEngineeringDetail("snnipet: 调试摘要")).toBe(true);
    expect(hasInternalEngineeringDetail("as_of 参数不受支持")).toBe(true);
    expect(hasInternalEngineeringDetail("score=0.82; cursor=next")).toBe(true);
    expect(hasInternalEngineeringDetail("service-aabbccddeeff0011-3")).toBe(true);
    expect(hasInternalEngineeringDetail("结构化文书预览")).toBe(true);
    expect(
      hasInternalEngineeringDetail("018f9e62-b8e4-7f11-8d4a-128ca6725910"),
    ).toBe(true);
    expect(hasInternalEngineeringDetail(`sha256:${"a".repeat(64)}`)).toBe(true);
  });

  it("withholds structured payloads and strips machine-only fields from prose", () => {
    expect(
      sanitizePublicGeneratedText(
        '{"schema_version":1,"article_id":"law-1","snippet":"raw"}',
      ),
    ).toBe("内容已完成处理，请在相应成果中查看。");
    expect(
      sanitizePublicGeneratedText(
        `结论可供复核。\narticle_id: law-1\n文件位于 C:\\private\\result.pdf`,
      ),
    ).toBe("结论可供复核。");
    expect(sanitizePublicGeneratedText("应当依法履行。[SRC:law-secret]")).toBe(
      "应当依法履行。",
    );
  });

  it("withholds a legacy case title polluted by internal markers or paths", () => {
    expect(publicTitle("合同纠纷 [SRC:law-secret]", "未命名案件")).toBe(
      "未命名案件",
    );
    expect(
      publicTitle("案件材料 C:\\Users\\someone\\private.pdf", "未命名案件"),
    ).toBe("未命名案件");
    expect(
      sanitizePublicGeneratedText(
        "买方主张逾期交付。project_id=project-secret",
        "暂无案件摘要",
      ),
    ).not.toContain("project_id");
  });

  it("cleans the real legal-search leak while preserving the readable table", () => {
    const raw = `3. legal_search 返回结果（3 条）
查询条件："民法典 合同履行 逾期交付"，limit=3

⚠️ as_of 参数在 schema_version=1 下不被支持，实际传入参数为 {schema_version, query, limit}。如需日期过滤，可改用 case_date 字段。

| # | article_id（稳定记录 ID） | 法条名称 | 条号 | 效力日期 | 所属文件 |
| --- | --- | --- | --- | --- | --- |
| 1 | art-06132e139e973a593f7745f9 | —（无标题） | 第九条 | 2025-01-20 起 | 《国务院关于修改和废止部分行政法规的决定》 |
| 2 | art-ed602e165210c106e96de7c9 | —（无标题） | 第八条第二项 | 2025-01-20 起 | 同上 |
| 3 | art-5c546732f6927381f1fb693f | —（无标题） | 第六条第二项 | 2025-01-20 起 | 同上 |

各条 snippet 摘要：

第九条：将《婚姻登记条例》中“胁迫结婚……依据民法典第一千零五十二条……请求撤销婚姻”`;

    const cleaned = sanitizePublicGeneratedText(raw);

    expect(cleaned).toBe(`3. 法律检索 返回结果（3 条）
查询条件："民法典 合同履行 逾期交付"

| # | 法条名称 | 条号 | 效力日期 | 所属文件 |
| --- | --- | --- | --- | --- |
| 1 | 《国务院关于修改和废止部分行政法规的决定》 | 第九条 | 2025-01-20 起 | 《国务院关于修改和废止部分行政法规的决定》 |
| 2 | 《国务院关于修改和废止部分行政法规的决定》 | 第八条第二项 | 2025-01-20 起 | 同上 |
| 3 | 《国务院关于修改和废止部分行政法规的决定》 | 第六条第二项 | 2025-01-20 起 | 同上 |

各条内容摘要：

第九条：将《婚姻登记条例》中“胁迫结婚……依据民法典第一千零五十二条……请求撤销婚姻”`);
    for (const forbidden of [
      "legal_search",
      "as_of",
      "schema_version",
      "article_id",
      "snippet",
      "snnipet",
      "request_uuid",
      "limit",
      "score",
      "cursor",
      "metadata",
      "无标题",
    ]) {
      expect(cleaned).not.toContain(forbidden);
    }
  });

  it("removes inline process details, paths, opaque ids, and hashes", () => {
    const cleaned = sanitizePublicGeneratedText(`## 结构化文书预览
模型措辞：被告应继续履行合同。
材料：[打开本地文件](C:\\Users\\someone\\案件\\结果.docx)
记录 018f9e62-b8e4-7f11-8d4a-128ca6725910，art-06132e139e973a593f7745f9，sha256:${"a".repeat(64)}。
结论：依据《中华人民共和国民法典》第五百七十七条第一款（2021年起施行），违约方应承担违约责任。`);

    expect(cleaned).toContain("## 文书内容");
    expect(cleaned).toContain("文书表述：被告应继续履行合同。");
    expect(cleaned).toContain("材料：打开本地文件");
    expect(cleaned).toContain(
      "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）",
    );
    expect(cleaned).not.toMatch(
      /结构化文书预览|模型措辞|[A-Za-z]:\\|018f9e62|art-06132|sha256|a{32}/u,
    );
  });

  it("preserves ordinary Chinese legal prose and Markdown tables", () => {
    const publicText = `合同履行结论如下：

| 法律依据 | 法律结论 |
| --- | --- |
| 《中华人民共和国民法典》第五百七十七条第一款（2021年起施行） | 当事人一方不履行合同义务，应当承担违约责任。 |`;

    expect(sanitizePublicGeneratedText(publicText)).toBe(publicText);
  });

  it("uses Chinese summary and semantic title fallbacks", () => {
    expect(publicContentSummary("raw english snippet")).toBe(
      "内容摘要暂不可用，请打开来源查看正文。",
    );
    expect(publicContentSummary("这是可供核对的内容摘要。")).toBe(
      "这是可供核对的内容摘要。",
    );
    expect(publicTitle("无标题", "《民法典》第五百七十七条")).toBe(
      "《民法典》第五百七十七条",
    );
    expect(publicTitle("—（无标题）", "《民法典》第五百七十七条")).toBe(
      "《民法典》第五百七十七条",
    );
  });
});
