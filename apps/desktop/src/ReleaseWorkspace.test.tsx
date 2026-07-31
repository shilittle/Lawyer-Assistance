import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  ReleaseWorkspace,
  releaseOperationIsActive,
  type ReleaseOperation,
} from "./ReleaseWorkspace";

describe("ReleaseWorkspace maintenance activity", () => {
  it.each([
    ["idle", false],
    ["checking", true],
    ["installing", true],
    ["maintenance", true],
    ["restarting", true],
  ] as const)("maps %s to activity=%s", (operation, expected) => {
    expect(releaseOperationIsActive(operation as ReleaseOperation)).toBe(
      expected,
    );
  });

  it("disables update and diagnostic actions when another maintenance mutation is active", () => {
    const markup = renderToStaticMarkup(<ReleaseWorkspace disabled />);

    expect(markup).toContain('disabled="">检查更新</button>');
    expect(markup).toContain('disabled="">导出诊断报告</button>');
  });

  it("points application backup users to the lifecycle panel on the same page", () => {
    const markup = renderToStaticMarkup(<ReleaseWorkspace />);

    expect(markup).toContain("由本页下方的");
    expect(markup).not.toContain("备份操作已统一迁移到");
    expect(markup).not.toContain("隐私与本地处理 →");
  });
});
