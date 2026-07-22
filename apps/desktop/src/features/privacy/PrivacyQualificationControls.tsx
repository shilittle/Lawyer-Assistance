import { useEffect, useState } from "react";

import {
  getPrivacyConfig,
  installLocalMineruNetworkIsolation,
  installLocalMineruTrust,
  revokeLocalMineruQualification,
  runLocalMineruQualification,
} from "../../ipc/privacy/client";
import type { PrivacyConfigResponse } from "../../ipc/privacy/types";
import "./qualification.css";

interface PrivacyQualificationControlsProps {
  snapshot: PrivacyConfigResponse;
  disabled: boolean;
  onSnapshot: (snapshot: PrivacyConfigResponse) => void;
  onActivityChange?: (active: boolean) => void;
}

type QualificationAction = "idle" | "trust" | "firewall" | "qualify" | "revoke";

function errorMessage(error: unknown): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof error.message === "string"
  ) {
    return error.message;
  }
  return "本机 MinerU 资格操作失败。";
}

export function PrivacyQualificationControls({
  snapshot,
  disabled,
  onSnapshot,
  onActivityChange,
}: PrivacyQualificationControlsProps) {
  const [action, setAction] = useState<QualificationAction>("idle");
  const [ttlDays, setTtlDays] = useState("30");
  const [authorizeProduction, setAuthorizeProduction] = useState(false);
  const [authorizeAutoRouting, setAuthorizeAutoRouting] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const busy = action !== "idle";
  const controlsDisabled = disabled || busy || snapshot.config.ocr.mode === "off";

  useEffect(() => {
    onActivityChange?.(busy);
    return () => onActivityChange?.(false);
  }, [busy, onActivityChange]);

  async function perform(
    nextAction: QualificationAction,
    operation: () => Promise<PrivacyConfigResponse>,
    success: string,
  ) {
    if (disabled || busy) return;
    setAction(nextAction);
    setError("");
    setNotice("");
    try {
      const next = await operation();
      onSnapshot(next);
      setNotice(success);
    } catch (reason: unknown) {
      setError(errorMessage(reason));
    } finally {
      setAction("idle");
    }
  }

  async function installTrust() {
    if (controlsDisabled) return;
    setAction("trust");
    setError("");
    setNotice("");
    try {
      const trust = await installLocalMineruTrust();
      onSnapshot(await getPrivacyConfig());
      setNotice(
        `已建立本机受信清单：${trust.modelFileCount} 个模型文件、${trust.runtimeExecutableCount} 个运行时可执行文件。`,
      );
    } catch (reason: unknown) {
      setError(errorMessage(reason));
    } finally {
      setAction("idle");
    }
  }

  function qualify() {
    const days = Number(ttlDays);
    if (!Number.isSafeInteger(days) || days < 1 || days > 90) {
      setError("资格有效期必须是 1–90 天的整数。");
      return;
    }
    if (!authorizeProduction) {
      setError("必须显式勾选生产案件 OCR 授权，才能签发生产资格。");
      return;
    }
    void perform(
      "qualify",
      () =>
        runLocalMineruQualification({
          ttlSeconds: days * 24 * 60 * 60,
          productionCaseOcrAuthorized: true,
          appAutoEnableAuthorized: authorizeAutoRouting,
        }),
      "合成 canary 已通过；资格已绑定当前应用、worker、运行时、模型和防火墙状态。",
    );
  }

  const expires = snapshot.qualification.expiresAtUnix
    ? new Date(snapshot.qualification.expiresAtUnix * 1_000).toLocaleString()
    : "无有效资格";

  return (
    <section className="privacy-qualification-controls" aria-busy={busy}>
      <div className="panel-heading">
        <div>
          <p className="eyebrow">本机生产资格</p>
          <h3>安装信任、强制断网、运行 canary、签发或撤销</h3>
        </div>
        <span className="privacy-gate-badge">
          {snapshot.capabilities.scannedCaseOcrEnabled ? "OCR ready" : "OCR blocked"}
        </span>
      </div>

      <ol className="privacy-qualification-steps">
        <li>
          <button disabled={controlsDisabled} type="button" onClick={() => void installTrust()}>
            {action === "trust" ? "正在生成受信清单…" : "1. 建立当前安装信任"}
          </button>
          <span>逐文件哈希 worker、tools JSON、离散运行时和模型全集；任一变化都会失效。</span>
        </li>
        <li>
          <button
            disabled={controlsDisabled}
            type="button"
            onClick={() =>
              void perform(
                "firewall",
                installLocalMineruNetworkIsolation,
                "Windows Defender Firewall 出站阻断规则已安装并从 ActiveStore 复核。",
              )
            }
          >
            {action === "firewall" ? "正在安装并复核…" : "2. 安装并复核网络隔离"}
          </button>
          <span>此步骤需要管理员权限；拒绝提权或规则缺失时保持 fail closed。</span>
        </li>
        <li className="privacy-qualification-authorize">
          <label>
            <span>有效期（天）</span>
            <input
              disabled={controlsDisabled}
              inputMode="numeric"
              value={ttlDays}
              onChange={(event) => setTtlDays(event.target.value)}
            />
          </label>
          <label>
            <input
              checked={authorizeProduction}
              disabled={controlsDisabled}
              type="checkbox"
              onChange={(event) => setAuthorizeProduction(event.target.checked)}
            />
            我明确授权当前受信环境处理生产案件扫描件
          </label>
          <label>
            <input
              checked={authorizeAutoRouting}
              disabled={controlsDisabled}
              type="checkbox"
              onChange={(event) => setAuthorizeAutoRouting(event.target.checked)}
            />
            我明确授权 App 自动将低质量 PDF 路由到本地 OCR（不含自动批准脱敏）
          </label>
          <button disabled={controlsDisabled || !authorizeProduction} type="button" onClick={qualify}>
            {action === "qualify" ? "正在运行合成 canary…" : "3. 运行 canary 并签发资格"}
          </button>
        </li>
        <li>
          <button
            disabled={disabled || busy || !snapshot.qualification.qualificationId}
            type="button"
            onClick={() =>
              void perform(
                "revoke",
                revokeLocalMineruQualification,
                "当前本机 OCR 资格已撤销。",
              )
            }
          >
            {action === "revoke" ? "正在撤销…" : "撤销当前资格"}
          </button>
          <span>资格到期：{expires}</span>
        </li>
      </ol>

      {snapshot.qualification.reasonCodes.length ? (
        <p className="privacy-qualification-note">
          阻断原因：<code>{snapshot.qualification.reasonCodes.join(", ")}</code>
        </p>
      ) : null}
      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {notice ? <p className="privacy-notice" aria-live="polite">{notice}</p> : null}
    </section>
  );
}
