import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  assignUnassignedCaseMaterial,
  listCaseMaterials,
  listCaseRedactionGenerations,
  listUnassignedCaseMaterials,
} from "../../../ipc/privacy/case-material-client";
import type {
  AssignUnassignedCaseMaterialRequest,
  CaseMaterialSummary,
  CaseRedactionGenerationSummary,
  UnassignedCaseMaterialSummary,
} from "../../../ipc/privacy/case-material-types";
import "../../privacy/privacy.css";
import { ApprovedGenerationList } from "./ApprovedGenerationList";
import { CaseMaterialHistorySummary } from "./CaseMaterialHistorySummary";
import { CaseMaterialList } from "./CaseMaterialList";
import {
  caseMaterialSelectionIsHistoryOnly,
  isCaseMaterialAvailable,
  isCaseRedactionGenerationAvailable,
} from "./caseMaterialAvailability";
import "./case-materials.css";
import { RedactionWorkbench } from "./RedactionWorkbench";
import { UnassignedCaseMaterialList } from "./UnassignedCaseMaterialList";
import {
  buildUnassignedAssignmentRequest,
  CASE_MATERIAL_CONTEXT_DISCARD_CONFIRMATION,
  caseMaterialsWorkspaceDraftIsDirty,
  executeConfirmedUnassignedAssignment,
  unassignedAssignmentConfirmation,
} from "./unassignedAssignment";

export interface CaseMaterialsWorkspaceProps {
  projectId: string | null;
  resetKey: number;
  onDraftDirtyChange: (dirty: boolean) => void;
  onMutationActivityChange: (active: boolean) => void;
}

function displayError(error: unknown): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof error.message === "string"
  ) {
    return error.message;
  }
  return "无法读取当前案件的材料目录。";
}

function latestGenerationId(
  generations: readonly CaseRedactionGenerationSummary[],
): string | null {
  return (
    [...generations]
      .filter(
        isCaseRedactionGenerationAvailable,
      )
      .sort(
        (left, right) =>
          right.generationNumber - left.generationNumber,
      )[0]?.redactionId ?? null
  );
}

export function CaseMaterialsWorkspace({
  projectId,
  resetKey,
  onDraftDirtyChange,
  onMutationActivityChange,
}: CaseMaterialsWorkspaceProps) {
  const [materials, setMaterials] = useState<CaseMaterialSummary[]>([]);
  const [generations, setGenerations] = useState<
    CaseRedactionGenerationSummary[]
  >([]);
  const [unassignedMaterials, setUnassignedMaterials] = useState<
    UnassignedCaseMaterialSummary[]
  >([]);
  const [assignmentActor, setAssignmentActor] = useState("");
  const [selectedMaterialId, setSelectedMaterialId] = useState<
    string | null
  >(null);
  const [selectedRedactionId, setSelectedRedactionId] = useState<
    string | null
  >(null);
  const [
    generationCatalogMaterialId,
    setGenerationCatalogMaterialId,
  ] = useState<string | null>(null);
  const [loadingMaterials, setLoadingMaterials] = useState(
    projectId !== null,
  );
  const [loadingUnassigned, setLoadingUnassigned] = useState(
    projectId !== null,
  );
  const [loadingGenerations, setLoadingGenerations] = useState(false);
  const [assignmentActive, setAssignmentActive] = useState(false);
  const [workbenchBusy, setWorkbenchBusy] = useState(false);
  const [workbenchDirty, setWorkbenchDirty] = useState(false);
  const [workbenchKey, setWorkbenchKey] = useState(0);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const materialRequestSequence = useRef(0);
  const generationRequestSequence = useRef(0);
  const unassignedRequestSequence = useRef(0);

  const refreshMaterials = useCallback(
    async (preferredMaterialId?: string | null) => {
      if (!projectId) return [];
      const sequence = materialRequestSequence.current + 1;
      materialRequestSequence.current = sequence;
      const next = await listCaseMaterials({ projectId });
      if (sequence !== materialRequestSequence.current) return [];
      if (next.some((material) => material.projectId !== projectId)) {
        throw new Error("材料目录包含其他案件记录；已阻断显示。");
      }
      setMaterials(next);
      setSelectedMaterialId((current) => {
        const preferred = preferredMaterialId ?? current;
        if (
          preferred &&
          next.some(
            (material) => material.materialId === preferred,
          )
        ) {
          return preferred;
        }
        return (
          next.find(isCaseMaterialAvailable)?.materialId ??
          next[0]?.materialId ??
          null
        );
      });
      return next;
    },
    [projectId],
  );

  const refreshGenerations = useCallback(
    async (
      materialId: string,
      preferredRedactionId?: string | null,
    ) => {
      if (!projectId) return [];
      const sequence = generationRequestSequence.current + 1;
      generationRequestSequence.current = sequence;
      const next = await listCaseRedactionGenerations({
        projectId,
        materialId,
      });
      if (sequence !== generationRequestSequence.current) return [];
      if (
        next.some(
          (generation) =>
            generation.projectId !== projectId ||
            generation.materialId !== materialId,
        )
      ) {
        throw new Error("脱敏代次包含跨案件或跨材料记录；已阻断显示。");
      }
      const sorted = [...next].sort(
        (left, right) =>
          right.generationNumber - left.generationNumber,
      );
      setGenerations(sorted);
      setGenerationCatalogMaterialId(materialId);
      setSelectedRedactionId((current) => {
        const preferred = preferredRedactionId ?? current;
        return preferred &&
          sorted.some(
            (generation) => generation.redactionId === preferred,
          )
          ? preferred
          : latestGenerationId(sorted) ??
              sorted[0]?.redactionId ??
              null;
      });
      return sorted;
    },
    [projectId],
  );

  useEffect(() => {
    if (!projectId) return;
    setLoadingMaterials(true);
    const sequence = materialRequestSequence.current + 1;
    materialRequestSequence.current = sequence;
    void listCaseMaterials({ projectId })
      .then((next) => {
        if (sequence !== materialRequestSequence.current) return;
        if (
          next.some((material) => material.projectId !== projectId)
        ) {
          throw new Error(
            "材料目录包含其他案件记录；已阻断显示。",
          );
        }
        setMaterials(next);
        setGenerationCatalogMaterialId(null);
        setSelectedMaterialId(
          next.find(isCaseMaterialAvailable)?.materialId ??
            next[0]?.materialId ??
            null,
        );
      })
      .catch((reason: unknown) => {
        if (sequence === materialRequestSequence.current) {
          setError(displayError(reason));
        }
      })
      .finally(() => {
        if (sequence === materialRequestSequence.current) {
          setLoadingMaterials(false);
        }
      });
    return () => {
      materialRequestSequence.current += 1;
    };
  }, [projectId, resetKey]);

  useEffect(() => {
    if (!projectId) return;
    setLoadingUnassigned(true);
    const sequence = unassignedRequestSequence.current + 1;
    unassignedRequestSequence.current = sequence;
    void listUnassignedCaseMaterials({ projectId })
      .then((next) => {
        if (sequence !== unassignedRequestSequence.current) return;
        setUnassignedMaterials(next);
      })
      .catch((reason: unknown) => {
        if (sequence === unassignedRequestSequence.current) {
          setError(displayError(reason));
        }
      })
      .finally(() => {
        if (sequence === unassignedRequestSequence.current) {
          setLoadingUnassigned(false);
        }
      });
    return () => {
      unassignedRequestSequence.current += 1;
    };
  }, [projectId, resetKey]);

  useEffect(() => {
    if (!projectId || !selectedMaterialId) {
      setGenerations([]);
      setSelectedRedactionId(null);
      setGenerationCatalogMaterialId(null);
      setLoadingGenerations(false);
      return;
    }
    const materialId = selectedMaterialId;
    setLoadingGenerations(true);
    setGenerations([]);
    setSelectedRedactionId(null);
    setGenerationCatalogMaterialId(null);
    const sequence = generationRequestSequence.current + 1;
    generationRequestSequence.current = sequence;
    void listCaseRedactionGenerations({ projectId, materialId })
      .then((next) => {
        if (sequence !== generationRequestSequence.current) return;
        if (
          next.some(
            (generation) =>
              generation.projectId !== projectId ||
              generation.materialId !== materialId,
          )
        ) {
          throw new Error(
            "脱敏代次包含跨案件或跨材料记录；已阻断显示。",
          );
        }
        const sorted = [...next].sort(
          (left, right) =>
            right.generationNumber - left.generationNumber,
        );
        setGenerations(sorted);
        setGenerationCatalogMaterialId(materialId);
        setSelectedRedactionId(
          latestGenerationId(sorted) ??
            sorted[0]?.redactionId ??
            null,
        );
      })
      .catch((reason: unknown) => {
        if (sequence === generationRequestSequence.current) {
          setError(displayError(reason));
        }
      })
      .finally(() => {
        if (sequence === generationRequestSequence.current) {
          setLoadingGenerations(false);
        }
      });
    return () => {
      generationRequestSequence.current += 1;
    };
  }, [projectId, selectedMaterialId]);

  const discardWorkbenchContext = useCallback(() => {
    if (workbenchDirty) {
      setWorkbenchDirty(false);
      setWorkbenchKey((current) => current + 1);
    }
  }, [workbenchDirty]);

  const requestWorkbenchContextChange = useCallback(
    (deferDiscard = false): boolean => {
      if (workbenchBusy) {
        setError(
          "材料脱敏操作仍在进行；请等待完成后再切换材料或代次。",
        );
        return false;
      }
      if (
        workbenchDirty &&
        !window.confirm(CASE_MATERIAL_CONTEXT_DISCARD_CONFIRMATION)
      ) {
        setNotice("已取消切换；案件材料与风险审阅草稿仍完整保留。");
        return false;
      }
      if (!deferDiscard) {
        discardWorkbenchContext();
      }
      setError("");
      return true;
    },
    [
      discardWorkbenchContext,
      workbenchBusy,
      workbenchDirty,
    ],
  );

  const selectMaterial = useCallback(
    (materialId: string) => {
      if (materialId === selectedMaterialId) return;
      if (!requestWorkbenchContextChange()) return;
      setGenerationCatalogMaterialId(null);
      setSelectedMaterialId(materialId);
    },
    [requestWorkbenchContextChange, selectedMaterialId],
  );

  const selectGeneration = useCallback(
    (redactionId: string) => {
      if (redactionId === selectedRedactionId) return;
      if (!requestWorkbenchContextChange()) return;
      setSelectedRedactionId(redactionId);
    },
    [requestWorkbenchContextChange, selectedRedactionId],
  );

  const reviewChanged = useCallback(
    async (materialId: string, redactionId: string | null) => {
      if (!projectId) return;
      await refreshMaterials(materialId);
      const next = await refreshGenerations(materialId, redactionId);
      setSelectedMaterialId(materialId);
      setSelectedRedactionId(
        redactionId &&
          next.some(
            (generation) => generation.redactionId === redactionId,
          )
          ? redactionId
          : latestGenerationId(next),
      );
    },
    [projectId, refreshGenerations, refreshMaterials],
  );

  const setDraftDirty = useCallback(
    (dirty: boolean) => {
      setWorkbenchDirty(dirty);
    },
    [],
  );

  useEffect(() => {
    onDraftDirtyChange(
      caseMaterialsWorkspaceDraftIsDirty(
        workbenchDirty,
        assignmentActor,
      ),
    );
  }, [
    assignmentActor,
    onDraftDirtyChange,
    workbenchDirty,
  ]);

  useEffect(
    () => () => {
      onDraftDirtyChange(false);
    },
    [onDraftDirtyChange],
  );

  const setMutationActive = useCallback(
    (active: boolean) => {
      setWorkbenchBusy(active);
      onMutationActivityChange(active);
    },
    [onMutationActivityChange],
  );

  const assignUnassigned = useCallback(
    async (material: UnassignedCaseMaterialSummary) => {
      if (!projectId || assignmentActive || workbenchBusy) return;
      let request: AssignUnassignedCaseMaterialRequest;
      try {
        request = buildUnassignedAssignmentRequest(
          projectId,
          material,
          assignmentActor,
        );
      } catch (reason: unknown) {
        setError(displayError(reason));
        return;
      }
      let started = false;
      try {
        const outcome = await executeConfirmedUnassignedAssignment({
          authorizeContextChange: () =>
            requestWorkbenchContextChange(true),
          confirmAssignment: () =>
            window.confirm(
              unassignedAssignmentConfirmation(
                request,
                material.displayName,
              ),
            ),
          execute: async () => {
            started = true;
            setAssignmentActive(true);
            onMutationActivityChange(true);
            setError("");
            setNotice("");
            const response =
              await assignUnassignedCaseMaterial(request);
            if (
              response.projectId !== projectId ||
              response.materialId !== material.materialId
            ) {
              throw new Error(
                "后端归属结果与明确选择的案件或材料不一致；已阻断界面更新。",
              );
            }
            const [nextMaterials, nextUnassigned] =
              await Promise.all([
                listCaseMaterials({ projectId }),
                listUnassignedCaseMaterials({ projectId }),
              ]);
            if (
              nextMaterials.some(
                (item) => item.projectId !== projectId,
              ) ||
              !nextMaterials.some(
                (item) =>
                  item.materialId === material.materialId,
              )
            ) {
              throw new Error(
                "归属后的案件材料目录不完整或包含跨案件记录；界面保持原状态。",
              );
            }
            if (
              nextUnassigned.some(
                (item) =>
                  item.materialId === material.materialId,
              )
            ) {
              throw new Error(
                "归属后的未归属清单仍包含目标材料；界面保持原状态。",
              );
            }
            return {
              response,
              nextMaterials,
              nextUnassigned,
            };
          },
          commit: ({
            response,
            nextMaterials,
            nextUnassigned,
          }) => {
            setMaterials(nextMaterials);
            setUnassignedMaterials(nextUnassigned);
            discardWorkbenchContext();
            setGenerationCatalogMaterialId(null);
            setSelectedMaterialId(material.materialId);
            setAssignmentActor("");
            setNotice(
              response.idempotentReplay
                ? "该材料此前已按同一审计操作归入当前案件；目录已刷新。"
                : "历史材料已按明确用户操作归入当前案件；目录与未归属清单已刷新。",
            );
          },
        });
        if (outcome.kind === "assignment_cancelled") {
          setNotice("已取消归属；历史材料、操作人输入及当前草稿保持不变。");
        }
      } catch (reason: unknown) {
        setError(displayError(reason));
      } finally {
        if (started) {
          setAssignmentActive(false);
          onMutationActivityChange(false);
        }
      }
    },
    [
      assignmentActive,
      assignmentActor,
      discardWorkbenchContext,
      onMutationActivityChange,
      projectId,
      requestWorkbenchContextChange,
      workbenchBusy,
    ],
  );

  const selectedMaterial = useMemo(
    () =>
      materials.find(
        (material) => material.materialId === selectedMaterialId,
      ) ?? null,
    [materials, selectedMaterialId],
  );
  const visibleGenerations = useMemo(
    () =>
      generations.filter(
        (generation) =>
          generation.materialId === selectedMaterialId,
      ),
    [generations, selectedMaterialId],
  );
  const visibleSelectedRedactionId =
    selectedRedactionId &&
    visibleGenerations.some(
      (generation) =>
        generation.redactionId === selectedRedactionId,
    )
      ? selectedRedactionId
      : null;
  const selectedGeneration = useMemo(
    () =>
      visibleGenerations.find(
        (generation) =>
          generation.redactionId === visibleSelectedRedactionId,
      ) ?? null,
    [visibleGenerations, visibleSelectedRedactionId],
  );
  const historyOnly = caseMaterialSelectionIsHistoryOnly(
    selectedMaterial,
    selectedGeneration,
  );
  const generationCatalogReady =
    selectedMaterial === null ||
    generationCatalogMaterialId === selectedMaterial.materialId;
  const busy =
    loadingMaterials ||
    loadingUnassigned ||
    loadingGenerations ||
    workbenchBusy ||
    assignmentActive;

  if (!projectId) {
    return (
      <section className="case-materials-empty panel">
        <p className="eyebrow">材料与脱敏</p>
        <h2>先选择一个已保存案件</h2>
        <p>
          案件材料必须归属于现有 ProjectId。新建案件后请先保存，再导入本机材料。
        </p>
      </section>
    );
  }

  return (
    <main
      className="case-materials-workspace"
      aria-busy={busy}
      data-project-id={projectId}
    >
      <header className="case-materials-heading">
        <div>
          <p className="eyebrow">案件工作台 · 材料与脱敏</p>
          <h1>案件材料处理</h1>
          <p>
            所有文件选择、提取、OCR、脱敏与复核都限定在当前案件；
            Privacy/Vault 身份只由可信后端绑定解析。
          </p>
        </div>
        <code>{projectId}</code>
      </header>

      <UnassignedCaseMaterialList
        projectId={projectId}
        materials={unassignedMaterials}
        actor={assignmentActor}
        busy={busy}
        onActorChange={setAssignmentActor}
        onAssign={(material) => void assignUnassigned(material)}
      />

      <div className="case-materials-catalog">
        <CaseMaterialList
          materials={materials}
          selectedMaterialId={selectedMaterialId}
          busy={busy}
          onSelect={selectMaterial}
        />
        <ApprovedGenerationList
          generations={visibleGenerations}
          selectedRedactionId={visibleSelectedRedactionId}
          busy={busy}
          onSelect={selectGeneration}
        />
      </div>

      {selectedMaterial?.migrationStatus === "legacy_reference" ? (
        <p className="privacy-risk-blocker" role="alert">
          该记录是尚未解析的历史材料引用，不能读取原文或进入脱敏工作流。
        </p>
      ) : null}
      {selectedMaterial?.migrationStatus === "blocked" ? (
        <p className="privacy-risk-blocker" role="alert">
          该材料存在迁移或身份冲突，必须先处理迁移问题；系统不会猜测案件归属。
        </p>
      ) : null}

      {selectedMaterial && !generationCatalogReady ? (
        <section className="panel" aria-busy="true">
          <p>正在读取所选材料的安全代次摘要…</p>
        </section>
      ) : historyOnly && selectedMaterial ? (
        <CaseMaterialHistorySummary
          material={selectedMaterial}
          generation={selectedGeneration}
        />
      ) : (
        <RedactionWorkbench
          key={`${projectId}:${resetKey}:${workbenchKey}:${selectedMaterialId ?? "new"}:${visibleSelectedRedactionId ?? "none"}`}
          projectId={projectId}
          selectedRedactionId={
            selectedGeneration &&
            isCaseRedactionGenerationAvailable(selectedGeneration)
              ? visibleSelectedRedactionId
              : null
          }
          latestRedactionId={latestGenerationId(visibleGenerations)}
          disabled={loadingMaterials || assignmentActive}
          onDraftDirtyChange={setDraftDirty}
          onMutationActivityChange={setMutationActive}
          onReviewChanged={reviewChanged}
        />
      )}

      {error ? (
        <p className="error-text" role="alert">{error}</p>
      ) : null}
      {notice ? (
        <p className="privacy-notice" aria-live="polite">{notice}</p>
      ) : null}
    </main>
  );
}
