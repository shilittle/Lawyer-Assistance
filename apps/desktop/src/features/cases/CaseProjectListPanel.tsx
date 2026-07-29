import { publicTitle } from "../../publicOutput";
import { publicCaseBusinessText, clampCaseProjectPage } from "./model";
import type { CaseWorkspaceController } from "./useCaseWorkspaceController";

export interface CaseProjectListPanelProps {
  controller: CaseWorkspaceController;
}

export function CaseProjectListPanel({
  controller,
}: CaseProjectListPanelProps) {
  const {
    caseProjects,
    setCaseProjectPage,
    selectedCaseProjectId,
    caseNavigationLocked,
    paginatedCaseProjects,
    startNewCaseProject,
    selectCaseProject,
  } = controller;

  return (
    <aside className="panel case-list-panel" aria-labelledby="case-list-title">
            <div className="panel-heading">
              <h2 id="case-list-title">案件项目</h2>
              <span>{caseProjects.length}</span>
            </div>
            <div className="provider-create-row">
              <button
                disabled={caseNavigationLocked}
                type="button"
                onClick={startNewCaseProject}
              >
                新建案件
              </button>
            </div>
            <div className="provider-list">
              {paginatedCaseProjects.projects.map((project) => (
                <button
                  className={`provider-item ${
                    selectedCaseProjectId === project.projectId
                      ? "is-selected"
                      : ""
                  }`}
                  disabled={caseNavigationLocked}
                  key={project.projectId}
                  type="button"
                  onClick={() => selectCaseProject(project)}
                >
                  <span className="item-title">
                    {publicTitle(project.title, "未命名案件")}
                  </span>
                  <span className="item-meta">
                    {project.caseType || "未分类"} ·{" "}
                    {project.openedOn ?? "未登记日期"}
                  </span>
                  <span className="item-summary">
                    {publicCaseBusinessText(project.summary, "暂无案件摘要")}
                  </span>
                </button>
              ))}
              {caseProjects.length === 0 ? (
                <p className="empty-state">暂无案件项目</p>
              ) : null}
            </div>
            {caseProjects.length > 0 ? (
              <nav className="case-pagination" aria-label="案件列表分页">
                <button
                  disabled={
                    caseNavigationLocked || paginatedCaseProjects.page <= 1
                  }
                  type="button"
                  onClick={() =>
                    setCaseProjectPage((current) =>
                      clampCaseProjectPage(current - 1, caseProjects.length),
                    )
                  }
                >
                  上一页
                </button>
                <span aria-live="polite">
                  第 {paginatedCaseProjects.page} / {paginatedCaseProjects.totalPages} 页
                </span>
                <button
                  disabled={
                    caseNavigationLocked ||
                    paginatedCaseProjects.page >= paginatedCaseProjects.totalPages
                  }
                  type="button"
                  onClick={() =>
                    setCaseProjectPage((current) =>
                      clampCaseProjectPage(current + 1, caseProjects.length),
                    )
                  }
                >
                  下一页
                </button>
              </nav>
            ) : null}
    </aside>
  );
}
