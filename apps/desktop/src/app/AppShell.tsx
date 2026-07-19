import type { ReactNode } from "react";

import { VIEW_METADATA, VIEW_NAVIGATION, type ViewMode } from "./views";

export interface AppShellStatus {
  kind: "loading" | "ready" | "error";
  text: string;
}

export interface AppShellProps {
  activeView: ViewMode;
  children: ReactNode;
  status: AppShellStatus;
  onNavigate: (view: ViewMode) => void;
}

export function AppShell({
  activeView,
  children,
  status,
  onNavigate,
}: AppShellProps) {
  const activeMetadata = VIEW_METADATA[activeView];

  return (
    <main className="app-shell">
      <header className="top-bar">
        <div>
          <p className="eyebrow">{activeMetadata.eyebrow}</p>
          <h1>{activeMetadata.title}</h1>
        </div>
        <div className="top-actions">
          <nav className="view-tabs" aria-label="主视图">
            {VIEW_NAVIGATION.map((view) => (
              <button
                aria-current={
                  activeMetadata.futureArea === view.futureArea
                    ? "page"
                    : undefined
                }
                className={
                  activeMetadata.futureArea === view.futureArea ? "is-active" : ""
                }
                key={view.id}
                type="button"
                onClick={() => onNavigate(view.id)}
              >
                {view.navigationLabel}
              </button>
            ))}
          </nav>
          <div className="health-chip" role="status" aria-live="polite">
            <span className={`status-dot status-dot--${status.kind}`} />
            <span>{status.text}</span>
          </div>
        </div>
      </header>

      {children}
    </main>
  );
}
