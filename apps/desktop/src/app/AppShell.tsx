import type { ReactNode } from "react";

import {
  defaultRouteForArea,
  legacyViewFromRoute,
  type AppRoute,
} from "./routes";
import { VIEW_METADATA, VIEW_NAVIGATION } from "./views";

export interface AppShellStatus {
  kind: "loading" | "ready" | "error";
  text: string;
}

export interface AppShellProps {
  children: ReactNode;
  status: AppShellStatus;
  route: AppRoute;
  onNavigate: (route: AppRoute) => void;
}

export function AppShell({
  children,
  status,
  route,
  onNavigate,
}: AppShellProps) {
  const activeView = legacyViewFromRoute(route);
  const activeMetadata = VIEW_METADATA[activeView];
  const activeArea = route.area;

  const navigateToArea = (view: (typeof VIEW_NAVIGATION)[number]) => {
    onNavigate(defaultRouteForArea(view.futureArea));
  };

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
                  activeArea === view.futureArea ? "page" : undefined
                }
                className={
                  activeArea === view.futureArea ? "is-active" : ""
                }
                key={view.id}
                type="button"
                onClick={() => navigateToArea(view)}
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
