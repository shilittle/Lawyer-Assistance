import type { ReactNode } from "react";

import {
  defaultRouteForArea,
  legacyViewFromRoute,
  type AppRoute,
} from "./routes";
import { VIEW_METADATA, VIEW_NAVIGATION, type ViewMode } from "./views";

export interface AppShellStatus {
  kind: "loading" | "ready" | "error";
  text: string;
}

interface AppShellCommonProps {
  children: ReactNode;
  status: AppShellStatus;
}

export interface TypedAppShellProps extends AppShellCommonProps {
  route: AppRoute;
  activeView?: never;
  onNavigate: (route: AppRoute) => void;
}

export interface LegacyAppShellProps extends AppShellCommonProps {
  activeView: ViewMode;
  route?: never;
  onNavigate: (view: ViewMode) => void;
}

export type AppShellProps = TypedAppShellProps | LegacyAppShellProps;

function isTypedAppShellProps(
  props: AppShellProps,
): props is TypedAppShellProps {
  return props.route !== undefined;
}

export function AppShell(props: AppShellProps) {
  const { children, status } = props;
  const activeView = isTypedAppShellProps(props)
    ? legacyViewFromRoute(props.route)
    : props.activeView;
  const activeMetadata = VIEW_METADATA[activeView];
  const activeArea = isTypedAppShellProps(props)
    ? props.route.area
    : activeMetadata.futureArea;

  const navigateToArea = (view: (typeof VIEW_NAVIGATION)[number]) => {
    if (isTypedAppShellProps(props)) {
      props.onNavigate(defaultRouteForArea(view.futureArea));
      return;
    }
    props.onNavigate(view.id);
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
