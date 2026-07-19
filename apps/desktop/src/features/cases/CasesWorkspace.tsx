import type { ReactNode } from "react";

export interface CasesWorkspaceProps {
  busy: boolean;
  children: ReactNode;
}

export function CasesWorkspace({ busy, children }: CasesWorkspaceProps) {
  return (
    <section
      className="case-layout"
      aria-busy={busy}
      aria-label="案件工作台 β"
    >
      {children}
    </section>
  );
}
