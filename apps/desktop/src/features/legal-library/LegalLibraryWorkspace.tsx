import type { ReactNode } from "react";

export function LegalLibraryWorkspace({ children }: { children: ReactNode }) {
  return (
    <section className="legal-library-workspace" aria-label="法律库工作区">
      {children}
    </section>
  );
}
