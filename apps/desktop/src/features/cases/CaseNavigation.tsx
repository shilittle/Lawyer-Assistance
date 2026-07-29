import type { CaseRoutePage } from "../../app/routes";

// Kept beside the controlled component so the route labels and rendered
// navigation cannot drift during the phased migration.
// eslint-disable-next-line react-refresh/only-export-components
export const CASE_NAVIGATION_ITEMS = [
  { section: "overview", label: "概览" },
  { section: "materials", label: "材料与脱敏" },
  { section: "work", label: "案件工作" },
  { section: "outputs", label: "成果" },
] as const satisfies ReadonlyArray<{
  section: CaseRoutePage;
  label: string;
}>;

export type CaseSection = CaseRoutePage;

export interface CaseNavigationProps {
  section: CaseSection;
  onSectionChange: (section: CaseSection) => void;
}

export function CaseNavigation({
  section,
  onSectionChange,
}: CaseNavigationProps) {
  return (
    <nav className="workspace-subnav case-navigation" aria-label="案件工作台功能">
      {CASE_NAVIGATION_ITEMS.map((item) => (
        <button
          aria-current={section === item.section ? "page" : undefined}
          className={section === item.section ? "is-active" : ""}
          key={item.section}
          type="button"
          onClick={() => onSectionChange(item.section)}
        >
          {item.label}
        </button>
      ))}
    </nav>
  );
}
