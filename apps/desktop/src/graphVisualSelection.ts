import type { Core } from "cytoscape";

import type { GraphSelection } from "./ipc/graph/types";

export function syncGraphVisualSelection(
  cy: Core | null,
  selection: GraphSelection | null,
) {
  if (!cy) return;
  cy.elements().unselect();
  if (!selection) return;
  const id =
    selection.kind === "node"
      ? `node:${selection.node.id}`
      : `edge:${selection.edge.id}`;
  cy.getElementById(id).select();
}
