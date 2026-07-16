import { invoke } from "@tauri-apps/api/core"; import type { GraphData } from "./types";
export const getCaseGraph=(projectId:string):Promise<GraphData>=>invoke("get_case_graph",{request:{projectId}});
export const getLawGraph=(documentId:string):Promise<GraphData>=>invoke("get_law_graph",{request:{documentId}});
