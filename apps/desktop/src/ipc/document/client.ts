import { invoke } from "@tauri-apps/api/core";
import type { DocumentTemplateMetadata,ExportDocumentRequest,GeneratedDocument,PreviewDocumentRequest } from "./types";
export async function listDocumentTemplates():Promise<DocumentTemplateMetadata[]>{ return (await invoke<{templates:DocumentTemplateMetadata[]}>("list_document_templates")).templates }
export async function previewDocument(request:PreviewDocumentRequest):Promise<GeneratedDocument>{ return (await invoke<{document:GeneratedDocument}>("preview_document",{request})).document }
export function exportDocument(request:ExportDocumentRequest):Promise<{recordId:string;exportPath:string;citationCount:number}>{ return invoke("export_document",{request}) }
