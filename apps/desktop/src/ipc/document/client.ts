import { invoke } from "@tauri-apps/api/core";
import type { DocumentTemplateMetadata,ExportDocumentPdfRequest,ExportDocumentPdfResponse,PreviewDocumentRequest,PreviewDocumentResponse } from "./types";
export async function listDocumentTemplates():Promise<DocumentTemplateMetadata[]>{ return (await invoke<{templates:DocumentTemplateMetadata[]}>("list_document_templates")).templates }
export function previewDocument(request:PreviewDocumentRequest):Promise<PreviewDocumentResponse>{ return invoke("preview_document",{request}) }
export function exportDocumentPdf(request:ExportDocumentPdfRequest):Promise<ExportDocumentPdfResponse>{ return invoke("export_document_pdf",{request}) }
