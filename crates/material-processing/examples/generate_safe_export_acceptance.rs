use material_processing::{
    approved_text_sha256, reconstruct_approved_text_docx, reconstruct_approved_text_markdown,
    reconstruct_approved_text_pdf, reconstruct_approved_text_txt,
    verify_approved_text_derived_bytes, verify_approved_text_pdf_bytes, ApprovedTextPage,
    SafeDerivedFormat, SafePdfExportLimits, SafePdfExportRequest,
};
use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: generate_safe_export_acceptance <output-directory>")?;
    fs::create_dir_all(&output)?;

    let pages = vec![
        ApprovedTextPage {
            page_number: 1,
            text: "民事起诉状（脱敏副本）\n原告：【当事人A】\n被告：【当事人B】\n请求依法判令履行合同义务。"
                .to_owned(),
        },
        ApprovedTextPage {
            page_number: 2,
            text: "事实与理由\n【当事人A】与【当事人B】于2025年签订合同。\n联系方式：【联系方式A】\n本页内容已经人工复核。"
                .to_owned(),
        },
    ];
    let request = SafePdfExportRequest {
        approved_text_sha256: approved_text_sha256(&pages)?,
        pages,
        forbidden_canaries: vec!["RAW_CASE_SECRET_CANARY".to_owned()],
    };
    let limits = SafePdfExportLimits::default();

    let pdf = reconstruct_approved_text_pdf(&request, limits)?;
    verify_approved_text_pdf_bytes(&pdf.bytes, &request, limits)?;
    fs::write(output.join("approved-redacted.pdf"), &pdf.bytes)?;

    let txt = reconstruct_approved_text_txt(&request, limits)?;
    verify_approved_text_derived_bytes(SafeDerivedFormat::Txt, &txt.bytes, &request, limits)?;
    fs::write(output.join("approved-redacted.txt"), &txt.bytes)?;

    let markdown = reconstruct_approved_text_markdown(&request, limits)?;
    verify_approved_text_derived_bytes(
        SafeDerivedFormat::Markdown,
        &markdown.bytes,
        &request,
        limits,
    )?;
    fs::write(output.join("approved-redacted.md"), &markdown.bytes)?;

    let docx = reconstruct_approved_text_docx(&request, limits)?;
    verify_approved_text_derived_bytes(SafeDerivedFormat::Docx, &docx.bytes, &request, limits)?;
    fs::write(output.join("approved-redacted.docx"), &docx.bytes)?;

    println!(
        "SAFE_EXPORT_ACCEPTANCE_OK formats=4 source_pages={} output_pdf_pages={} approved_text_sha256={}",
        request.pages.len(),
        pdf.output_page_count,
        request.approved_text_sha256
    );
    Ok(())
}
