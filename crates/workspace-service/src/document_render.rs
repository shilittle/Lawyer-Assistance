use crate::{Error, Result};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use serde::Serialize;
use std::{
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Default, Serialize)]
struct Span {
    text: String,
    bold: bool,
    italic: bool,
}
#[derive(Clone, Default, Serialize)]
struct Block {
    kind: String,
    level: u8,
    list_id: u32,
    list_number: Option<u64>,
    runs: Vec<Span>,
    rows: Vec<Vec<Vec<Span>>>,
}
#[derive(Serialize)]
struct Document {
    blocks: Vec<Block>,
}
pub fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn parse(markdown: &str) -> Document {
    let mut blocks = Vec::new();
    let mut current = Block {
        kind: "paragraph".into(),
        ..Default::default()
    };
    let mut table = false;
    let mut cell = Vec::new();
    let mut row = Vec::new();
    let mut rows = Vec::new();
    let (mut bold, mut italic, mut bullet) = (false, false, false);
    let mut lists = Vec::<(u32, Option<u64>)>::new();
    let mut items = Vec::<(u32, Option<u64>)>::new();
    let mut next_list_id = 0;
    fn flush(blocks: &mut Vec<Block>, current: &mut Block) {
        if !current.runs.is_empty() {
            blocks.push(std::mem::replace(
                current,
                Block {
                    kind: "paragraph".into(),
                    ..Default::default()
                },
            ));
        }
    }
    for event in Parser::new_ext(
        markdown,
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH,
    ) {
        match event {
            Event::Start(Tag::Heading { level, .. }) => {
                flush(&mut blocks, &mut current);
                current.kind = "heading".into();
                current.level = level as u8;
            }
            Event::Start(Tag::Paragraph) if !table => {
                flush(&mut blocks, &mut current);
                current.kind = if bullet { "bullet" } else { "paragraph" }.into();
                if let Some((id, number)) = items.last() {
                    current.list_id = *id;
                    current.list_number = *number;
                }
            }
            Event::Start(Tag::List(start)) => {
                next_list_id += 1;
                lists.push((next_list_id, start));
            }
            Event::End(TagEnd::List(_)) => {
                lists.pop();
            }
            Event::Start(Tag::Item) => {
                flush(&mut blocks, &mut current);
                bullet = true;
                current.kind = "bullet".into();
                if let Some((id, number)) = lists.last_mut() {
                    current.list_id = *id;
                    current.list_number = *number;
                    items.push((*id, *number));
                    if let Some(n) = number {
                        *n += 1;
                    }
                }
            }
            Event::End(TagEnd::Item) => {
                flush(&mut blocks, &mut current);
                items.pop();
                bullet = !items.is_empty();
            }
            Event::Start(Tag::Strong) => bold = true,
            Event::End(TagEnd::Strong) => bold = false,
            Event::Start(Tag::Emphasis) => italic = true,
            Event::End(TagEnd::Emphasis) => italic = false,
            Event::Start(Tag::Table(_)) => {
                flush(&mut blocks, &mut current);
                table = true;
                rows.clear();
            }
            Event::Start(Tag::TableHead | Tag::TableRow) => row.clear(),
            Event::Start(Tag::TableCell) => cell.clear(),
            Event::End(TagEnd::TableCell) => row.push(std::mem::take(&mut cell)),
            Event::End(TagEnd::TableHead | TagEnd::TableRow) => rows.push(std::mem::take(&mut row)),
            Event::End(TagEnd::Table) => {
                blocks.push(Block {
                    kind: "table".into(),
                    rows: std::mem::take(&mut rows),
                    ..Default::default()
                });
                table = false;
            }
            Event::Text(t) | Event::Code(t) | Event::Html(t) | Event::InlineHtml(t) => {
                let span = Span {
                    text: t.into_string(),
                    bold,
                    italic,
                };
                if table {
                    cell.push(span)
                } else {
                    current.runs.push(span)
                }
            }
            Event::SoftBreak | Event::HardBreak => {
                let span = Span {
                    text: "\n".into(),
                    bold,
                    italic,
                };
                if table {
                    cell.push(span)
                } else {
                    current.runs.push(span)
                }
            }
            Event::End(TagEnd::Paragraph | TagEnd::Heading(_) | TagEnd::CodeBlock) if !table => {
                flush(&mut blocks, &mut current);
            }
            Event::Rule => {
                flush(&mut blocks, &mut current);
            }
            _ => {}
        }
    }
    flush(&mut blocks, &mut current);
    Document { blocks }
}
fn text_runs(runs: &[Span]) -> String {
    runs.iter().map(|r| r.text.as_str()).collect()
}
fn html_runs(runs: &[Span]) -> String {
    runs.iter()
        .map(|r| {
            let mut s = escape(&r.text).replace('\n', "<br>");
            if r.bold {
                s = format!("<strong>{s}</strong>")
            }
            if r.italic {
                s = format!("<em>{s}</em>")
            }
            s
        })
        .collect()
}
pub fn rendered_html(markdown: &str) -> String {
    let mut html = String::new();
    for b in parse(markdown).blocks {
        match b.kind.as_str() {
            "heading" => {
                let level = b.level.clamp(1, 6);
                html.push_str(&format!("<h{level}>{}</h{level}>", html_runs(&b.runs)));
            }
            "table" => {
                html.push_str("<table><tbody>");
                for (i, row) in b.rows.iter().enumerate() {
                    html.push_str("<tr>");
                    for cell in row {
                        let tag = if i == 0 { "th" } else { "td" };
                        html.push_str(&format!("<{tag}>{}</{tag}>", html_runs(cell)));
                    }
                    html.push_str("</tr>");
                }
                html.push_str("</tbody></table>");
            }
            "bullet" => {
                if let Some(number) = b.list_number {
                    html.push_str(&format!(
                        "<ol start=\"{number}\"><li>{}</li></ol>",
                        html_runs(&b.runs)
                    ));
                } else {
                    html.push_str(&format!("<ul><li>{}</li></ul>", html_runs(&b.runs)));
                }
            }
            _ => html.push_str(&format!("<p>{}</p>", html_runs(&b.runs))),
        }
    }
    html
}
pub fn rendered_text(markdown: &str) -> String {
    let mut out = Vec::new();
    for b in parse(markdown).blocks {
        if b.kind == "table" {
            for row in b.rows {
                out.push(
                    row.iter()
                        .map(|c| text_runs(c))
                        .collect::<Vec<_>>()
                        .join("\t"),
                );
            }
        } else {
            out.push(format!(
                "{}{}",
                if b.kind == "bullet" {
                    b.list_number
                        .map(|n| format!("{n}. "))
                        .unwrap_or_else(|| "• ".into())
                } else {
                    String::new()
                },
                text_runs(&b.runs)
            ));
        }
    }
    out.join("\n\n") + "\n"
}
fn xml_runs(runs: &[Span]) -> String {
    runs.iter().map(|r|format!("<w:r><w:rPr>{}{}<w:rFonts w:ascii=\"Times New Roman\" w:eastAsia=\"宋体\"/></w:rPr>{}</w:r>",if r.bold{"<w:b/>"}else{""},if r.italic{"<w:i/>"}else{""},r.text.split('\n').map(|v|format!("<w:t xml:space=\"preserve\">{}</w:t>",escape(v))).collect::<Vec<_>>().join("<w:br/>"))).collect()
}
fn paragraph(runs: &[Span], level: u8, list_id: u32) -> String {
    format!(
        "<w:p><w:pPr>{}{}<w:spacing w:after=\"120\" w:line=\"300\"/><w:widowControl/></w:pPr>{}</w:p>",
        if level > 0 {
            format!("<w:pStyle w:val=\"Heading{}\"/>", level.min(3))
        } else {
            String::new()
        },
        if list_id>0 {
            format!("<w:numPr><w:ilvl w:val=\"0\"/><w:numId w:val=\"{list_id}\"/></w:numPr>")
        } else {
            String::new()
        },
        xml_runs(runs)
    )
}
fn docx(markdown: &str) -> Result<Vec<u8>> {
    let mut body = String::new();
    let parsed = parse(markdown);
    let mut list_definitions = std::collections::BTreeMap::new();
    for b in &parsed.blocks {
        if b.list_id > 0 {
            list_definitions.entry(b.list_id).or_insert(b.list_number);
        }
    }
    let mut numbering=String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><w:numbering xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">");
    for (id, start) in &list_definitions {
        numbering.push_str(&format!("<w:abstractNum w:abstractNumId=\"{id}\"><w:multiLevelType w:val=\"singleLevel\"/><w:lvl w:ilvl=\"0\"><w:start w:val=\"{}\"/><w:numFmt w:val=\"{}\"/><w:lvlText w:val=\"{}\"/><w:pPr><w:ind w:left=\"360\" w:hanging=\"240\"/></w:pPr></w:lvl></w:abstractNum>",start.unwrap_or(1),if start.is_some(){"decimal"}else{"bullet"},if start.is_some(){"%1."}else{"•"}));
    }
    for id in list_definitions.keys() {
        numbering.push_str(&format!(
            "<w:num w:numId=\"{id}\"><w:abstractNumId w:val=\"{id}\"/></w:num>"
        ));
    }
    numbering.push_str("</w:numbering>");
    for (index, b) in parsed.blocks.into_iter().enumerate() {
        if b.kind == "table" {
            let columns = b.rows.iter().map(Vec::len).max().unwrap_or(1);
            let weights = (0..columns)
                .map(|column| {
                    b.rows
                        .iter()
                        .filter_map(|row| row.get(column))
                        .map(|cell| {
                            cell.iter()
                                .map(|run| run.text.chars().count())
                                .sum::<usize>()
                        })
                        .max()
                        .unwrap_or(6)
                        .clamp(6, 30)
                })
                .collect::<Vec<_>>();
            let total = weights.iter().sum::<usize>();
            let widths = weights
                .iter()
                .map(|weight| 9072 * weight / total)
                .collect::<Vec<_>>();
            body.push_str("<w:tbl><w:tblPr><w:tblW w:w=\"9072\" w:type=\"dxa\"/><w:tblLayout w:type=\"fixed\"/><w:tblCellMar><w:left w:w=\"80\" w:type=\"dxa\"/><w:right w:w=\"80\" w:type=\"dxa\"/></w:tblCellMar><w:tblBorders><w:top w:val=\"single\" w:sz=\"4\"/><w:left w:val=\"single\" w:sz=\"4\"/><w:bottom w:val=\"single\" w:sz=\"4\"/><w:right w:val=\"single\" w:sz=\"4\"/><w:insideH w:val=\"single\" w:sz=\"4\"/><w:insideV w:val=\"single\" w:sz=\"4\"/></w:tblBorders></w:tblPr><w:tblGrid>");
            for width in &widths {
                body.push_str(&format!("<w:gridCol w:w=\"{width}\"/>"));
            }
            body.push_str("</w:tblGrid>");
            for (i, row) in b.rows.iter().enumerate() {
                body.push_str("<w:tr><w:trPr><w:cantSplit/>");
                if i == 0 {
                    body.push_str("<w:tblHeader/>");
                }
                body.push_str("</w:trPr>");
                for (column, c) in row.iter().enumerate() {
                    body.push_str(&format!(
                        "<w:tc><w:tcPr><w:tcW w:w=\"{}\" w:type=\"dxa\"/></w:tcPr>{}</w:tc>",
                        widths[column],
                        paragraph(c, 0, 0)
                    ));
                }
                body.push_str("</w:tr>");
            }
            body.push_str("</w:tbl>");
        } else {
            let p = paragraph(&b.runs, b.level, b.list_id);
            body.push_str(&if index == 0 && b.level == 1 {
                p.replace("Heading1", "Title")
            } else {
                p
            });
        }
    }
    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><w:body>{body}<w:sectPr><w:footerReference w:type=\"default\" r:id=\"footer1\"/><w:pgSz w:w=\"11906\" w:h=\"16838\"/><w:pgMar w:top=\"1361\" w:right=\"1417\" w:bottom=\"1361\" w:left=\"1417\"/></w:sectPr></w:body></w:document>"
    );
    let styles = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><w:styles xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:style w:type=\"paragraph\" w:styleId=\"Heading1\"><w:name w:val=\"heading 1\"/><w:pPr><w:keepNext/><w:outlineLvl w:val=\"0\"/></w:pPr><w:rPr><w:b/><w:sz w:val=\"36\"/></w:rPr></w:style><w:style w:type=\"paragraph\" w:styleId=\"Heading2\"><w:name w:val=\"heading 2\"/><w:pPr><w:keepNext/><w:outlineLvl w:val=\"1\"/></w:pPr><w:rPr><w:b/><w:sz w:val=\"28\"/></w:rPr></w:style><w:style w:type=\"paragraph\" w:styleId=\"Heading3\"><w:name w:val=\"heading 3\"/><w:pPr><w:keepNext/><w:outlineLvl w:val=\"2\"/></w:pPr><w:rPr><w:b/></w:rPr></w:style></w:styles>";
    let content = "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/><Override PartName=\"/word/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml\"/><Override PartName=\"/word/footer1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml\"/></Types>";
    let rels = "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>";
    let styles_rel = "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"styles\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/></Relationships>";
    let styles=styles.replace("<w:style w:type=\"paragraph\" w:styleId=\"Heading1\">", "<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii=\"Times New Roman\" w:eastAsia=\"宋体\"/><w:sz w:val=\"22\"/></w:rPr></w:rPrDefault></w:docDefaults><w:style w:type=\"paragraph\" w:styleId=\"Title\"><w:name w:val=\"Title\"/><w:pPr><w:jc w:val=\"center\"/><w:keepNext/></w:pPr><w:rPr><w:b/><w:sz w:val=\"36\"/></w:rPr></w:style><w:style w:type=\"paragraph\" w:styleId=\"Heading1\">");
    let content=content.replace("</Types>","<Override PartName=\"/word/numbering.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml\"/></Types>");
    let styles_rel=styles_rel.replace("</Relationships>","<Relationship Id=\"numbering\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering\" Target=\"numbering.xml\"/><Relationship Id=\"footer1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer\" Target=\"footer1.xml\"/></Relationships>");
    let footer = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><w:ftr xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr><w:r><w:fldChar w:fldCharType=\"begin\" w:dirty=\"true\"/></w:r><w:r><w:instrText xml:space=\"preserve\"> PAGE \\* MERGEFORMAT </w:instrText></w:r><w:r><w:fldChar w:fldCharType=\"separate\"/></w:r><w:r><w:t>1</w:t></w:r><w:r><w:fldChar w:fldCharType=\"end\"/></w:r></w:p></w:ftr>";
    let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, text) in [
        ("[Content_Types].xml", content.as_str()),
        ("_rels/.rels", rels),
        ("word/document.xml", &document),
        ("word/styles.xml", styles.as_str()),
        ("word/numbering.xml", numbering.as_str()),
        ("word/footer1.xml", footer),
        ("word/_rels/document.xml.rels", styles_rel.as_str()),
    ] {
        z.start_file(name, zip::write::SimpleFileOptions::default())
            .map_err(|_| Error::new("export_failed"))?;
        z.write_all(text.as_bytes())?;
    }
    Ok(z.finish()
        .map_err(|_| Error::new("export_failed"))?
        .into_inner())
}
pub fn runtime_tools() -> PathBuf {
    if let Some(p) = std::env::var_os("LAWYER_RUNTIME_TOOLS") {
        return PathBuf::from(p);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("tools");
            if p.is_dir() {
                return p;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../output/runtime-tools")
}
pub fn export_document(markdown: &str, format: &str, temp_root: &Path) -> Result<Vec<u8>> {
    if markdown.len() > 2 * 1024 * 1024 {
        return Err(Error::new("document_too_large"));
    }
    match format {
        "txt" => Ok(rendered_text(markdown).into_bytes()),
        "md" => Ok(markdown.as_bytes().to_vec()),
        "docx" => docx(markdown),
        "pdf" => {
            let tools = runtime_tools();
            let exe = tools.join("typst.exe");
            if !exe.is_file() {
                return Err(Error::new("pdf_runtime_missing"));
            }
            std::fs::create_dir_all(temp_root)?;
            let temp = tempfile::tempdir_in(temp_root)?;
            std::fs::write(
                temp.path().join("document.json"),
                serde_json::to_vec(&parse(markdown))?,
            )?;
            std::fs::write(
                temp.path().join("document.typ"),
                include_str!("document.typ"),
            )?;
            let mut command = Command::new(exe);
            command
                .arg("compile")
                .arg("--root")
                .arg(temp.path())
                .arg("--font-path")
                .arg(tools.join("fonts"))
                .arg("--ignore-system-fonts")
                .arg(temp.path().join("document.typ"))
                .arg(temp.path().join("document.pdf"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000);
            }
            let mut child = command
                .spawn()
                .map_err(|_| Error::new("pdf_runtime_failed"))?;
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if let Some(status) = child.try_wait()? {
                    if !status.success() {
                        return Err(Error::new("pdf_render_failed"));
                    }
                    break;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::new("pdf_render_timeout"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(std::fs::read(temp.path().join("document.pdf"))?)
        }
        _ => Err(Error::new("unsupported_export_format")),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn render_preserves_structure_and_escapes_html() {
        let md = "# 起诉状\n\n**事实**：价款126800元。\n\n| 项目 | 金额 |\n|---|---|\n| 欠款 | 126800 |\n\n<script>alert(1)</script>";
        let html = rendered_html(md);
        assert!(html.contains("<h1>起诉状</h1>"));
        assert!(html.contains("<strong>事实</strong>"));
        assert!(html.contains("<table>"));
        assert!(!html.contains("<script>"));
        let text = rendered_text(md);
        assert!(!text.contains("**事实**"));
        assert!(text.contains("项目\t金额"));
        let data = docx(md).unwrap();
        let mut z = zip::ZipArchive::new(Cursor::new(data)).unwrap();
        let mut xml = String::new();
        std::io::Read::read_to_string(&mut z.by_name("word/document.xml").unwrap(), &mut xml)
            .unwrap();
        assert!(xml.contains("<w:tbl>"));
        assert!(xml.contains("<w:b/>"));
        assert!(!xml.contains("**事实**"));
    }
    #[test]
    fn ordered_lists_preserve_numbers_and_docx_uses_numbering_properties() {
        let md = "# 清单\n\n3. 付款126800元\n4. 日期2026年8月11日\n\n- 附件\n";
        assert!(rendered_text(md).contains("3. 付款126800元"));
        assert!(rendered_text(md).contains("4. 日期2026年8月11日"));
        assert!(rendered_html(md).contains("<ol start=\"3\"><li>"));
        let mut z = zip::ZipArchive::new(Cursor::new(docx(md).unwrap())).unwrap();
        let mut xml = String::new();
        std::io::Read::read_to_string(&mut z.by_name("word/document.xml").unwrap(), &mut xml)
            .unwrap();
        assert!(xml.contains("<w:numPr>"));
        assert!(xml.contains("w:val=\"Title\""));
        let mut definitions = String::new();
        std::io::Read::read_to_string(
            &mut z.by_name("word/numbering.xml").unwrap(),
            &mut definitions,
        )
        .unwrap();
        assert!(definitions.contains("<w:start w:val=\"3\"/>"));
        assert!(definitions.contains("w:val=\"decimal\""));
    }

    #[test]
    fn docx_emits_keep_next_heading3_and_page_number_parts() {
        let md = "# 标题\n\n### 三级标题\n\n正文";
        let mut z = zip::ZipArchive::new(Cursor::new(docx(md).unwrap())).unwrap();

        let mut document = String::new();
        std::io::Read::read_to_string(&mut z.by_name("word/document.xml").unwrap(), &mut document)
            .unwrap();
        assert!(document.contains("w:val=\"Heading3\""));
        assert!(document.contains("<w:footerReference w:type=\"default\" r:id=\"footer1\"/>"));

        let mut styles = String::new();
        std::io::Read::read_to_string(&mut z.by_name("word/styles.xml").unwrap(), &mut styles)
            .unwrap();
        assert!(styles.contains(
            "<w:style w:type=\"paragraph\" w:styleId=\"Heading3\"><w:name w:val=\"heading 3\"/><w:pPr><w:keepNext/><w:outlineLvl w:val=\"2\"/></w:pPr>"
        ));

        let mut footer = String::new();
        std::io::Read::read_to_string(&mut z.by_name("word/footer1.xml").unwrap(), &mut footer)
            .unwrap();
        assert!(footer.contains("w:jc w:val=\"center\""));
        assert!(footer.contains("w:fldCharType=\"begin\""));
        assert!(footer.contains(" PAGE \\* MERGEFORMAT "));
        assert!(footer.contains("w:fldCharType=\"separate\""));
        assert!(footer.contains("w:fldCharType=\"end\""));

        let mut content_types = String::new();
        std::io::Read::read_to_string(
            &mut z.by_name("[Content_Types].xml").unwrap(),
            &mut content_types,
        )
        .unwrap();
        assert!(content_types.contains(
            "<Override PartName=\"/word/footer1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml\"/>"
        ));

        let mut relationships = String::new();
        std::io::Read::read_to_string(
            &mut z.by_name("word/_rels/document.xml.rels").unwrap(),
            &mut relationships,
        )
        .unwrap();
        assert!(relationships.contains(
            "<Relationship Id=\"footer1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer\" Target=\"footer1.xml\"/>"
        ));
    }
}
