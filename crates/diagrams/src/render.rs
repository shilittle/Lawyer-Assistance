//! Safe, deterministic SVG and self-contained HTML rendering.
//!
//! Every byte of CSS and JavaScript below is trusted, versioned application
//! code.  Diagram content is emitted only through context-specific escaping;
//! it is never interpreted as markup, style, script, or a network location.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::Value;

use crate::layout::{layout, Layout, LayoutNode, LayoutStrategy};
use crate::model::DiagramSpec;

const RENDERER_VERSION: &str = "1.0.0";

// These hashes are updated alongside the fixed constants after formatting.
const CSP_NONCE: &str = "la-diagrams-renderer-v1";
const FIXED_CSS: &str = ".legend-swatch.dashed{border-style:dashed}.node:focus-visible .node-card,.edge:focus-visible path{stroke:var(--focus);stroke-width:4}.advanced-hidden{display:none!important}.node.has-limitation .node-card{stroke:#b56a00;stroke-width:3}@media print{body,body.theme-dark,body.theme-auto{--bg:#fff;--panel:#fff;--ink:#111827;--muted:#4b5563;--line:#9ca3af;--accent:#245ec7;color-scheme:light}}";
const PRINT_PORTRAIT_CSS: &str = "@page{size:A4 portrait;margin:10mm}";

const TRUSTED_CSS: &str = r#":root{color-scheme:light;--bg:#f6f7fb;--panel:#fff;--ink:#182033;--muted:#647087;--line:#c8d0df;--accent:#245ec7;--focus:#ffb020;--danger:#b83a3a;--shadow:0 10px 30px rgba(26,39,72,.12);font-family:Inter,"Noto Sans SC","Microsoft YaHei",system-ui,sans-serif}*{box-sizing:border-box}html,body{height:100%;margin:0;background:var(--bg);color:var(--ink)}body.theme-dark{--bg:#111722;--panel:#1b2433;--ink:#eef3ff;--muted:#a8b3c7;--line:#445169;--accent:#82aefb;--focus:#ffd166;--danger:#ff8b8b;color-scheme:dark}@media(prefers-color-scheme:dark){body.theme-auto{--bg:#111722;--panel:#1b2433;--ink:#eef3ff;--muted:#a8b3c7;--line:#445169;--accent:#82aefb;--focus:#ffd166;--danger:#ff8b8b;color-scheme:dark}}button,input,select{font:inherit;color:inherit}button,select,input[type=search]{border:1px solid var(--line);border-radius:7px;background:var(--panel);padding:7px 10px}button{cursor:pointer}button:hover,button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid color-mix(in srgb,var(--focus) 55%,transparent);outline-offset:1px}.app-header{padding:18px 22px 12px;background:var(--panel);border-bottom:1px solid var(--line)}h1{font-size:20px;margin:0 0 5px}.summary{margin:0;color:var(--muted);white-space:pre-wrap}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:10px 14px;background:var(--panel);border-bottom:1px solid var(--line)}.toolbar label{display:flex;gap:6px;align-items:center;font-size:13px}.toolbar .spacer{flex:1}.workspace{height:calc(100% - 130px);min-height:460px;display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:0}.canvas-shell{position:relative;overflow:hidden;background:radial-gradient(circle at 1px 1px,var(--line) 1px,transparent 1.5px);background-size:22px 22px}.diagram-svg{width:100%;height:100%;display:block;touch-action:none;user-select:none}.sidebar{overflow:auto;background:var(--panel);border-left:1px solid var(--line);padding:18px}.sidebar h2{font-size:17px;margin:0 0 14px}.detail-row{margin:0 0 13px}.detail-label{display:block;color:var(--muted);font-size:12px;margin-bottom:3px}.detail-value{white-space:pre-wrap;overflow-wrap:anywhere}.source-list{display:grid;gap:8px}.source-button{text-align:left;width:100%;font-size:13px}.legend{position:absolute;left:14px;bottom:14px;max-width:min(620px,calc(100% - 28px));display:flex;flex-wrap:wrap;gap:7px 12px;padding:9px 12px;border:1px solid var(--line);border-radius:9px;background:color-mix(in srgb,var(--panel) 94%,transparent);box-shadow:var(--shadow);font-size:12px}.legend-item{display:inline-flex;align-items:center;gap:5px}.legend-swatch{width:15px;height:11px;border-radius:3px;border:2px solid var(--line);background:#e8eefc}.legend-line{width:24px;border-top:3px solid var(--muted)}.legend-line.weak{border-top-style:dotted}.legend-line.unknown{border-top-style:dashed}.lane-line{stroke:var(--line);stroke-width:2;stroke-dasharray:8 9}.lane-label{fill:var(--muted);font-size:12px}.group-box{fill:color-mix(in srgb,var(--accent) 5%,transparent);stroke:color-mix(in srgb,var(--accent) 45%,var(--line));stroke-width:1.5;stroke-dasharray:8 6}.group-label{fill:var(--muted);font-size:12px;font-weight:600}.edge{cursor:pointer}.edge path{fill:none;stroke:#6d7a91;stroke-width:2.2;marker-end:url(#arrow);vector-effect:non-scaling-stroke}.edge.symmetric path{marker-start:url(#arrow-start)}.edge.strength-conclusive path{stroke-width:4}.edge.strength-strong path{stroke-width:3}.edge.strength-moderate path{stroke-width:2.2}.edge.strength-weak path{stroke-width:1.8;stroke-dasharray:3 6}.edge.strength-unknown path{stroke-width:1.8;stroke-dasharray:9 6}.edge.relation-contradicts path,.edge.relation-conflicts_with path,.edge.relation-conflicts_in_time_with path{stroke:var(--danger)}.edge.relation-applies_before path,.edge.relation-superior_to path{stroke:var(--accent)}.edge text{fill:var(--muted);font-size:11px;paint-order:stroke;stroke:var(--panel);stroke-width:5px;stroke-linejoin:round}.edge.selected path{stroke:var(--focus);stroke-width:4}.node{cursor:pointer}.node .node-card{fill:var(--panel);stroke:#6d7a91;stroke-width:2;rx:11;filter:url(#soft-shadow);vector-effect:non-scaling-stroke}.node .importance-bar{fill:#96a2b8}.node.importance-critical .importance-bar{fill:#c13232}.node.importance-high .importance-bar{fill:#e49022}.node.importance-low .importance-bar{fill:#a9b1c0}.node.status-disputed .node-card,.node.status-contradicted .node-card{stroke:var(--danger);stroke-dasharray:7 4}.node.status-established .node-card,.node.status-effective .node-card,.node.status-completed .node-card{stroke:#26805c;stroke-width:3}.node.status-unknown .node-card,.node.status-uncertain .node-card{stroke-dasharray:3 5}.node.selected .node-card{stroke:var(--focus);stroke-width:4}.node text{fill:var(--ink);pointer-events:none}.node .node-label{font-size:14px;font-weight:650}.node .node-meta{font-size:11px;fill:var(--muted)}.node .type-icon{fill:color-mix(in srgb,var(--accent) 18%,var(--panel));stroke:var(--accent);stroke-width:1.6}.node .status-mark{fill:var(--panel);stroke:#6d7a91;stroke-width:2}.node.status-established .status-mark,.node.status-effective .status-mark{fill:#26805c;stroke:#26805c}.node.status-disputed .status-mark,.node.status-contradicted .status-mark{fill:#c13232;stroke:#c13232}.node.type-evidence .type-icon{fill:#e7f4ec;stroke:#287b52}.node.type-issue .type-icon{fill:#fff1cc;stroke:#ac6b00}.node.type-law .type-icon,.node.type-regulation .type-icon,.node.type-rule .type-icon{fill:#ece8ff;stroke:#654fc4}.node.type-party .type-icon{fill:#e5f0ff;stroke:#2c68ad}.node.type-amount .type-icon,.node.type-account .type-icon{fill:#e7f7f6;stroke:#18756f}.node.type-event .type-icon,.node.type-procedure .type-icon{fill:#fff0e6;stroke:#b75c22}.is-hidden{display:none!important}.is-dimmed{opacity:.16}.empty-note{position:absolute;top:16px;left:50%;transform:translateX(-50%);padding:8px 12px;border-radius:8px;background:var(--panel);box-shadow:var(--shadow);color:var(--muted)}.detail-record,.source-record{display:none}.print-note{display:none}@media(max-width:900px){.workspace{grid-template-columns:1fr}.sidebar{position:absolute;right:0;top:0;bottom:0;width:min(340px,92vw);box-shadow:var(--shadow);z-index:3}.sidebar[data-empty=true]{display:none}}@page{size:A4 landscape;margin:10mm}body.print-a4-portrait{@page{size:A4 portrait}}@media print{body{background:#fff}.toolbar,.sidebar,.legend{display:none!important}.app-header{border:0;padding:0 0 8mm}.workspace{height:auto;display:block}.canvas-shell{height:175mm;background:none}.diagram-svg{height:100%;width:100%}.print-note{display:block;font-size:10px;color:#555}}"#;

const TRUSTED_JS: &str = r#"(()=>{'use strict';const svg=document.querySelector('[data-testid="diagram-svg"]');const viewport=document.querySelector('[data-testid="viewport"]');const nodes=[...svg.querySelectorAll('.node')];const edges=[...svg.querySelectorAll('.edge')];const search=document.querySelector('[data-testid="diagram-search"]');const typeFilter=document.querySelector('[data-testid="type-filter"]');const statusFilter=document.querySelector('[data-testid="status-filter"]');const weakToggle=document.querySelector('[data-testid="weak-toggle"]');const lowToggle=document.querySelector('[data-testid="low-toggle"]');const emptyNote=document.querySelector('[data-testid="empty-note"]');const sidebar=document.querySelector('[data-testid="detail-sidebar"]');const detailTitle=document.querySelector('[data-testid="detail-title"]');const detailKind=document.querySelector('[data-testid="detail-kind"]');const detailStatus=document.querySelector('[data-testid="detail-status"]');const detailText=document.querySelector('[data-testid="detail-text"]');const detailTags=document.querySelector('[data-testid="detail-tags"]');const detailMetadata=document.querySelector('[data-testid="detail-metadata"]');const sourceList=document.querySelector('[data-testid="source-list"]');const records=[...document.querySelectorAll('.detail-record')];const sourceRecords=[...document.querySelectorAll('.source-record')];let selectedId='';let focusMode='';let scale=1;let tx=0;let ty=0;let dragging=false;let lastX=0;let lastY=0;const originalViewBox=svg.getAttribute('viewBox');const byId=(id)=>records.find((record)=>record.dataset.recordId===id);const sourceById=(id)=>sourceRecords.find((record)=>record.dataset.sourceId===id);const field=(record,name)=>{const item=[...record.children].find((child)=>child.dataset.field===name);return item?item.textContent:''};const setText=(element,value,fallback='—')=>{element.textContent=value||fallback};const applyTransform=()=>viewport.setAttribute('transform',`translate(${tx.toFixed(2)} ${ty.toFixed(2)}) scale(${scale.toFixed(4)})`);const createSourceButton=(id)=>{const source=sourceById(id);const button=document.createElement('button');button.type='button';button.className='source-button';button.dataset.sourceId=id;if(source){button.textContent=`${field(source,'title')} · ${field(source,'locator')}`;button.setAttribute('aria-label',`查看来源 ${field(source,'title')}`)}else{button.textContent=id}button.addEventListener('click',()=>showSource(id));return button};const showSource=(id)=>{const source=sourceById(id);if(!source)return;setText(detailTitle,field(source,'title'));setText(detailKind,field(source,'kind'));setText(detailStatus,field(source,'verification'));setText(detailText,field(source,'quote')||field(source,'locator'));setText(detailTags,field(source,'uri'));setText(detailMetadata,field(source,'extra'));sourceList.replaceChildren();sidebar.dataset.empty='false'};const selectRecord=(id)=>{selectedId=id;nodes.forEach((node)=>node.classList.toggle('selected',node.dataset.nodeId===id));edges.forEach((edge)=>edge.classList.toggle('selected',edge.dataset.edgeId===id));const record=byId(id);if(!record)return;setText(detailTitle,field(record,'label'));setText(detailKind,field(record,'kind'));setText(detailStatus,field(record,'status'));setText(detailText,field(record,'details'));setText(detailTags,field(record,'tags'));setText(detailMetadata,field(record,'metadata'));sourceList.replaceChildren(...field(record,'sources').split(',').filter(Boolean).map(createSourceButton));sidebar.dataset.empty='false';focusMode='';applyFilters()};const connected=(origin,direction)=>{const found=new Set([origin]);const queue=[origin];while(queue.length){const id=queue.shift();edges.forEach((edge)=>{let next='';if(direction==='upstream'&&edge.dataset.target===id)next=edge.dataset.source;if(direction==='downstream'&&edge.dataset.source===id)next=edge.dataset.target;if(direction==='both')next=edge.dataset.source===id?edge.dataset.target:(edge.dataset.target===id?edge.dataset.source:'');if(next&&!found.has(next)){found.add(next);queue.push(next)}})}return found};const applyFilters=()=>{const query=search.value.trim().toLocaleLowerCase();const allowed=focusMode&&selectedId?connected(selectedId,focusMode):null;let visibleCount=0;nodes.forEach((node)=>{const visible=(!query||node.dataset.search.includes(query))&&(!typeFilter.value||node.dataset.nodeType===typeFilter.value)&&(!statusFilter.value||node.dataset.status===statusFilter.value)&&(!lowToggle.checked||node.dataset.importance!=='low')&&(!allowed||allowed.has(node.dataset.nodeId));node.classList.toggle('is-hidden',!visible);if(visible)visibleCount+=1});edges.forEach((edge)=>{const source=nodes.find((node)=>node.dataset.nodeId===edge.dataset.source);const target=nodes.find((node)=>node.dataset.nodeId===edge.dataset.target);const hidden=!source||!target||source.classList.contains('is-hidden')||target.classList.contains('is-hidden')||(weakToggle.checked&&edge.dataset.strength==='weak');edge.classList.toggle('is-hidden',hidden)});emptyNote.hidden=visibleCount!==0};[search,typeFilter,statusFilter,weakToggle,lowToggle].forEach((control)=>control.addEventListener(control===search?'input':'change',()=>{focusMode='';applyFilters()}));nodes.forEach((node)=>{node.addEventListener('click',(event)=>{event.stopPropagation();selectRecord(node.dataset.nodeId)});node.addEventListener('keydown',(event)=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();selectRecord(node.dataset.nodeId)}})});edges.forEach((edge)=>edge.addEventListener('click',(event)=>{event.stopPropagation();selectRecord(edge.dataset.edgeId)}));document.querySelector('[data-testid="focus-upstream"]').addEventListener('click',()=>{if(selectedId){focusMode='upstream';applyFilters()}});document.querySelector('[data-testid="focus-downstream"]').addEventListener('click',()=>{if(selectedId){focusMode='downstream';applyFilters()}});document.querySelector('[data-testid="focus-clear"]').addEventListener('click',()=>{focusMode='';applyFilters()});const zoom=(factor)=>{scale=Math.min(4,Math.max(.25,scale*factor));applyTransform()};document.querySelector('[data-testid="zoom-in"]').addEventListener('click',()=>zoom(1.2));document.querySelector('[data-testid="zoom-out"]').addEventListener('click',()=>zoom(1/1.2));document.querySelector('[data-testid="fit-view"]').addEventListener('click',()=>{scale=1;tx=0;ty=0;svg.setAttribute('viewBox',originalViewBox);applyTransform()});document.querySelector('[data-testid="reset-view"]').addEventListener('click',()=>{search.value='';typeFilter.value='';statusFilter.value='';weakToggle.checked=weakToggle.dataset.initial==='true';lowToggle.checked=lowToggle.dataset.initial==='true';selectedId='';focusMode='';nodes.forEach((node)=>node.classList.remove('selected'));edges.forEach((edge)=>edge.classList.remove('selected'));scale=1;tx=0;ty=0;applyTransform();applyFilters();sidebar.dataset.empty='true'});document.querySelector('[data-testid="print-diagram"]').addEventListener('click',()=>window.print());svg.addEventListener('wheel',(event)=>{event.preventDefault();zoom(event.deltaY<0?1.12:1/1.12)},{passive:false});svg.addEventListener('pointerdown',(event)=>{if(event.target.closest('.node,.edge'))return;dragging=true;lastX=event.clientX;lastY=event.clientY;svg.setPointerCapture(event.pointerId)});svg.addEventListener('pointermove',(event)=>{if(!dragging)return;const box=svg.getBoundingClientRect();const view=svg.viewBox.baseVal;tx+=(event.clientX-lastX)*view.width/box.width/scale;ty+=(event.clientY-lastY)*view.height/box.height/scale;lastX=event.clientX;lastY=event.clientY;applyTransform()});const stopDrag=()=>{dragging=false};svg.addEventListener('pointerup',stopDrag);svg.addEventListener('pointercancel',stopDrag);svg.addEventListener('click',()=>{selectedId='';focusMode='';nodes.forEach((node)=>node.classList.remove('selected'));edges.forEach((edge)=>edge.classList.remove('selected'));applyFilters()});applyTransform();applyFilters()})();"#;

const TRUSTED_ENHANCEMENT_JS: &str = include_str!("runtime-enhancements.js");

/// Render a complete, offline HTML document with a strict CSP.
pub fn render_html(spec: &DiagramSpec) -> String {
    let value = serde_json::to_value(spec).unwrap_or(Value::Null);
    let scene = layout(spec);
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("法律与案件示意图");
    let summary = value.get("summary").and_then(Value::as_str).unwrap_or("");
    let theme = value
        .pointer("/display_options/theme")
        .and_then(Value::as_str)
        .unwrap_or("light");
    let show_legend = value
        .pointer("/display_options/show_legend")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let show_sources = value
        .pointer("/display_options/show_sources")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let hide_weak = value
        .pointer("/display_options/hide_weak_edges")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || scene.nodes.len() > 100;
    let max_initial_nodes = value
        .pointer("/layout_hints/max_initial_nodes")
        .and_then(Value::as_u64)
        .unwrap_or(100) as usize;
    let collapse_low = value
        .pointer("/display_options/collapse_low_importance")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || scene.nodes.len() > 100
        || scene.nodes.len() > max_initial_nodes;
    let portrait = value
        .pointer("/display_options/print_page_size")
        .and_then(Value::as_str)
        == Some("a4_portrait");
    let body_class = format!(
        "theme-{}{}",
        safe_token(theme),
        if portrait { " print-a4-portrait" } else { "" }
    );
    let mut html =
        String::with_capacity(32_000 + scene.nodes.len() * 1_500 + scene.edges.len() * 800);
    html.push_str("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    let _ = write!(html, "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'nonce-{CSP_NONCE}'; script-src 'nonce-{CSP_NONCE}'; img-src data:; font-src data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\">");
    html.push_str("<meta name=\"referrer\" content=\"no-referrer\"><meta name=\"color-scheme\" content=\"light dark\">");
    let _ = write!(html, "<meta name=\"generator\" content=\"Lawyer Assistance diagrams {RENDERER_VERSION}\"><title>");
    push_text(&mut html, title);
    let _ = write!(html, "</title><style nonce=\"{CSP_NONCE}\">");
    html.push_str(TRUSTED_CSS);
    html.push_str(FIXED_CSS);
    html.push_str("</style>");
    if portrait {
        let _ = write!(
            html,
            "<style nonce=\"{CSP_NONCE}\">{PRINT_PORTRAIT_CSS}</style>"
        );
    }
    html.push_str("</head><body class=\"");
    push_attr(&mut html, &body_class);
    html.push_str("\" data-renderer-version=\"");
    html.push_str(RENDERER_VERSION);
    html.push_str("\" data-layout-strategy=\"");
    html.push_str(scene.strategy.as_str());
    html.push_str("\"><header class=\"app-header\"><h1 data-testid=\"diagram-title\">");
    push_text(&mut html, title);
    html.push_str("</h1><p class=\"summary\" data-testid=\"diagram-summary\">");
    push_text(&mut html, summary);
    html.push_str("</p></header>");
    render_toolbar(&mut html, &scene, hide_weak, collapse_low);
    render_advanced_toolbar(&mut html, &scene, &value);
    if scene.nodes.len() > 100 {
        html.push_str("<aside class=\"app-header\" role=\"status\" data-testid=\"performance-warning\"><strong>性能提示：</strong>大型图已自动折叠低重要性节点并隐藏弱关联；可按主体、类型、状态搜索筛选，或聚焦所选节点的上下游后渐进展开。</aside>");
    }
    html.push_str(
        "<main class=\"workspace\"><section class=\"canvas-shell\" aria-label=\"示意图画布\">",
    );
    html.push_str(&render_svg_layout(&scene, &value));
    html.push_str(
        "<p class=\"empty-note\" data-testid=\"empty-note\" hidden>没有符合当前筛选条件的节点</p>",
    );
    if show_legend {
        render_legend(&mut html);
    }
    html.push_str("</section>");
    render_sidebar(&mut html);
    html.push_str("</main><p class=\"print-note\">本图由固定模板离线生成；来源 URI 仅展示，不会自动访问。</p>");
    render_detail_records(&mut html, &scene, &value);
    render_group_records(&mut html, &value);
    render_provenance_record(&mut html, &value, show_sources);
    let _ = write!(html, "<script nonce=\"{CSP_NONCE}\">");
    html.push_str(TRUSTED_JS);
    html.push_str(TRUSTED_ENHANCEMENT_JS);
    html.push_str("</script></body></html>");
    html
}

/// Render only the deterministic SVG scene.
pub fn render_svg(spec: &DiagramSpec) -> String {
    let value = serde_json::to_value(spec).unwrap_or(Value::Null);
    let scene = layout(spec);
    render_svg_layout(&scene, &value)
}

fn render_toolbar(html: &mut String, scene: &Layout, hide_weak: bool, collapse_low: bool) {
    let node_types: BTreeSet<_> = scene
        .nodes
        .iter()
        .map(|node| node.node_type.as_str())
        .collect();
    let statuses: BTreeSet<_> = scene
        .nodes
        .iter()
        .map(|node| node.status.as_str())
        .collect();
    html.push_str("<nav class=\"toolbar\" aria-label=\"图示工具栏\" data-testid=\"diagram-toolbar\"><label>搜索 <input type=\"search\" data-testid=\"diagram-search\" aria-label=\"搜索节点\" autocomplete=\"off\"></label><label>类型 <select data-testid=\"type-filter\" aria-label=\"按节点类型筛选\"><option value=\"\">全部</option>");
    for node_type in node_types {
        html.push_str("<option value=\"");
        push_attr(html, node_type);
        html.push_str("\">");
        push_text(html, type_name(node_type));
        html.push_str("</option>");
    }
    html.push_str("</select></label><label>状态 <select data-testid=\"status-filter\" aria-label=\"按状态筛选\"><option value=\"\">全部</option>");
    for status in statuses {
        html.push_str("<option value=\"");
        push_attr(html, status);
        html.push_str("\">");
        push_text(html, status_name(status));
        html.push_str("</option>");
    }
    html.push_str("</select></label><label><input type=\"checkbox\" data-testid=\"weak-toggle\" data-initial=\"");
    html.push_str(if hide_weak {
        "true\" checked"
    } else {
        "false\""
    });
    html.push_str("> 隐藏弱边</label><label><input type=\"checkbox\" data-testid=\"low-toggle\" data-initial=\"");
    html.push_str(if collapse_low {
        "true\" checked"
    } else {
        "false\""
    });
    html.push_str("> 折叠低重要度</label><span class=\"spacer\"></span><button type=\"button\" data-testid=\"focus-upstream\" aria-label=\"聚焦上游\">上游</button><button type=\"button\" data-testid=\"focus-downstream\" aria-label=\"聚焦下游\">下游</button><button type=\"button\" data-testid=\"focus-clear\">清除聚焦</button><button type=\"button\" data-testid=\"zoom-in\" aria-label=\"放大\">＋</button><button type=\"button\" data-testid=\"zoom-out\" aria-label=\"缩小\">－</button><button type=\"button\" data-testid=\"fit-view\">适应</button><button type=\"button\" data-testid=\"reset-view\">重置</button><button type=\"button\" data-testid=\"print-diagram\">打印</button></nav>");
}

fn render_advanced_toolbar(html: &mut String, scene: &Layout, value: &Value) {
    let issues: Vec<_> = scene
        .nodes
        .iter()
        .filter(|node| node.node_type == "issue")
        .collect();
    let parties: Vec<_> = scene
        .nodes
        .iter()
        .filter(|node| node.node_type == "party")
        .collect();
    html.push_str("<nav class=\"toolbar\" aria-label=\"争点、主体与分组工具\" data-testid=\"advanced-toolbar\">");
    if !issues.is_empty() {
        html.push_str("<label>争议点 <select data-testid=\"issue-filter\" aria-label=\"按争议点筛选\"><option value=\"\">全部</option>");
        for node in issues {
            html.push_str("<option value=\"");
            push_attr(html, &node.id);
            html.push_str("\">");
            push_text(html, node.short_label.as_deref().unwrap_or(&node.label));
            html.push_str("</option>");
        }
        html.push_str("</select></label>");
    }
    if !parties.is_empty() {
        html.push_str("<label>主体 <select data-testid=\"subject-filter\" aria-label=\"按主体筛选\"><option value=\"\">全部</option>");
        for node in parties {
            html.push_str("<option value=\"");
            push_attr(html, &node.id);
            html.push_str("\">");
            push_text(html, node.short_label.as_deref().unwrap_or(&node.label));
            html.push_str("</option>");
        }
        html.push_str("</select></label>");
    }
    for group in value
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = group.get("id").and_then(Value::as_str).unwrap_or("");
        let label = group.get("label").and_then(Value::as_str).unwrap_or(id);
        let collapsed = group
            .get("collapsed_by_default")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        html.push_str("<button type=\"button\" data-group-toggle=\"");
        push_attr(html, id);
        html.push_str("\" aria-pressed=\"");
        html.push_str(if collapsed { "true" } else { "false" });
        html.push_str("\">分组：");
        push_text(html, label);
        html.push_str("</button>");
    }
    html.push_str("<span class=\"spacer\"></span><button type=\"button\" data-testid=\"focus-both\">上下游</button><button type=\"button\" data-testid=\"progressive-expand\">渐进展开一层</button></nav>");
}

fn render_svg_layout(scene: &Layout, value: &Value) -> String {
    let mut svg = String::with_capacity(8_000 + scene.nodes.len() * 900 + scene.edges.len() * 500);
    let _ = write!(svg, "<svg class=\"diagram-svg\" data-testid=\"diagram-svg\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {:.1} {:.1}\" role=\"group\" aria-labelledby=\"svg-title svg-desc\" tabindex=\"0\"><title id=\"svg-title\">", scene.width, scene.height);
    push_text(
        &mut svg,
        value
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("法律与案件示意图"),
    );
    svg.push_str("</title><desc id=\"svg-desc\">可搜索、筛选并查看来源的法律与案件示意图</desc><defs><filter id=\"soft-shadow\" x=\"-20%\" y=\"-30%\" width=\"140%\" height=\"170%\"><feDropShadow dx=\"0\" dy=\"3\" stdDeviation=\"4\" flood-opacity=\".12\"/></filter><marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"7\" markerHeight=\"7\" orient=\"auto-start-reverse\"><path d=\"M 0 0 L 10 5 L 0 10 z\" fill=\"context-stroke\"/></marker><marker id=\"arrow-start\" viewBox=\"0 0 10 10\" refX=\"1\" refY=\"5\" markerWidth=\"7\" markerHeight=\"7\" orient=\"auto-start-reverse\"><path d=\"M 10 0 L 0 5 L 10 10 z\" fill=\"context-stroke\"/></marker></defs><g data-testid=\"viewport\" id=\"viewport\">");
    if scene.strategy == LayoutStrategy::CaseTimeline {
        render_timeline_lanes(&mut svg, scene);
    }
    render_groups(&mut svg, scene, value);
    for edge in &scene.edges {
        let symmetric = is_symmetric(&edge.relation);
        svg.push_str("<g class=\"edge strength-");
        push_attr(&mut svg, &safe_token(&edge.strength));
        svg.push_str(" relation-");
        push_attr(&mut svg, &safe_token(&edge.relation));
        if symmetric {
            svg.push_str(" symmetric");
        }
        svg.push_str("\" role=\"button\" tabindex=\"0\" data-edge-id=\"");
        push_attr(&mut svg, &edge.id);
        svg.push_str("\" data-source=\"");
        push_attr(&mut svg, &edge.source);
        svg.push_str("\" data-target=\"");
        push_attr(&mut svg, &edge.target);
        svg.push_str("\" data-strength=\"");
        push_attr(&mut svg, &edge.strength);
        svg.push_str("\" aria-label=\"");
        push_attr(
            &mut svg,
            &format!(
                "关系：{}",
                if edge.label.is_empty() {
                    relation_name(&edge.relation)
                } else {
                    &edge.label
                }
            ),
        );
        svg.push_str("\"><path d=\"");
        push_attr(&mut svg, &edge.path);
        svg.push_str("\"/>");
        let shown_label = if edge.label.is_empty() {
            relation_name(&edge.relation)
        } else {
            &edge.label
        };
        if !shown_label.is_empty() {
            let _ = write!(
                svg,
                "<text x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"middle\">",
                edge.label_x, edge.label_y
            );
            push_text(&mut svg, shown_label);
            svg.push_str("</text>");
        }
        svg.push_str("</g>");
    }
    for node in &scene.nodes {
        render_node(&mut svg, node);
    }
    svg.push_str("</g></svg>");
    svg
}

fn render_node(svg: &mut String, node: &LayoutNode) {
    let search_text = format!(
        "{} {} {} {}",
        node.label,
        node.details,
        node.tags.join(" "),
        node.metadata
            .values()
            .map(metadata_value)
            .collect::<Vec<_>>()
            .join(" ")
    )
    .to_lowercase();
    svg.push_str("<g class=\"node type-");
    push_attr(svg, &safe_token(&node.node_type));
    svg.push_str(" status-");
    push_attr(svg, &safe_token(&node.status));
    svg.push_str(" importance-");
    push_attr(svg, &safe_token(&node.importance));
    if node.metadata.contains_key("limitation_deadline") {
        svg.push_str(" has-limitation");
    }
    svg.push_str("\" role=\"button\" tabindex=\"0\" data-node-id=\"");
    push_attr(svg, &node.id);
    svg.push_str("\" data-node-type=\"");
    push_attr(svg, &node.node_type);
    svg.push_str("\" data-status=\"");
    push_attr(svg, &node.status);
    svg.push_str("\" data-importance=\"");
    push_attr(svg, &node.importance);
    svg.push_str("\" data-search=\"");
    push_attr(svg, &search_text);
    svg.push_str("\" aria-label=\"");
    push_attr(
        svg,
        &format!(
            "{}，{}，{}",
            node.label,
            type_name(&node.node_type),
            status_name(&node.status)
        ),
    );
    svg.push_str("\">");
    let _ = write!(svg, "<rect class=\"node-card\" x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\"/><rect class=\"importance-bar\" x=\"{:.1}\" y=\"{:.1}\" width=\"6\" height=\"{:.1}\" rx=\"3\"/>", node.x, node.y, node.width, node.height, node.x + 1.0, node.y + 8.0, node.height - 16.0);
    render_type_icon(svg, node);
    let status_x = node.x + node.width - 17.0;
    let status_y = node.y + 17.0;
    let _ = write!(
        svg,
        "<circle class=\"status-mark\" cx=\"{status_x:.1}\" cy=\"{status_y:.1}\" r=\"5.5\"/>"
    );
    let shown = node.short_label.as_deref().unwrap_or(&node.label);
    let lines = wrap_label(shown, ((node.width - 66.0) / 14.0) as usize, 3);
    let text_x = node.x + 50.0;
    let text_y = node.y + 26.0;
    let _ = write!(
        svg,
        "<text class=\"node-label\" x=\"{text_x:.1}\" y=\"{text_y:.1}\">"
    );
    for (index, line) in lines.iter().enumerate() {
        let _ = write!(
            svg,
            "<tspan x=\"{text_x:.1}\" dy=\"{}\">",
            if index == 0 { "0" } else { "18" }
        );
        push_text(svg, line);
        svg.push_str("</tspan>");
    }
    svg.push_str("</text>");
    let meta_y = node.y + node.height - 11.0;
    let _ = write!(
        svg,
        "<text class=\"node-meta\" x=\"{text_x:.1}\" y=\"{meta_y:.1}\">"
    );
    let timing_note = node
        .metadata
        .get("limitation_deadline")
        .and_then(Value::as_str)
        .map(|deadline| format!(" · 时效 {}", deadline.chars().take(16).collect::<String>()))
        .or_else(|| {
            node.metadata
                .get("date_precision")
                .and_then(Value::as_str)
                .filter(|precision| *precision != "day")
                .map(|precision| format!(" · 日期精度 {precision}"))
        })
        .unwrap_or_default();
    push_text(
        svg,
        &format!(
            "{} · {}{}",
            type_name(&node.node_type),
            status_name(&node.status),
            timing_note
        ),
    );
    svg.push_str("</text></g>");
}

fn render_type_icon(svg: &mut String, node: &LayoutNode) {
    let x = node.x + 25.0;
    let y = node.y + 28.0;
    match node.node_type.as_str() {
        "party" => {
            let _ = write!(svg, "<g class=\"type-icon\"><circle cx=\"{x:.1}\" cy=\"{:.1}\" r=\"7\"/><path d=\"M {:.1} {:.1} a 12 10 0 0 1 24 0\" fill=\"none\"/></g>", y - 8.0, x - 12.0, y + 13.0);
        }
        "evidence" | "law" | "regulation" | "rule" | "judicial_interpretation" => {
            let _ = write!(svg, "<path class=\"type-icon\" d=\"M {:.1} {:.1} h 18 l 6 6 v 24 h -24 z M {:.1} {:.1} h 6 v 6\"/>", x - 12.0, y - 15.0, x + 6.0, y - 15.0);
        }
        "amount" | "account" => {
            let _ = write!(svg, "<circle class=\"type-icon\" cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"15\"/><text x=\"{x:.1}\" y=\"{:.1}\" text-anchor=\"middle\" font-size=\"15\">¥</text>", y + 5.0);
        }
        "event" | "procedure" => {
            let _ = write!(svg, "<rect class=\"type-icon\" x=\"{:.1}\" y=\"{:.1}\" width=\"28\" height=\"25\" rx=\"3\"/><path d=\"M {:.1} {:.1} h 28 M {:.1} {:.1} v -7 M {:.1} {:.1} v -7\" fill=\"none\" stroke=\"currentColor\"/>", x - 14.0, y - 10.0, x - 14.0, y - 3.0, x - 7.0, y - 7.0, x + 7.0, y - 7.0);
        }
        "issue" => {
            let _ = write!(svg, "<path class=\"type-icon\" d=\"M {x:.1} {:.1} l 16 16 l -16 16 l -16 -16 z\"/><text x=\"{x:.1}\" y=\"{:.1}\" text-anchor=\"middle\" font-size=\"17\">?</text>", y - 16.0, y + 6.0);
        }
        _ => {
            let _ = write!(svg, "<circle class=\"type-icon\" cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"15\"/><circle cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"4\" fill=\"currentColor\"/>");
        }
    }
}

fn render_timeline_lanes(svg: &mut String, scene: &Layout) {
    let lanes: BTreeSet<_> = scene.nodes.iter().map(|node| node.lane).collect();
    for lane in lanes {
        let nodes: Vec<_> = scene
            .nodes
            .iter()
            .filter(|node| node.lane == lane)
            .collect();
        if nodes.is_empty() {
            continue;
        }
        let y = nodes.iter().map(|node| node.center_y()).sum::<f64>() / nodes.len() as f64;
        let _ = write!(svg, "<line class=\"lane-line\" x1=\"42\" y1=\"{y:.1}\" x2=\"{:.1}\" y2=\"{y:.1}\"/><text class=\"lane-label\" x=\"44\" y=\"{:.1}\">轨道 {}</text>", scene.width - 42.0, y - 12.0, lane + 1);
    }
}

fn render_groups(svg: &mut String, scene: &Layout, value: &Value) {
    let positions: BTreeMap<_, _> = scene
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    let groups = value.get("groups").and_then(Value::as_array);
    for group in groups.into_iter().flatten() {
        let id = group.get("id").and_then(Value::as_str).unwrap_or("");
        let label = group.get("label").and_then(Value::as_str).unwrap_or("");
        let member_ids = group.get("node_ids").and_then(Value::as_array);
        let members: Vec<_> = member_ids
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter_map(|id| positions.get(id).copied())
            .collect();
        if members.is_empty() {
            continue;
        }
        let min_x = members
            .iter()
            .map(|node| node.x)
            .fold(f64::INFINITY, f64::min)
            - 18.0;
        let min_y = members
            .iter()
            .map(|node| node.y)
            .fold(f64::INFINITY, f64::min)
            - 30.0;
        let max_x = members
            .iter()
            .map(|node| node.x + node.width)
            .fold(0.0, f64::max)
            + 18.0;
        let max_y = members
            .iter()
            .map(|node| node.y + node.height)
            .fold(0.0, f64::max)
            + 18.0;
        svg.push_str("<g data-group-id=\"");
        push_attr(svg, id);
        svg.push_str("\"><rect class=\"group-box\" x=\"");
        let _ = write!(svg, "{min_x:.1}\" y=\"{min_y:.1}\" width=\"{:.1}\" height=\"{:.1}\" rx=\"14\"/><text class=\"group-label\" x=\"{:.1}\" y=\"{:.1}\">", max_x - min_x, max_y - min_y, min_x + 10.0, min_y + 18.0);
        push_text(svg, label);
        svg.push_str("</text></g>");
    }
}

fn render_legend(html: &mut String) {
    html.push_str("<aside class=\"legend\" data-testid=\"diagram-legend\" aria-label=\"图例\"><span class=\"legend-item\"><span class=\"legend-swatch\"></span>节点类型由图标与底色区分</span><span class=\"legend-item\"><span class=\"legend-swatch dashed\"></span>争议/不确定状态</span><span class=\"legend-item\"><span class=\"legend-line\"></span>强/中等关系</span><span class=\"legend-item\"><span class=\"legend-line weak\"></span>弱关系</span><span class=\"legend-item\"><span class=\"legend-line unknown\"></span>未知强度</span></aside>");
}

fn render_sidebar(html: &mut String) {
    html.push_str("<aside class=\"sidebar\" data-testid=\"detail-sidebar\" data-empty=\"true\" aria-label=\"详情与来源\"><h2 data-testid=\"detail-title\">选择节点或关系</h2><p class=\"detail-row\"><span class=\"detail-label\">类型</span><span class=\"detail-value\" data-testid=\"detail-kind\">—</span></p><p class=\"detail-row\"><span class=\"detail-label\">状态/强度</span><span class=\"detail-value\" data-testid=\"detail-status\">—</span></p><p class=\"detail-row\"><span class=\"detail-label\">详情</span><span class=\"detail-value\" data-testid=\"detail-text\">—</span></p><p class=\"detail-row\"><span class=\"detail-label\">标签/URI</span><span class=\"detail-value\" data-testid=\"detail-tags\">—</span></p><p class=\"detail-row\"><span class=\"detail-label\">元数据</span><span class=\"detail-value\" data-testid=\"detail-metadata\">—</span></p><div class=\"detail-row\"><span class=\"detail-label\">来源</span><div class=\"source-list\" data-testid=\"source-list\"></div></div></aside>");
}

fn render_detail_records(html: &mut String, scene: &Layout, value: &Value) {
    let show_sources = value
        .pointer("/display_options/show_sources")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    html.push_str("<section aria-hidden=\"true\">");
    for node in &scene.nodes {
        let source_refs: &[String] = if show_sources { &node.source_refs } else { &[] };
        detail_record(
            html,
            &node.id,
            &node.label,
            type_name(&node.node_type),
            status_name(&node.status),
            &node.details,
            &node.tags.join("、"),
            &metadata_map(&node.metadata),
            source_refs,
        );
    }
    for edge in &scene.edges {
        let source_refs: &[String] = if show_sources { &edge.source_refs } else { &[] };
        let label = if edge.label.is_empty() {
            relation_name(&edge.relation)
        } else {
            &edge.label
        };
        detail_record(
            html,
            &edge.id,
            label,
            relation_name(&edge.relation),
            strength_name(&edge.strength),
            "",
            "",
            &metadata_map(&edge.metadata),
            source_refs,
        );
    }
    for source in value
        .get("sources")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|_| show_sources)
    {
        html.push_str("<div class=\"source-record\" data-source-id=\"");
        push_attr(html, source.get("id").and_then(Value::as_str).unwrap_or(""));
        html.push_str("\">");
        hidden_field(
            html,
            "title",
            source.get("title").and_then(Value::as_str).unwrap_or(""),
        );
        hidden_field(
            html,
            "kind",
            source.get("kind").and_then(Value::as_str).unwrap_or(""),
        );
        hidden_field(
            html,
            "verification",
            source
                .get("verification_status")
                .and_then(Value::as_str)
                .unwrap_or(""),
        );
        hidden_field(
            html,
            "locator",
            source.get("locator").and_then(Value::as_str).unwrap_or(""),
        );
        hidden_field(
            html,
            "quote",
            source.get("quote").and_then(Value::as_str).unwrap_or(""),
        );
        hidden_field(
            html,
            "uri",
            safe_display_uri(source.get("uri").and_then(Value::as_str)).unwrap_or(""),
        );
        let extra = source
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .filter(|(key, value)| {
                        ![
                            "id",
                            "title",
                            "kind",
                            "verification_status",
                            "locator",
                            "quote",
                            "uri",
                        ]
                        .contains(&key.as_str())
                            && !value.is_null()
                    })
                    .map(|(key, value)| format!("{key}: {}", metadata_value(value)))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        hidden_field(html, "extra", &extra);
        html.push_str("</div>");
    }
    html.push_str("</section>");
}

#[allow(clippy::too_many_arguments)]
fn detail_record(
    html: &mut String,
    id: &str,
    label: &str,
    kind: &str,
    status: &str,
    details: &str,
    tags: &str,
    metadata: &str,
    sources: &[String],
) {
    html.push_str("<div class=\"detail-record\" data-record-id=\"");
    push_attr(html, id);
    html.push_str("\">");
    hidden_field(html, "label", label);
    hidden_field(html, "kind", kind);
    hidden_field(html, "status", status);
    hidden_field(html, "details", details);
    hidden_field(html, "tags", tags);
    hidden_field(html, "metadata", metadata);
    hidden_field(html, "sources", &sources.join(","));
    html.push_str("</div>");
}

fn render_group_records(html: &mut String, value: &Value) {
    for group in value
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        html.push_str("<div class=\"group-record\" hidden data-group-id=\"");
        push_attr(html, group.get("id").and_then(Value::as_str).unwrap_or(""));
        html.push_str("\" data-node-ids=\"");
        let node_ids = group
            .get("node_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(",");
        push_attr(html, &node_ids);
        html.push_str("\" data-collapsed=\"");
        html.push_str(
            if group
                .get("collapsed_by_default")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                "true"
            } else {
                "false"
            },
        );
        html.push_str("\"></div>");
    }
}

fn render_provenance_record(html: &mut String, value: &Value, show_sources: bool) {
    let Some(provenance) = value.get("provenance") else {
        return;
    };
    let mut provenance = provenance.clone();
    if !show_sources {
        if let Some(object) = provenance.as_object_mut() {
            object.insert("source_file_ids".to_owned(), Value::Array(Vec::new()));
        }
    }
    let serialized = serde_json::to_string(&provenance).unwrap_or_default();
    html.push_str(
        "<section class=\"provenance-record\" hidden data-testid=\"diagram-provenance\">",
    );
    hidden_field(html, "json", &serialized);
    html.push_str("</section>");
}

fn hidden_field(html: &mut String, name: &str, value: &str) {
    html.push_str("<span data-field=\"");
    push_attr(html, name);
    html.push_str("\">");
    push_text(html, value);
    html.push_str("</span>");
}

fn metadata_map(metadata: &BTreeMap<String, Value>) -> String {
    metadata
        .iter()
        .map(|(key, value)| format!("{key}: {}", metadata_value(value)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn metadata_value(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => values
            .iter()
            .map(metadata_value)
            .collect::<Vec<_>>()
            .join("、"),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| format!("{key}={}", metadata_value(value)))
            .collect::<Vec<_>>()
            .join("；"),
    }
}

fn wrap_label(value: &str, max_units: usize, max_lines: usize) -> Vec<String> {
    let max_units = max_units.max(6);
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut units = 0usize;
    for ch in value.chars() {
        let width = if ch.is_ascii() { 1 } else { 2 };
        if units + width > max_units * 2 && !current.is_empty() {
            lines.push(current);
            current = String::new();
            units = 0;
            if lines.len() == max_lines - 1 {
                break;
            }
        }
        current.push(ch);
        units += width;
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    if value.chars().count() > lines.iter().map(|line| line.chars().count()).sum::<usize>() {
        if let Some(last) = lines.last_mut() {
            last.push('…');
        }
    }
    lines
}

fn safe_display_uri(uri: Option<&str>) -> Option<&str> {
    let uri = uri?;
    if uri.chars().any(|ch| ch.is_control()) {
        return None;
    }
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("https://")
        || lower.starts_with("http://")
        || lower.starts_with("lawyer-assistance:")
    {
        Some(uri)
    } else {
        None
    }
}

fn is_symmetric(relation: &str) -> bool {
    matches!(
        relation,
        "same_event_as"
            | "conflicts_in_time_with"
            | "contracts_with"
            | "related_party_of"
            | "conflicts_with"
    )
}

fn type_name(value: &str) -> &'static str {
    match value {
        "party" => "主体",
        "account" => "账户",
        "event" => "事件",
        "legal_relationship" => "法律关系",
        "fact" => "事实",
        "issue" => "争议点",
        "evidence" => "证据",
        "rule" => "规则",
        "claim" => "请求",
        "defense" => "抗辩",
        "amount" => "金额",
        "procedure" => "程序",
        "law" => "法律",
        "regulation" => "行政法规",
        "supervisory_regulation" => "监察法规",
        "judicial_interpretation" => "司法解释",
        "department_rule" => "部门规章",
        "local_regulation" => "地方性法规",
        "local_government_rule" => "地方政府规章",
        "normative_document" => "规范性文件",
        "guiding_case" => "指导性案例",
        "legal_principle" => "法律原则",
        "element" => "构成要件",
        "legal_consequence" => "法律后果",
        "exception_rule" => "例外规则",
        "application_conclusion" => "适用结论",
        "missing_information" => "缺失信息",
        _ => "节点",
    }
}

fn status_name(value: &str) -> &'static str {
    match value {
        "alleged" => "主张中",
        "admitted" => "已自认",
        "supported" => "有证据支持",
        "disputed" => "有争议",
        "contradicted" => "相矛盾",
        "established" => "当前材料确认",
        "unsupported" => "无支持",
        "unknown" => "未知",
        "active" => "有效/进行中",
        "inactive" => "非活动",
        "pending" => "待处理",
        "completed" => "已完成",
        "effective" => "现行有效",
        "repealed" => "已废止",
        "expired" => "已失效",
        "not_yet_effective" => "尚未生效",
        "uncertain" => "不确定",
        "not_applicable" => "不适用",
        _ => "未知",
    }
}

fn strength_name(value: &str) -> &'static str {
    match value {
        "conclusive" => "决定性",
        "strong" => "强",
        "moderate" => "中等",
        "weak" => "弱",
        _ => "未知",
    }
}

fn relation_name(value: &str) -> &'static str {
    match value {
        "supports" => "支持",
        "contradicts" => "反驳",
        "proves" => "证明",
        "alleges" => "主张",
        "admits" => "自认",
        "disputes" => "争议",
        "raises" => "提出争点",
        "applies_to" => "适用于",
        "requires" => "要求",
        "leads_to" => "导致",
        "based_on" => "基于",
        "involves" => "涉及",
        "occurred_before" => "先于",
        "occurred_after" => "后于",
        "same_event_as" => "同一事件",
        "conflicts_in_time_with" => "时间冲突",
        "paid_to" => "支付给",
        "transferred_to" => "转给",
        "owes" => "负有债务",
        "guarantees" => "担保",
        "controls" => "控制",
        "owns" => "持有",
        "represents" => "代理",
        "employs" => "雇佣",
        "contracts_with" => "订约",
        "related_party_of" => "关联主体",
        "superior_to" => "效力高于",
        "authorized_by" => "依据授权",
        "implements" => "实施细化",
        "references" => "引用",
        "supplements" => "补充",
        "interprets" => "解释",
        "exception_to" => "例外",
        "limits" => "限制",
        "conflicts_with" => "规范冲突",
        "repeals" => "废止",
        "amends" => "修改",
        "replaces" => "替代",
        "applies_before" => "优先适用",
        "contains" => "包含",
        "belongs_to" => "属于",
        "related_to" => "关联",
        _ => "关系",
    }
}

fn safe_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn push_text(output: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            ch if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') => output.push('\u{fffd}'),
            _ => output.push(ch),
        }
    }
}

fn push_attr(output: &mut String, value: &str) {
    push_text(output, value);
}
