#set page(paper: "a4", margin: (x: 25mm, y: 24mm), numbering: "1", number-align: center)
#set text(font: "Source Han Serif SC", size: 11pt, lang: "zh")
#set par(justify: true, leading: 0.7em)
#set heading(numbering: none)
#show heading.where(level: 1): it => align(center, it)
#let data = json("document.json")
#let spans(runs) = {
  for r in runs {
    let t = text(r.text)
    if r.bold { t = strong(t) }
    if r.italic { t = emph(t) }
    t
  }
}
#for block in data.blocks {
  if block.kind == "heading" {
    heading(level: block.level, spans(block.runs))
  } else if block.kind == "table" {
    if block.rows.len() > 0 {
      let columns = block.rows.first().len()
      let rows = block.rows.map(row => row.map(cell => spans(cell)))
      table(columns: columns, inset: 5pt, stroke: 0.4pt + gray,
        table.header(..rows.first()), ..rows.slice(1).flatten())
    }
  } else if block.kind == "bullet" {
    if block.list_number == none { list(spans(block.runs)) }
    else { enum(start: block.list_number, spans(block.runs)) }
    parbreak()
  } else {
    spans(block.runs)
    parbreak()
  }
}
