import fs from 'node:fs';
import path from 'node:path';
import {root,startServer,check} from './ai_test_client.mjs';
const output=path.join(root,'output/ai-upgrade-exports');fs.mkdirSync(output,{recursive:true});
const session=await startServer(path.join(root,'output/ai-upgrade-live/workspace'));
const client=session.client;const report={exports:[],started_at:new Date().toISOString()};
try{
 const runs=(await client.request('/api/v1/ai/runs')).runs.filter(r=>r.kind==='writing'&&r.status==='completed'&&!r.parent_id);
 check(runs.length>=3,'writing_runs_missing');
 const before=await client.request('/api/v1/ai/usage');
 const text='# 排版验收文书\n\n本附件为合成排版验收材料。合同价款 **126800.00 元**，已付 30000.00 元，余款 96800.00 元；约定日期为 2026-04-10。\n\n## 请求事项\n\n1. 支付剩余价款。\n2. 核对交付凭证。\n3. 保留尚待补充的事实。\n\n## 证据目录\n\n| 序号 | 证据名称 | 日期与证明事项 |\n| --- | --- | --- |\n'+Array.from({length:80},(_,i)=>`| ${i+1} | 合成证据 ${i+1} | 2026-04-10：逐项核对交付、验收与付款记录，确认跨页表格没有遮挡、遗漏或溢出。 |`).join('\n')+'\n\n## 补充说明\n\n- 此处为普通项目列表。\n- 以下内容必须保持为文字：<script>alert(1)</script>。\n\n文书结束。';
 const edited=await client.request(`/api/v1/ai/runs/${runs[0].id}/content`,'PUT',{content:text});
 check(edited.id!==runs[0].id,'edit_overwrote_history');
 for(const [index,r] of [...runs.slice(0,3),edited].entries()){
  const current=await client.request(`/api/v1/ai/runs/${r.id}`);const name=index===3?'long-table':`writing-${index+1}`;
  fs.writeFileSync(path.join(output,`${name}.json`),JSON.stringify(current,null,2));
  for(const format of ['txt','docx','pdf']){
   const bytes=await client.request(`/api/v1/ai/runs/${r.id}/export?format=${format}`,'GET',undefined,true);
   fs.writeFileSync(path.join(output,`${name}.${format}`),bytes);report.exports.push({name,id:r.id,format,bytes:bytes.length});
  }
 }
 const after=await client.request('/api/v1/ai/usage');check(JSON.stringify(before)===JSON.stringify(after),'export_or_edit_called_model');report.no_model_calls=true;report.usage=after;
}catch(e){report.error=e.message;process.exitCode=1;}finally{await session.stop();fs.writeFileSync(path.join(output,'export-report.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report));}
