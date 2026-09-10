import fs from 'node:fs';import path from 'node:path';import {root,startServer,check,sleep} from './ai_test_client.mjs';
const output=path.resolve(root,process.argv[2]||'output/ai-upgrade-live');const session=await startServer(path.join(output,'workspace'));const client=session.client;const report={reopened_at:new Date().toISOString(),resumed:[],exports:[],conversations:[]};
try{
 let history=(await client.request('/api/v1/ai/runs')).runs;check(history.length>=9,'history_lost');report.history_count=history.length;
 check(!history.some(r=>['queued','running'].includes(r.status)),'original_batch_still_running');
 const parents=new Set(history.map(r=>r.parent_id).filter(Boolean));
 for(const run of history.filter(r=>['paused','failed'].includes(r.status)&&!parents.has(r.id))){const next=await client.request(`/api/v1/ai/runs/${run.id}/continue`,'POST',{});const result=await client.waitRun(next.id);report.resumed.push({id:result.id,parent_id:run.id,status:result.status,error_code:result.error_code,usage:result.usage,citations:result.citations.length,tool_steps:result.tool_steps.length});fs.writeFileSync(path.join(output,`${run.id}-resumed.json`),JSON.stringify(result,null,2));console.log(JSON.stringify(report.resumed.at(-1)));}
 history=(await client.request('/api/v1/ai/runs')).runs;
 for(const run of history.filter(r=>r.kind==='writing'&&r.status==='completed')){
  const current=await client.request(`/api/v1/ai/runs/${run.id}`);const before=JSON.stringify(current.usage);
  for(const format of ['txt','docx','pdf']){const bytes=await client.request(`/api/v1/ai/runs/${run.id}/export?format=${format}`,'GET',undefined,true);fs.writeFileSync(path.join(output,`verified-${run.id}.${format}`),bytes);report.exports.push({id:run.id,format,bytes:bytes.length});}
  check(JSON.stringify((await client.request(`/api/v1/ai/runs/${run.id}`)).usage)===before,'export_called_model');
 }
 await sleep(5000);
 for(const summary of (await client.request('/api/v1/ai/conversations')).conversations){const c=await client.request(`/api/v1/ai/conversations/${summary.id}`);report.conversations.push({id:c.id,title:c.title,messages:c.messages.length,manual:c.title_manual});}
}catch(e){report.error=e.message;console.error(e.message);process.exitCode=1;}finally{fs.writeFileSync(path.join(output,'resume-report.json'),JSON.stringify(report,null,2));await session.stop();}
