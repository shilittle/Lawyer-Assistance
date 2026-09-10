import fs from 'node:fs';import path from 'node:path';
import {root,startServer,configureGlm,check} from './ai_test_client.mjs';
const outputArg=process.argv.indexOf('--output-dir');
const output=outputArg>=0?path.resolve(root,process.argv[outputArg+1]):path.join(root,'output/ai-upgrade-live');fs.mkdirSync(output,{recursive:true});
const server=await startServer(path.join(output,'workspace'));const client=server.client;const report={started_at:new Date().toISOString(),model:'glm-5.3-flash',reasoning_effort:'low',runs:[],checks:[]};
try {
 const selection=await configureGlm(client);report.connection=await client.request('/api/v1/ai/providers/test','POST',selection);console.log('GLM configured and connected');
 for(const query of ['公司','合同']){const start=Date.now();const r=await client.request('/api/v1/legal/search/page?'+new URLSearchParams({query,limit:'5',view:'grouped'}));report.checks.push({name:'law_search',query,total:r.total,keys:Object.keys(r),first:r.laws?.[0]?.law?.title,ms:Date.now()-start});console.log(JSON.stringify(report.checks.at(-1)));}
 const scenario='以下全部是虚构验收材料。2026年3月12日，清沅测试设备有限公司向澄岭测试商贸有限公司出售设备，总价126800元，合同约定4月10日前支付全部价款。买方签收并使用后仅支付30000元，剩余96800元经催告未付。买方称设备存在质量问题，但验收单写明外观和运行正常，其后未提交检测报告。合同签署人为买方采购经理，合同盖有公司公章。卖方希望请求剩余价款并主张逾期付款损失。请分析价款支付义务、质量异议、代理权限及举证问题，分别改变关键词检索相应法条，并读取原文；无法确认的事实列出待补充。';
 for(let repeat=1;repeat<=3;repeat++){
  for(const kind of ['search','writing','chat']){
   const conversation=kind==='chat'?await client.request('/api/v1/ai/conversations','POST',{}):null;
   const started=Date.now();const created=await client.request('/api/v1/ai/runs','POST',{kind,prompt:scenario,document_type:kind==='writing'?'民事起诉状':undefined,requirements:kind==='writing'?'为卖方拟写起诉状，主体具体身份和法院不明处写待补充，金额日期准确，末尾列出已核验法律依据。':undefined,conversation_id:conversation?.id});
   let result=await client.waitRun(created.id);const attempts=[{id:result.id,status:result.status}];
   for(let continuation=0;result.status==='paused'&&continuation<2;continuation++){
    fs.writeFileSync(path.join(output,`${kind}-${repeat}-paused-${continuation+1}.json`),JSON.stringify(result,null,2));
    const next=await client.request(`/api/v1/ai/runs/${result.id}/continue`,'POST',{});result=await client.waitRun(next.id);attempts.push({id:result.id,status:result.status});
   }
   fs.writeFileSync(path.join(output,`${kind}-${repeat}.json`),JSON.stringify(result,null,2));
   report.runs.push({kind,repeat,id:result.id,attempts,status:result.status,error_code:result.error_code,usage:result.usage,tool_calls:result.tool_steps.length,queries:result.tool_steps.map(t=>t.query).filter(Boolean),citations:result.citations.length,ms:Date.now()-started});console.log(JSON.stringify(report.runs.at(-1)));fs.writeFileSync(path.join(output,'live-report.json'),JSON.stringify(report,null,2));
   if(result.status==='completed'&&kind==='writing')for(const format of ['txt','docx','pdf']){const bytes=await client.request(`/api/v1/ai/runs/${result.id}/export?format=${format}`,'GET',undefined,true);fs.writeFileSync(path.join(output,`writing-${repeat}.${format}`),bytes);}
  }
 }
 report.completed_at=new Date().toISOString();
 if(report.runs.length!==9||report.runs.some(run=>run.status!=='completed'))process.exitCode=1;
}catch(error){report.error=error.message;console.error(error.message);process.exitCode=1;}finally{try{report.usage=await client.request('/api/v1/ai/usage');}catch(error){report.usage_error=error.message;}fs.writeFileSync(path.join(output,'live-report.json'),JSON.stringify(report,null,2));await server.stop();}
