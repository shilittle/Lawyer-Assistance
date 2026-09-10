import fs from 'node:fs';import path from 'node:path';import {root,startServer,configureGlm,sleep} from './ai_test_client.mjs';
const fixtures=path.join(root,'output/ai-upgrade-fixtures');const manifest=JSON.parse(fs.readFileSync(path.join(fixtures,'manifest.json'),'utf8'));
const outputArg=process.argv.indexOf('--output-dir');
const output=outputArg>=0?path.resolve(root,process.argv[outputArg+1]):path.join(root,'output/ai-upgrade-redaction');fs.mkdirSync(output,{recursive:true});
const reportFile=path.join(output,'redaction-report.json');if(fs.existsSync(reportFile)){const previous=JSON.parse(fs.readFileSync(reportFile,'utf8'));fs.copyFileSync(reportFile,path.join(output,`redaction-report-${String(previous.started_at||Date.now()).replaceAll(':','-')}.json`));}
const session=await startServer(path.join(output,'workspace'));const client=session.client;
const report={model:'glm-5.3-flash',started_at:new Date().toISOString(),materials:[],errors:[]};
try{
 await configureGlm(client);
 const subset=process.argv.includes('--sample')?manifest.materials.filter(m=>m.case_id==='C01'):manifest.materials;
 const groups=new Map();
 for(const material of subset){
  if(!groups.has(material.case_id)){const g=await client.request('/api/v1/groups','POST',{name:`独立验收 ${material.case_id}`});groups.set(material.case_id,g.id);}
  const form=new FormData();form.set('group_id',groups.get(material.case_id));form.set('request_id',`fixture-${material.case_id}-${Date.now()}-${report.materials.length}`);if(material.encoding)form.set('encoding',material.encoding);
  form.append('files',new Blob([fs.readFileSync(path.join(fixtures,material.path))]),path.basename(material.path));
  const task=await client.request('/api/v1/imports','POST',form);report.materials.push({...material,material_id:task.materials[0].id,task_id:task.id,status:'queued',submitted_at:Date.now()});
 }
 const start=Date.now();let previous='';
 while(Date.now()-start<4*3600000){
  for(const item of report.materials.filter(m=>['queued','running'].includes(m.status))){
   const m=await client.request(`/api/v1/materials/${item.material_id}`);item.status=m.status;item.reason_code=m.reason_code;
   if(!['queued','running'].includes(m.status)){
    item.elapsed_ms=Date.now()-item.submitted_at;item.result_id=m.result_id;fs.writeFileSync(path.join(output,`${item.material_id}.json`),JSON.stringify(m,null,2));
    if(m.result_id){try{const result=await client.request(`/api/v1/results/${m.result_id}/export?format=txt`,'GET',undefined,true);fs.writeFileSync(path.join(output,`${item.material_id}.txt`),result);item.result_length=result.length;}catch(e){item.result_error=e.message;}}
    console.log(JSON.stringify({path:item.path,status:item.status,reason:item.reason_code,ms:item.elapsed_ms}));
   }
  }
  const counts=report.materials.reduce((a,m)=>(a[m.status]=(a[m.status]||0)+1,a),{});const progress=JSON.stringify(counts);if(progress!==previous){console.log(progress);previous=progress;}
  fs.writeFileSync(path.join(output,'redaction-report.json'),JSON.stringify(report,null,2));
  if(report.materials.every(m=>!['queued','running'].includes(m.status)))break;await sleep(3000);
 }
 report.completed_at=new Date().toISOString();
}catch(e){report.errors.push(e.message);console.error(e.message);process.exitCode=1;}finally{try{report.usage=await client.request('/api/v1/ai/usage');}catch(e){report.usage_error=e.message;}fs.writeFileSync(path.join(output,'redaction-report.json'),JSON.stringify(report,null,2));await session.stop();}
