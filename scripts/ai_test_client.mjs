import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
export const root = path.resolve(import.meta.dirname, '..');
export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
export function check(value, message) { if (!value) throw new Error(message); }
export function connection(dataDir) {
  const script = "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; $bytes=[IO.File]::ReadAllBytes($env:LAWYER_AI_TEST_DESCRIPTOR); $entropy=[Text.Encoding]::ASCII.GetBytes('LawyerAssistance/privacy/local-protected-blob/v1'); [Console]::Out.Write([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($bytes,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)))";
  const result=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{windowsHide:true,encoding:'utf8',env:{...process.env,LAWYER_AI_TEST_DESCRIPTOR:path.join(dataDir,'connection.dpapi')}});
  check(result.status===0,'connection_descriptor_failed'); return JSON.parse(result.stdout);
}
export class Client {
  constructor(origin){this.origin=origin;this.cookie='';this.csrf='';}
  async request(route, method='GET',body, binary=false) {
    const headers={cookie:this.cookie}; if(this.csrf&&method!=='GET') headers['x-csrf-token']=this.csrf;
    if(body!==undefined&&!(body instanceof FormData)){headers['content-type']='application/json';body=JSON.stringify(body);}
    const response=await fetch(this.origin+route,{method,headers,body,signal:AbortSignal.timeout(650000)});
    const cookie=response.headers.get('set-cookie');if(cookie)this.cookie=cookie.split(';')[0];
    if(binary&&response.ok)return Buffer.from(await response.arrayBuffer());
    const data=await response.json();if(!response.ok)throw new Error(`${route}:${data.error?.code||response.status}`); return data;
  }
  async login(token){const r=await this.request('/api/v1/session','POST',{token});this.csrf=r.csrf_token;}
  async waitRun(id,timeout=1800000){const start=Date.now();let previous='';while(Date.now()-start<timeout){const r=await this.request(`/api/v1/ai/runs/${id}`);if(r.stage!==previous){console.log(JSON.stringify({run:id,status:r.status,stage:r.stage}));previous=r.stage;}if(!['queued','running'].includes(r.status))return r;await sleep(1500);}throw new Error('run_timeout');}
}
export async function startServer(dataDir,executable=path.join(root,'target/x86_64-pc-windows-msvc/debug/lawyer-assistance.exe'),legalDb=path.join(root,'data/runtime/legal_core.sqlite'),options={}) {
  if(!options.portable){const info=fs.statSync(executable);const copied=path.join(root,'output/ai-test-bin',`${info.size}-${Math.trunc(info.mtimeMs)}-${process.pid}`,'lawyer-assistance.exe');fs.mkdirSync(path.dirname(copied),{recursive:true});if(!fs.existsSync(copied))fs.copyFileSync(executable,copied);executable=copied;}
  fs.mkdirSync(dataDir,{recursive:true});const log=fs.openSync(path.join(dataDir,'server-test.log'),'a');
  const env={...process.env};if(options.portable){delete env.LAWYER_RUNTIME_TOOLS;delete env.LAWYER_ASSISTANCE_PDFIUM;}else env.LAWYER_RUNTIME_TOOLS=path.join(root,'output/runtime-tools');
  if(options.discoverLegalDb)delete env.LEGAL_DB;
  const args=['serve','--port','0','--data-dir',dataDir];
  if(!options.discoverLegalDb)args.push('--legal-db',legalDb);
  const server=spawn(executable,args,{windowsHide:true,stdio:['ignore',log,log],env,cwd:options.portable?path.dirname(executable):root});
  let descriptor;for(let i=0;i<100;i++){if(server.exitCode!==null)throw new Error('server_exited');try{descriptor=connection(dataDir);if(descriptor.pid===server.pid)break;}catch{}await sleep(200);}
  check(descriptor?.pid===server.pid,'server_start_timeout');const client=new Client(descriptor.origin);await client.login(descriptor.bootstrap);
  return {client,server,stop:async()=>{server.kill();await new Promise(r=>server.exitCode===null?server.once('exit',r):r());fs.closeSync(log);}};
}
export async function configureGlm(client){
  const lines=fs.readFileSync(path.join(root,'apikey.txt'),'utf8').split(/\r?\n/).filter(s=>s.trim());const marker=lines.findIndex(s=>/^GLM\s+api/i.test(s));check(marker>=0&&lines[marker+1],'glm_key_missing');
  const key=lines[marker+1].trim();const p=await client.request('/api/v1/ai/providers');const old=p.providers.find(p=>p.name==='GLM 实际验收');
  const discovered=await client.request('/api/v1/ai/providers/models','POST',{preset:'glm',api_key:key});check(discovered.models.some(m=>m.id==='glm-5.3-flash'),'glm_model_not_discovered');
  const saved=await client.request('/api/v1/ai/providers','POST',{id:old?.id,preset:'glm',name:'GLM 实际验收',enabled_models:['glm-5.3-flash'],api_key:key});
  const selection={provider_id:saved.id,model:'glm-5.3-flash'};await client.request('/api/v1/ai/defaults','PUT',Object.fromEntries(['chat','writing','redaction','ocr'].map(k=>[k,selection])));return selection;
}
