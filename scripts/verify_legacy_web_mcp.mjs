import {spawn} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {root,startServer} from './ai_test_client.mjs';
const output=path.join(root,'output/ai-upgrade-regression');fs.mkdirSync(output,{recursive:true});
const data=path.join(output,`workspace-${Date.now()}`);const legal=path.join(output,'legal_core.synthetic.sqlite');
const mcp=path.join(root,'target/x86_64-pc-windows-msvc/debug/lawyer-assistance-mcp.exe');
const session=await startServer(data,undefined,legal);const results=[];
async function run(script,args){
 const log=fs.openSync(path.join(output,`${script}.log`),'w');
 const p=spawn(process.execPath,[path.join(root,'scripts',script+'.mjs'),...args],{cwd:root,windowsHide:true,stdio:['ignore',log,log]});
 const code=await new Promise(resolve=>p.once('exit',resolve));fs.closeSync(log);results.push({script,exit_code:code});
 if(code!==0)throw new Error(`${script}:exit_${code}`);
}
try{
 await run('smoke_web',['--data-dir',data,'--require-browser']);
 await run('smoke_mcp',['--data-dir',data,'--legal-db',legal,'--binary',mcp]);
}catch(e){results.push({error:e.message});process.exitCode=1;}finally{await session.stop();fs.writeFileSync(path.join(output,'regression-report.json'),JSON.stringify(results,null,2));console.log(JSON.stringify(results));}
