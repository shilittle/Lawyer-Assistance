import {spawn} from 'node:child_process';import fs from 'node:fs';import path from 'node:path';
import {root,startServer} from './ai_test_client.mjs';
const output=path.join(root,'output/ai-upgrade-corpus');fs.mkdirSync(output,{recursive:true});
const data=path.join(output,`workspace-${Date.now()}`);const session=await startServer(data);
try{
 const log=fs.openSync(path.join(output,'http-mcp-smoke.log'),'w');
 const p=spawn(process.execPath,[path.join(root,'scripts/smoke_cases.mjs'),'--data-dir',data,'--legal-db',path.join(root,'data/runtime/legal_core.sqlite'),'--binary',path.join(root,'target/x86_64-pc-windows-msvc/debug/lawyer-assistance-mcp.exe'),'--archive','true'],{cwd:root,windowsHide:true,stdio:['ignore',log,log]});
 const code=await new Promise(resolve=>p.once('exit',resolve));fs.closeSync(log);process.exitCode=code;
 console.log(fs.readFileSync(path.join(output,'http-mcp-smoke.log'),'utf8'));
}finally{await session.stop();}
