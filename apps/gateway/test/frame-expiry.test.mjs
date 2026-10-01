import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

// Clock changes and real synthetic Ed25519 proofs are confined to one child process.
// No wall-clock sleeps, external service, real secret or production clock mutation.
function scenario(mode, actualGateway = false) {
  const code = `import {generateKeyPairSync,sign} from 'node:crypto';
    import {runtimeSurfaceGuards} from ${JSON.stringify(new URL("../src/protocol-guard.mjs", import.meta.url).href)};
    import {toolSurfaceHash,canonicalJson,createArtifactSnapshot} from ${JSON.stringify(new URL("../src/artifact.mjs", import.meta.url).href)};
    import {getSignedAdmission} from ${JSON.stringify(new URL("../src/signed-admission.mjs", import.meta.url).href)};
    import {runArtifact} from ${JSON.stringify(new URL("../src/index.mjs", import.meta.url).href)};
    import {fileURLToPath} from 'node:url';
    const input=JSON.parse(process.argv[1]), key=generateKeyPairSync('ed25519');
    let wall=Date.now(),mono=performance.now();Date.now=()=>wall;
    Object.defineProperty(performance,'now',{value:()=>mono});
    const fixture=fileURLToPath(new URL('../../../demo/fixtures/mail-mcp-1.0.0',${JSON.stringify(import.meta.url)}));
    let tools=[{name:'alpha',inputSchema:{type:'object'},annotations:{readOnlyHint:true,destructiveHint:false}}];
    let identity={releaseId:'0x'+'1'.repeat(64),artifactDigest:'sha256:'+'2'.repeat(64),manifestDigest:'sha256:'+'3'.repeat(64),toolSurfaceHash:toolSurfaceHash(tools)};
    if(input.actualGateway){const local=await createArtifactSnapshot(fixture);tools=local.tools;identity={...local,releaseId:identity.releaseId};await local.cleanup();}
    const options={identity,policyHash:'0x'+'4'.repeat(64),chainId:1337,registryContract:'0x'+'5'.repeat(40),validatorSetVersion:1,
      tenantId:'frame-expiry-synthetic',operationClass:'READ_PRIVATE',keyId:'synthetic-issuer',publicKey:key.publicKey.export({type:'spki',format:'pem'}),
      apiToken:'SYNTHETIC_FRAME_TOKEN',apiBaseUrl:'https://synthetic.invalid',timeoutMs:100,cacheFile:null,indexer:null,rpc:null,admissionMode:'balanced'};
    let checks=0;const sources=[];
    const advance=()=>{mono+=input.mode==='valid'?100:2000;wall+=input.mode==='rollback'?-10000:input.mode==='valid'?100:2000;};
    const response=()=>{const snapshot={schemaVersion:'1.0.0',keyId:options.keyId,releaseId:identity.releaseId,artifactDigest:identity.artifactDigest,toolSurfaceHash:identity.toolSurfaceHash,
      policyHash:options.policyHash,chainId:options.chainId,registryContract:options.registryContract,validatorSetVersion:1,tenantId:options.tenantId,operationClass:'READ_PRIVATE',
      observedBlock:2,blockHash:'0x'+'6'.repeat(64),issuedAt:new Date(wall).toISOString(),expiresAt:new Date(wall+1000).toISOString(),
      decision:'ALLOW',status:'VERIFIED',reasonCode:'RELEASE_VERIFIED',reportUrl:'/v1/releases/'+identity.releaseId};
      return Response.json({snapshot,signature:sign(null,Buffer.from(canonicalJson(snapshot)),key.privateKey).toString('base64url')});};
    const beforeCall=async()=>{if(++checks===2)advance();const decision=await getSignedAdmission({...options,fetchImpl:async()=>input.mode==='cache'&&checks===1?new Response('',{status:503}):response()});sources.push(decision.decisionSource);return decision;};
    if(input.mode==='cache')await getSignedAdmission({...options,fetchImpl:async()=>response()});
    const meta={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientInfo':{name:'expiry-test',version:'1'},'io.modelcontextprotocol/clientCapabilities':{}};
    const batch=[1,2].map(id=>({jsonrpc:'2.0',id,method:'tools/call',params:{name:tools[0].name,arguments:{},_meta:meta}}));
    const wire=' '+JSON.stringify(batch)+' \\r\\n';let error=null,forwarded=[];
    if(input.actualGateway){let calls=0;try{await runArtifact({...options,artifactDir:fixture,controlReleaseId:identity.releaseId,mode:'live',capture:true,input:wire,executionTimeoutMs:1000,
      fetchImpl:async()=>{if(++calls===3)advance();return response();}});}catch(e){error=e.message;}console.log(JSON.stringify({error,calls}));}
    else{const write=(stream,value)=>new Promise((yes,no)=>stream.write(value,e=>e?no(e):yes()));let guards;
      guards=runtimeSurfaceGuards(identity.toolSurfaceHash,tools,beforeCall,{sendInternal:request=>write(guards.responses,JSON.stringify({jsonrpc:'2.0',id:request.id,result:{tools}})+'\\n')});
      guards.requests.on('data',chunk=>forwarded.push(chunk.toString()));guards.requests.on('error',()=>{});guards.responses.on('error',()=>{});
      try{await write(guards.requests,wire);}catch(e){error=e.message;}finally{guards.close();}
      console.log(JSON.stringify({error,sources,forwarded:forwarded.length,preserved:forwarded[0]===wire}));}`;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", code, JSON.stringify({ mode, actualGateway })], { encoding: "utf8", windowsHide: true, timeout: 10000, maxBuffer: 65536 });
  assert.equal(child.status, 0, "SYNTHETIC_EXPIRY_CHILD_FAILED");
  return JSON.parse(child.stdout.trim());
}

test("final batch fence rejects a previously valid API/cache lease expired while a later admission was awaited", () => {
  for (const mode of ["expired", "cache", "rollback"]) {
    const result = scenario(mode); assert.equal(result.forwarded, 0, mode); assert.equal(result.error, "MCP_ADMISSION_LEASE_EXPIRED", mode);
    assert.deepEqual(result.sources, [mode === "cache" ? "CACHE" : "API", "API"]);
  }
  const valid = scenario("valid"); assert.equal(valid.error, null); assert.equal(valid.forwarded, 1); assert.equal(valid.preserved, true);
});

test("actual Gateway caller passes signed call leases to the common final-forward fence", () => {
  const result = scenario("expired", true); assert.equal(result.calls, 3); assert.equal(result.error, "MCP_ADMISSION_LEASE_EXPIRED");
});
