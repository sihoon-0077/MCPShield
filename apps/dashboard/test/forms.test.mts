import assert from "node:assert/strict";
import test from "node:test";
import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { NextRequest } from "next/server";
import { POST } from "../app/api/control/[...path]/route";
import { privateNode } from "../../../tests/api/runtime-fullcycle-helpers.js";

const dashboard = dirname(dirname(fileURLToPath(import.meta.url)));
test("every dashboard form has POST fallback and no action/submit override that can put private values in a URL", async () => {
  const components = join(dashboard, "components"); let forms = 0;
  for (const path of (await readdir(components, { recursive: true })).filter(path => path.endsWith(".tsx"))) {
    const source = ts.createSourceFile(path, await readFile(join(components, path), "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const visit = (node: ts.Node) => {
      if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
        const attrs = node.attributes.properties.filter(ts.isJsxAttribute), tag = node.tagName.getText(source);
        if (tag === "form") {
          forms++; const method = attrs.find(attr => attr.name.getText(source) === "method")?.initializer;
          assert.ok(method && ts.isStringLiteral(method) && method.text === "post", `POST fallback required: ${path}`);
          assert.equal(attrs.some(attr => attr.name.getText(source) === "action"), false, `Native forms stay on the console document: ${path}`);
          assert.equal(node.attributes.properties.some(ts.isJsxSpreadAttribute), false, `No opaque native-form override: ${path}`);
        }
        assert.equal(attrs.some(attr => ["formMethod", "formAction"].includes(attr.name.getText(source))), false, `No submit override: ${path}`);
      }
      ts.forEachChild(node, visit);
    }; visit(source);
  }
  assert.ok(forms >= 9, "All existing login, appeal and operation form callers were inspected");
});

test("native form bodies cannot mutate control BFF endpoints even with a cookie, and cross-origin POST remains rejected", async context => {
  let forwards = 0; context.mock.method(globalThis, "fetch", async () => { forwards++; throw Error("UNEXPECTED_FORWARD"); });
  const previous = process.env.MCPSHIELD_PUBLIC_ORIGIN; process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  try {
    for (const path of ["session", "scans", "policies", "receipt-ledgers", "appeals/synthetic/resolve", "releases/synthetic/appeals", "releases/synthetic/prepare"]) {
      for (const origin of ["https://console.test", "https://attacker.invalid"]) {
        const response = await POST(new NextRequest(`https://console.test/api/control/${path}`, { method: "POST",
          headers: { origin, cookie: "mcpshield_control=synthetic-private-token", "content-type": "application/x-www-form-urlencoded" },
          body: "token=SYNTHETIC_PRIVATE_FORM_VALUE&resolution=SYNTHETIC_PRIVATE_FORM_VALUE" }), { params: Promise.resolve({ path: path.split("/") }) });
        assert.equal(response.status, origin === "https://console.test" ? 415 : 403); assert.doesNotMatch(await response.text(), /SYNTHETIC_PRIVATE_FORM_VALUE/);
        assert.equal(response.headers.get("set-cookie"), null);
      }
    }
    assert.equal(forwards, 0);
  } finally { previous === undefined ? delete process.env.MCPSHIELD_PUBLIC_ORIGIN : process.env.MCPSHIELD_PUBLIC_ORIGIN = previous; }
});

// Run after build:dashboard. This is actual local HTTP, not a browser/hydration claim.
test("built console native POST renders the same unauthenticated login view without redirecting or reflecting private form values", { skip: process.env.MCPSHIELD_FORM_HTTP_TESTS !== "1", timeout: 20000 }, async () => {
  // Next must bootstrap its own AsyncLocalStorage before any route imports;
  // the existing bounded child helper isolates it from the BFF unit-test runtime.
  const result = await privateNode(`
    import next from 'next'; import {createServer} from 'node:http';
    const output=process.stdout.write.bind(process.stdout),runtimeOutput=[];let outputBytes=0;
    process.stdout.write=(chunk,...rest)=>{if((outputBytes+=Buffer.byteLength(chunk))>65536)throw Error('FORM_RUNTIME_OUTPUT_LIMIT');runtimeOutput.push(String(chunk));const callback=rest.at(-1);if(typeof callback==='function')callback();return true;};
    let input='';for await(const chunk of process.stdin)input+=chunk;
    const {directory}=JSON.parse(input),app=next({dev:false,dir:directory,hostname:'127.0.0.1',quiet:true});
    const server=createServer((request,response)=>{void app.getRequestHandler()(request,response).catch(()=>{response.statusCode=500;response.end('FORM_HANDLER_FAILED');});});
    try{
      await app.prepare();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
      const origin='http://127.0.0.1:'+server.address().port;
      const before=await fetch(origin+'/console',{signal:AbortSignal.timeout(5000)}),beforeBody=await before.text();
      const response=await fetch(origin+'/console',{method:'POST',redirect:'manual',signal:AbortSignal.timeout(5000),
        headers:{origin,'content-type':'application/x-www-form-urlencoded'},body:'token=SYNTHETIC_PRIVATE_FORM_VALUE&resolution=SYNTHETIC_PRIVATE_FORM_VALUE'});
      const body=await response.text();
      const view=value=>value.match(/<main\\b[\\s\\S]*?<\\/main>/)?.[0];
      output(JSON.stringify({status:response.status,sameLoginView:before.status===200&&Boolean(view(body))&&view(body)===view(beforeBody),login:body.includes('name="token"'),location:response.headers.get('location'),cookie:response.headers.get('set-cookie'),reflected:body.includes('SYNTHETIC_PRIVATE_FORM_VALUE'),logged:runtimeOutput.join('').includes('SYNTHETIC_PRIVATE_FORM_VALUE')}));
    }finally{server.closeAllConnections();await new Promise(resolve=>server.close(()=>resolve()));await app.close();}
  `, { directory: dashboard, token: "SYNTHETIC_PRIVATE_FORM_VALUE" }, 15000);
  assert.deepEqual(result, { status: 200, sameLoginView: true, login: true, location: null, cookie: null, reflected: false, logged: false });
});
