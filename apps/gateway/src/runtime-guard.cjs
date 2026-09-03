"use strict";

const denied = () => { throw new Error("MCPShield runtime egress is disabled"); };
for (const name of ["fetch", "WebSocket", "EventSource"]) {
  if (name in globalThis) Object.defineProperty(globalThis, name, { value: denied, writable: false, configurable: false });
}
for (const name of ["binding", "_linkedBinding", "getBuiltinModule"]) {
  if (name in process) Object.defineProperty(process, name, { value: denied, writable: false, configurable: false });
}
