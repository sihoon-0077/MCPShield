import type { FetchRequest } from "ethers";
export function checkedServiceUrl(value: string, allowedHttpHosts?: string[]): URL;
export function boundedServiceRequest(url: string, init: RequestInit, options?: { timeoutMs?: number; maxBytes?: number; allowedHttpHosts?: string[] }): Promise<{ statusCode: number; statusMessage: string; headers: Record<string, string>; body: Buffer }>;
export function v2RpcRequest(url: string, options?: { timeoutMs?: number; signal?: AbortSignal; allowedHttpHosts?: string[] }): FetchRequest;
