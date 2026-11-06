import { ScanResults } from "../../../components/site/scan-results";
// The per-validator vote table and admission view are the console's own components; they keep the console's styles.
import "../console/console.css";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

const first = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value) || null;

// ?scan=<uuid> | ?release=<0x…64> | nothing (newest completed scan). Malformed values count as missing.
export default async function Page({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const scan = first(params.scan), release = first(params.release);
  return <ScanResults scanId={scan && /^[0-9a-f-]{36}$/.test(scan) ? scan : null} releaseId={release && /^0x[0-9a-f]{64}$/.test(release) ? release : null} />;
}
