import { ScanProgress } from "../../../components/site/scan-progress";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

const first = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value) || null;

// Only a scan UUID reaches the client; anything else is treated as "no scan".
export default async function Page({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const scan = first(params.scan);
  return <ScanProgress scanId={scan && /^[0-9a-f-]{36}$/.test(scan) ? scan : null} reused={first(params.reused) === "1"} />;
}
