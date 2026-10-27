import { ScanProgress } from "../../../components/site/scan-progress";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

const first = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value) || undefined;

export default async function Page({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  return <ScanProgress scanId={first(params.scanId) ?? "MS-2841"} tool={first(params.tool) ?? "filesystem-mcp"} version={first(params.version) ?? "2.4.1"} />;
}
