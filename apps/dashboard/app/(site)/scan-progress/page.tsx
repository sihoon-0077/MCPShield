import { ScanProgress } from "../../../components/site/scan-progress";
import { isTarget } from "../../../components/site/scan-session";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

const first = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value) || null;

export default async function Page({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const target = first(params.target);
  return <ScanProgress sessionId={first(params.session)} target={isTarget(target) ? target : "1.0.1"} />;
}
