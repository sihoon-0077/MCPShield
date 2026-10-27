import { ScanResults } from "../../../components/site/scan-results";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function Page({ searchParams }: { searchParams: SearchParams }) {
  const { session } = await searchParams;
  return <ScanResults sessionId={(Array.isArray(session) ? session[0] : session) || null} />;
}
