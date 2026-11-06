import { SecurityScan } from "../../../components/site/security-scan";
import { isFixtureVersion } from "../../../components/site/v3-model";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

// ?version=1.0.1 preselects that fixture; the default is 1.0.0.
export default async function Page({ searchParams }: { searchParams: SearchParams }) {
  const { version } = await searchParams;
  const value = Array.isArray(version) ? version[0] : version;
  return <SecurityScan initialVersion={isFixtureVersion(value) ? value : "1.0.0"} />;
}
