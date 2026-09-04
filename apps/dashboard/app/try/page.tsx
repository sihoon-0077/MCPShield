import type { Metadata } from "next";
import { JudgeDemo } from "../../components/judge-demo";

export const metadata: Metadata = {
  title: "Try MCPShield",
  description: "Run an isolated synthetic MCP supply-chain security demo",
};

export default function TryPage() {
  return <JudgeDemo />;
}
