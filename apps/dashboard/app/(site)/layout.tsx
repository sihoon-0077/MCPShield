import type { Metadata } from "next";
import { LanguageProvider } from "../../components/site/i18n";
import "./site.css";

export const metadata: Metadata = {
  title: "MCPShield",
  description: "MCPShield helps teams verify MCP tools for security risks before AI uses them, making it easier to block unsafe actions and build trust in AI workflows."
};

// Separate root layout so the Figma design CSS never mixes with the Control Room styles.
export default function SiteLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="ko">
      <body><LanguageProvider>{children}</LanguageProvider></body>
    </html>
  );
}
