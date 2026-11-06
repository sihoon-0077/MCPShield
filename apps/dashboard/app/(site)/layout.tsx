import type { Metadata } from "next";
import "pretendard/dist/web/variable/pretendardvariable-dynamic-subset.css";
import "@fontsource-variable/jetbrains-mono";
import { LanguageProvider } from "../../components/site/i18n";
import "./site.css";
import "./theme.css";
import "./landing.css";

export const metadata: Metadata = {
  title: "MCPShield",
  description: "MCPShield helps teams verify MCP tools for security risks before AI uses them, making it easier to block unsafe actions and build trust in AI workflows."
};

// Latin text and headings: Switzer and Cabinet Grotesk, served by the Fontshare API (their licence forbids committing the files).
const FONTSHARE = ["cabinet-grotesk", "switzer"].map((family) => `https://api.fontshare.com/v2/css?f[]=${family}@1&display=swap`);

// Separate root layout so the Figma design CSS never mixes with the Control Room styles.
export default function SiteLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="ko" data-scroll-behavior="smooth">
      <head>
        <link rel="preconnect" href="https://api.fontshare.com" crossOrigin="" />
        <link rel="preconnect" href="https://cdn.fontshare.com" crossOrigin="" />
        {FONTSHARE.map((href) => <link rel="stylesheet" href={href} key={href} />)}
      </head>
      <body><LanguageProvider>{children}</LanguageProvider></body>
    </html>
  );
}
