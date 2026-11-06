import "./globals.css";

// The Figma site keeps its own root layout in app/(site); /ledger sits outside that group, so it needs its own.
// globals.css is the Control Room stylesheet that /ledger used before the Figma merge (CSS variables, main, .eyebrow).
export default function LedgerRootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="ko">
      <body>{children}</body>
    </html>
  );
}
