import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MCPShield Control Room",
  description: "Release verification and gateway admission dashboard"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
