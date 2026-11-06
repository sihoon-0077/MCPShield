/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  // The dev-server "N" badge sits on the workspace sidebar in demo recordings.
  devIndicators: false,
  // The Figma-design workspace replaced the Control Room and Judge Lab pages; keep their old links working.
  async redirects() {
    return [
      { source: "/dashboard", destination: "/overview", permanent: false },
      { source: "/try", destination: "/security-scan", permanent: false }
    ];
  },
  async rewrites() {
    return [{ source: "/mcp", destination: "http://127.0.0.1:8787/mcp" }];
  }
};

export default nextConfig;
