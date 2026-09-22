/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  async rewrites() {
    return [{ source: "/mcp", destination: "http://127.0.0.1:8787/mcp" }];
  }
};

export default nextConfig;
