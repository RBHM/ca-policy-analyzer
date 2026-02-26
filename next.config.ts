import type { NextConfig } from "next";

const isGitHubPages = process.env.GITHUB_PAGES === "true";

const nextConfig: NextConfig = {
  output: "export",
  // GitHub Pages serves from /ca-policy-analyzer/
  basePath: isGitHubPages ? "/ca-policy-analyzer" : "",
  assetPrefix: isGitHubPages ? "/ca-policy-analyzer/" : undefined,
  images: {
    unoptimized: true, // Required for static export
  },
};

export default nextConfig;
