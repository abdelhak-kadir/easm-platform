import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output required for the Docker production image —
  // Next.js bundles only the files the server actually needs, so the
  // runner stage stays small and doesn't carry the full source tree.
  output: "standalone",
};

export default nextConfig;
