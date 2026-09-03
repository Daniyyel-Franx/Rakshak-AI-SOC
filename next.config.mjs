/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  // Same-origin bridge for the local FastAPI service in the preview.
  // The browser never needs direct access to localhost:8000.
  async rewrites() {
    return [
      {
        source: "/api/backend/api/:path*",
        destination: "http://127.0.0.1:8000/api/:path*",
      },
    ]
  },
}

export default nextConfig
