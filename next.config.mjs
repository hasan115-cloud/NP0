/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/download-extension',
        destination: '/api/download-extension',
      },
      {
        source: '/extension/download',
        destination: '/api/download-extension',
      },
      {
        source: '/health',
        destination: '/api/health',
      },
      {
        source: '/info',
        destination: '/api/info',
      },
    ];
  },
};

export default nextConfig;
