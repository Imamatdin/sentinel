/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',

  // Proxy API requests to backend in development
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://localhost:8000/api/:path*',
      },
    ];
  },
};

module.exports = nextConfig;
