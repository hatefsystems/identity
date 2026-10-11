//@ts-check
const path = require('node:path');

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  outputFileTracingRoot: path.join(__dirname, '../..'),
  // Transpile the shared workspace UI library (shadcn/ui components).
  transpilePackages: ['@hatef/ui'],
};

module.exports = nextConfig;
