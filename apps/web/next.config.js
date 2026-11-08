//@ts-check
const path = require('node:path');
const createNextIntlPlugin = require('next-intl/plugin');

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  outputFileTracingRoot: path.join(__dirname, '../..'),
  // Transpile the shared workspace UI library (shadcn/ui components).
  transpilePackages: ['@hatef/ui'],
};

module.exports = createNextIntlPlugin('./i18n/request.ts')(nextConfig);
