//@ts-check

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Transpile the shared workspace UI library (shadcn/ui components).
  transpilePackages: ['@hatef/ui'],
};

module.exports = nextConfig;
