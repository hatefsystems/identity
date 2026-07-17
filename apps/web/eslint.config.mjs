import baseConfig from '../../eslint.config.mjs';
import nx from '@nx/eslint-plugin';
import nextEslintPluginNext from '@next/eslint-plugin-next';

export default [
  ...baseConfig,
  ...nx.configs['flat/react-typescript'],
  { plugins: { '@next/next': nextEslintPluginNext } },
  {
    files: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    rules: {
      '@next/next/no-html-link-for-pages': ['error', 'apps/web/pages'],
      '@next/next/no-img-element': 'warn',
      '@next/next/no-sync-scripts': 'error',
      '@next/next/no-head-element': 'error',
      '@next/next/no-css-tags': 'error',
      '@next/next/no-document-import-in-page': 'error',
      '@next/next/no-head-import-in-document': 'error',
      '@next/next/no-duplicate-head': 'error',
    },
  },
  ...nx.configs['flat/typescript'],
  ...nx.configs['flat/javascript'],
  {
    ignores: ['.next/**/*', '**/out-tsc'],
  },
];
