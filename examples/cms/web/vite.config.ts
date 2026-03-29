import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const proxyTarget = process.env.VITE_API_PROXY_TARGET ?? '/';

export default defineConfig(({ command }) => ({
  base: command === 'serve' ? '/studio/' : './',
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (
            id.includes('@mui/material') ||
            id.includes('@mui/icons-material') ||
            id.includes('@emotion/react') ||
            id.includes('@emotion/styled')
          ) {
            return 'mui';
          }
          if (
            id.includes('react-router-dom') ||
            id.includes('@tanstack/react-query') ||
            id.includes('/react/') ||
            id.includes('/react-dom/')
          ) {
            return 'react';
          }
          return undefined;
        },
      },
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    open: '/studio/',
    proxy: {
      '/api': {
        target: proxyTarget,
        changeOrigin: true,
        secure: false,
      },
      '/_s3': {
        target: proxyTarget,
        changeOrigin: true,
        secure: false,
      },
      '/uploads': {
        target: proxyTarget,
        changeOrigin: true,
        secure: false,
      },
      '/openapi.json': {
        target: proxyTarget,
        changeOrigin: true,
        secure: false,
      },
    },
  },
  preview: {
    host: '0.0.0.0',
    port: 4173,
  },
}));
