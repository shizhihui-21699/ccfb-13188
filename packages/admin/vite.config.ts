import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// 开发环境把 /kms 与 /app 代理到两个 Bun 服务；生产由网关同源暴露
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5300,
    proxy: {
      '/kms': {
        target: 'http://127.0.0.1:3100',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/kms/, ''),
      },
      '/app': {
        target: 'http://127.0.0.1:3200',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/app/, ''),
      },
    },
  },
  build: { outDir: 'dist' },
});
