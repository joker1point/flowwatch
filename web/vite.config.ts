import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5273, // 避开 portwatch 的 5173，两个项目可以同时开着对照
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
})
