import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/analyze-url':   'http://localhost:8000',
      '/analyze-email': 'http://localhost:8000',
      '/health':        'http://localhost:8000',
    }
  }
})