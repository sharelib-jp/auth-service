import { defineConfig } from 'vite'
import { devtools } from '@tanstack/devtools-vite'

import { tanstackRouter } from '@tanstack/router-plugin/vite'

import viteReact from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const apiTarget = process.env.AUTH_API_TARGET ?? 'http://localhost:8080'
const extraAllowedHost = process.env.AUTH_DEV_ALLOWED_HOST

const config = defineConfig({
  resolve: { tsconfigPaths: true },
  plugins: [
    devtools(),
    tailwindcss(),
    tanstackRouter({ target: 'react', autoCodeSplitting: true }),
    viteReact(),
  ],
  server: {
    allowedHosts: [
      'localhost',
      'auth-dev-sharelib.luca.hij1.local.sasakulab.com',
      ...(extraAllowedHost ? [extraAllowedHost] : []),
    ],
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
      '/oauth2': { target: apiTarget, changeOrigin: true },
      '/.well-known': { target: apiTarget, changeOrigin: true },
      '/userinfo': { target: apiTarget, changeOrigin: true },
    },
  },
})

export default config
