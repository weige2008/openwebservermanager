import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { defineConfig } from '@rsbuild/core'
import { pluginReact } from '@rsbuild/plugin-react'
import { pluginTailwindcss } from '@rsbuild/plugin-tailwindcss'

const dirname = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig(({ envMode }) => {
  const isProd = envMode === 'production'

  return {
    plugins: [pluginReact(), pluginTailwindcss({ optimize: false })],
    source: {
      entry: {
        index: './src/main.tsx',
      },
    },
    html: {
      template: './index.html',
    },
    resolve: {
      alias: {
        '@': path.resolve(dirname, './src'),
      },
    },
    server: {
      host: '127.0.0.1',
      proxy: {
        '/api': { target: 'http://127.0.0.1:23876', changeOrigin: true, ws: true },
      },
    },
    output: {
      minify: isProd,
      cleanDistPath: true,
      distPath: {
        root: '../cmd/openwebservermanager/static',
        js: 'assets',
        css: 'assets',
        font: 'assets',
        image: 'assets',
      },
    },
    performance: {
      removeConsole: isProd ? ['log'] : false,
      buildCache: false,
    },
  }
})
