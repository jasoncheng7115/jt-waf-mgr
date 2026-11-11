// Build config for the jt-waf-mgr UI.
// Temporarily borrows jt-ipam's installed toolchain (read-only) so nothing has to be
// downloaded; see tools/build_frontend.sh. NM can be overridden with JTWAF_NODE_MODULES.
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const NM = process.env.JTWAF_NODE_MODULES || '/opt/jt-ipam/frontend/node_modules'
const here = path.dirname(fileURLToPath(import.meta.url))
const { default: vue } = await import(path.join(NM, '@vitejs/plugin-vue/dist/index.mjs'))

export default {
  root: here,
  base: '/',
  plugins: [vue()],
  define: {
    __VUE_OPTIONS_API__: 'false',
    __VUE_PROD_DEVTOOLS__: 'false',
    __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: 'false',
  },
  resolve: {
    alias: {
      vue: path.join(NM, 'vue/dist/vue.runtime.esm-bundler.js'),
      'vue-router': path.join(NM, 'vue-router/dist/vue-router.mjs'),
      '@iconoir/vue': path.join(NM, '@iconoir/vue/dist/esm/index.mjs'),
    },
  },
  build: {
    target: 'es2022',
    outDir: path.resolve(here, '../jtwafmgr/static'),
    emptyOutDir: true,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
    chunkSizeWarningLimit: 600,
  },
}
