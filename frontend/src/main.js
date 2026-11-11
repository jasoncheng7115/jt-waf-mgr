import { createApp } from 'vue'
import App from './App.vue'
import { router } from './router.js'
import { state, setSession } from './store.js'
import { get, setUnauthenticatedHandler, setSetupRequiredHandler } from './api.js'
import { setLang } from './i18n.js'
import './theme.js'
import './style.css'

setUnauthenticatedHandler(() => {
  const cur = router.currentRoute.value
  if (cur.name !== 'login') router.replace({ name: 'login', query: cur.fullPath && cur.fullPath !== '/' ? { next: cur.fullPath } : {} })
})

// The server says the account still has a mandatory step: refresh the user and let the guard route.
setSetupRequiredHandler(async (code) => {
  try { setSession(await get('/auth/me')) } catch { /* 401 handler covers it */ }
  if (state.user) {
    if (code === 'password_change_required') state.user.must_change_password = true
    if (code === 'totp_setup_required') state.user.totp_setup_required = true
  }
  router.replace({ name: code === 'password_change_required' ? 'change-password' : 'setup-totp' })
})

async function boot() {
  try {
    state.meta = Object.assign({}, state.meta, await get('/meta'))
  } catch { /* footer shows without a version */ }
  try {
    const me = await get('/auth/me', null, { quiet401: true })
    setSession(me)
    if (me && me.user && me.user.language) setLang(me.user.language)
  } catch { /* not logged in */ }
  state.ready = true
  const app = createApp(App)
  app.use(router)
  app.mount('#app')
}

boot()
