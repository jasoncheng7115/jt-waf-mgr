<template>
  <div class="authbox">
    <div class="authhead">
      <img class="authlogo" src="/logo-mark.svg" alt="" width="72" height="72">
      <h1 class="authtitle">jt-waf-mgr</h1>
      <p class="muted">{{ t('login.subtitle') }}</p>
    </div>
    <div v-if="state.meta.login_notice" class="alert info loginnotice" role="note">{{ safeMultiline(state.meta.login_notice) }}</div>
    <form class="form" autocomplete="on" @submit.prevent="submit">
      <template v-if="!needTotp">
        <label class="field">
          <span>{{ t('login.username') }}</span>
          <input v-model.trim="username" name="username" autocomplete="username" required autofocus maxlength="64">
        </label>
        <label class="field">
          <span>{{ t('login.password') }}</span>
          <input v-model="password" name="password" type="password" autocomplete="current-password" required maxlength="1024">
        </label>
      </template>
      <label v-else class="field">
        <span>{{ t('login.totp') }}</span>
        <input ref="totpEl" v-model.trim="totp" name="totp" inputmode="numeric" autocomplete="one-time-code"
               pattern="[0-9]{6}" maxlength="6" required>
        <small class="muted">{{ t('login.totp_hint') }}</small>
      </label>
      <div v-if="message" class="alert error" role="alert">{{ message }}</div>
      <div class="actions">
        <button type="submit" class="btn primary" :disabled="busy"><Icon name="login" />{{ busy ? t('common.working') : t('login.submit') }}</button>
        <button v-if="needTotp" type="button" class="btn ghost" @click="restart"><Icon name="back" />{{ t('common.back') }}</button>
      </div>
    </form>
  </div>
</template>

<script setup>
import { ref, nextTick, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { post } from '../api.js'
import { state, setSession } from '../store.js'
import { safeMultiline } from '../util.js'
import { t, errText, setLang } from '../i18n.js'
import { safeNext } from '../router.js'
import Icon from '../components/Icon.vue'

const route = useRoute()
const router = useRouter()
const username = ref('')
const password = ref('')
const totp = ref('')
const needTotp = ref(false)
const busy = ref(false)
const message = ref('')
const totpEl = ref(null)
let timer = null

async function submit() {
  busy.value = true
  message.value = ''
  try {
    const body = { username: username.value, password: password.value }
    if (needTotp.value) body.totp = totp.value
    const data = await post('/auth/login', body)
    password.value = ''
    totp.value = ''
    setSession(data)
    state.lastLogin = data.previous_login ? Object.assign({ navs: 0 }, data.previous_login) : null
    if (data.user && data.user.language) setLang(data.user.language)
    if (data.user && data.user.must_change_password) router.replace({ name: 'change-password' })
    else if (data.user && data.user.totp_setup_required) router.replace({ name: 'setup-totp' })
    else router.replace(safeNext(route.query.next))
  } catch (e) {
    if (e.code === 'totp_required') {
      needTotp.value = true
      await nextTick()
      if (totpEl.value) totpEl.value.focus()
    } else {
      if (e.code === 'totp_invalid') totp.value = ''
      message.value = errText(e)
      if (e.code === 'too_many_attempts' && e.details && e.details.retry_after) countdown(Number(e.details.retry_after))
    }
  } finally {
    busy.value = false
  }
}

function countdown(sec) {
  clearInterval(timer)
  let left = sec
  timer = setInterval(() => {
    left -= 1
    if (left <= 0) { clearInterval(timer); message.value = ''; return }
    message.value = errText({ code: 'too_many_attempts', details: { retry_after: left } })
  }, 1000)
}

function restart() {
  needTotp.value = false
  totp.value = ''
  password.value = ''
  message.value = ''
}

onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.authhead { display: flex; flex-direction: column; align-items: center; gap: 8px; text-align: center; }
.authlogo { display: block; width: 72px; height: 72px; }
</style>
