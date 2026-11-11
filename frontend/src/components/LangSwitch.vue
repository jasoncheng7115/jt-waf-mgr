<template>
  <SelectBox class="langswitch" small :model-value="lang" :options="options" :aria-label="t('app.language')" @change="change" />
</template>

<script setup>
import { computed } from 'vue'
import { lang, setLang, LANGUAGES, t } from '../i18n.js'
import { state } from '../store.js'
import { patch } from '../api.js'
import SelectBox from './SelectBox.vue'

const options = computed(() => LANGUAGES.map((l) => ({ value: l.code, label: l.label, icon: 'globe' })))

async function change(code) {
  setLang(code)
  if (state.user) {
    try {
      const u = await patch('/auth/me', { language: code })
      if (u && u.username) state.user = u
      else if (u && u.user) state.user = u.user
    } catch { /* language still applies locally */ }
  }
}
</script>
