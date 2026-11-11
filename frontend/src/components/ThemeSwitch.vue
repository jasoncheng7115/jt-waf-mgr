<!-- Follow the system / light / dark (per browser). -->
<template>
  <div class="seg themeswitch" role="radiogroup" :aria-label="t('theme.label')">
    <button v-for="v in THEMES" :key="v" type="button" role="radio" :aria-checked="theme === v ? 'true' : 'false'"
            :class="{ on: theme === v }" :title="t('theme.' + v)" :aria-label="t('theme.' + v)" @click="setTheme(v)">
      <Icon :name="v" />
    </button>
  </div>
</template>

<script setup>
import { t } from '../i18n.js'
import { theme, setTheme, THEMES } from '../theme.js'
import Icon from './Icon.vue'
</script>
