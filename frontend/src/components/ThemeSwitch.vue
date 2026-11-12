<!-- Follow the system / light / dark (per browser): one icon (the current choice) that opens the menu. -->
<template>
  <IconMenu class="themeswitch" :icon="theme" :title="t('theme.label') + ': ' + t('theme.' + theme)" :model-value="theme"
            :options="THEMES.map((v) => ({ value: v, label: t('theme.' + v), icon: v }))" @change="setTheme" />
</template>

<script setup>
import { t } from '../i18n.js'
import { theme, setTheme, THEMES } from '../theme.js'
import IconMenu from './IconMenu.vue'
</script>
