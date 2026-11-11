<template>
  <div class="page">
    <h1>{{ t('notfound.title') }}</h1>
    <p><RouterLink class="btn" to="/"><Icon name="back" />{{ t('nav.overview') }}</RouterLink></p>
  </div>
</template>

<script setup>
import { t } from '../i18n.js'
import Icon from '../components/Icon.vue'
</script>
