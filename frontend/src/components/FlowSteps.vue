<!-- A process drawn as steps: titles only -> one row of boxes with arrows (wraps on narrow screens); with
     descriptions -> a vertical timeline (number, title, description per line), which never wraps awkwardly. Used as guidance on every page that
     is part of a workflow, and with `current` / per-step state to show where an item stands.
     steps: [{ key, label, desc?, icon?, state?: 'done' | 'current' | 'todo' | 'fail' | 'skip', to? }] -->
<template>
  <figure class="flowsteps" :class="{ compact, detailed: !compact && steps.some((x) => x.desc) }">
    <figcaption v-if="title" class="fs-title"><Icon name="guide" />{{ title }}</figcaption>
    <ol class="fs-list">
      <li v-for="(s, i) in steps" :key="s.key" class="fs-step" :class="'st-' + (s.state || 'todo')" :aria-current="s.state === 'current' ? 'step' : null">
        <div class="fs-box">
          <span class="fs-num" aria-hidden="true"><Icon v-if="s.state === 'done'" name="check" /><Icon v-else-if="s.state === 'fail'" name="close" /><template v-else>{{ i + 1 }}</template></span>
          <div class="fs-body">
            <div class="fs-label"><Icon v-if="s.icon" :name="s.icon" /><RouterLink v-if="s.to" :to="s.to">{{ s.label }}</RouterLink><template v-else>{{ s.label }}</template></div>
            <div v-if="s.desc && !compact" class="fs-desc">{{ s.desc }}</div>
          </div>
        </div>
        <span v-if="i < steps.length - 1" class="fs-arrow" aria-hidden="true"><Icon name="next" /></span>
      </li>
    </ol>
    <p v-if="note" class="fs-note"><Icon name="info" />{{ note }}</p>
  </figure>
</template>

<script setup>
import Icon from './Icon.vue'
defineProps({ steps: { type: Array, required: true }, title: { type: String, default: '' }, note: { type: String, default: '' }, compact: Boolean })
</script>
