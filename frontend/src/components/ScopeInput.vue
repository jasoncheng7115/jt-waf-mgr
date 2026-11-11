<template>
  <div class="scope">
    <div class="field"><span><label :for="uid">{{ label }}</label></span>
      <SelectBox :id="uid" :model-value="modelValue.mode || 'any'" :disabled="disabled"
                 :options="modes.map((m) => ({ value: m, label: t('scope_mode.' + m) }))" @update:model-value="update('mode', $event)" />
    </div>
    <label v-if="(modelValue.mode || 'any') !== 'any'" class="field grow"><span>&nbsp;</span>
      <input :value="modelValue.value || ''" :disabled="disabled" maxlength="512" spellcheck="false" :placeholder="placeholder"
             :aria-label="label" class="mono" @input="update('value', $event.target.value)">
    </label>
  </div>
</template>

<script setup>
import { useId } from 'vue'
import { t } from '../i18n.js'
import SelectBox from './SelectBox.vue'

const props = defineProps({
  modelValue: { type: Object, default: () => ({ mode: 'any', value: '' }) },
  modes: { type: Array, default: () => ['any', 'exact', 'regex'] },
  label: { type: String, default: '' },
  placeholder: { type: String, default: '' },
  disabled: Boolean,
})
const emit = defineEmits(['update:modelValue'])
const uid = 'scope-' + useId()
function update(k, v) {
  emit('update:modelValue', Object.assign({}, props.modelValue, { [k]: v }))
}
</script>
