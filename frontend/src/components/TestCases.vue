<template>
  <div class="testcases">
    <div v-for="(tc, i) in modelValue" :key="i" class="tcase">
      <div class="filters inline">
        <div class="field"><span><label :for="uid + '-x' + i">{{ t('tests.expect') }}</label></span>
          <SelectBox :id="uid + '-x' + i" :model-value="tc.expect" :disabled="disabled" :options="expectOptions" @update:model-value="set(i, 'expect', Number($event))" />
        </div>
        <div class="field"><span><label :for="uid + '-s' + i">{{ t('tests.source') }}</label></span>
          <SelectBox :id="uid + '-s' + i" :model-value="tc.source" :disabled="disabled" :options="sourceOptions" @update:model-value="set(i, 'source', $event)" />
        </div>
        <div class="field"><span><label :for="uid + '-m' + i">{{ t('tests.method') }}</label></span>
          <SelectBox :id="uid + '-m' + i" :model-value="tc.method || 'GET'" :disabled="disabled" :options="METHODS" @update:model-value="set(i, 'method', $event)" />
        </div>
        <label class="field"><span>{{ t('tests.host') }}</span>
          <input :value="tc.host" :disabled="disabled" class="mono" maxlength="255" required :placeholder="disabled ? '' : 'app.example.com'" @input="set(i, 'host', $event.target.value.trim())">
        </label>
        <label class="field grow"><span>{{ t('tests.path') }}</span>
          <input :value="tc.path" :disabled="disabled" class="mono" maxlength="2048" required :placeholder="disabled ? '' : '/path?query'" @input="set(i, 'path', $event.target.value)">
        </label>
      </div>
      <div class="filters inline">
        <label class="field grow"><span>{{ t('tests.headers') }}</span>
          <textarea :value="headersText(tc)" :disabled="disabled" rows="2" class="mono" maxlength="4000" :placeholder="disabled ? '' : 'User-Agent: curl/8.0'" @input="setHeaders(i, $event.target.value)"></textarea>
        </label>
        <label class="field grow"><span>{{ t('tests.body') }}</span>
          <textarea :value="tc.body || ''" :disabled="disabled" rows="2" class="mono" maxlength="65536" :placeholder="disabled ? '' : 'a=1&b=2'" @input="set(i, 'body', $event.target.value || undefined)"></textarea>
        </label>
        <label class="field"><span>{{ t('tests.absent_rules') }}</span>
          <input :value="(tc.absent_rules || []).join(', ')" :disabled="disabled" class="mono" maxlength="200" :placeholder="disabled ? '' : '930120'" @change="set(i, 'absent_rules', ids($event.target.value))">
        </label>
      </div>
      <div class="actions"><button v-if="!disabled" type="button" class="btn small ghost" @click="remove(i)"><Icon name="delete" />{{ t('tests.remove') }}</button></div>
    </div>
    <div v-if="!modelValue.length" class="muted small">{{ t('tests.none') }}</div>
    <div v-if="!disabled" class="actions">
      <button type="button" class="btn small" @click="add"><Icon name="add" />{{ t('tests.add') }}</button>
    </div>
  </div>
</template>

<script setup>
import { computed, useId } from 'vue'
import { t } from '../i18n.js'
import Icon from './Icon.vue'
import SelectBox from './SelectBox.vue'

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const props = defineProps({
  modelValue: { type: Array, default: () => [] },
  defaultHost: { type: String, default: '' },
  disabled: Boolean,
})
const emit = defineEmits(['update:modelValue'])
const uid = 'tc-' + useId()
const expectOptions = computed(() => [
  { value: 403, label: '403 ' + t('tests.blocked'), icon: 'block' },
  { value: 200, label: '200 ' + t('tests.allowed'), icon: 'check' },
])
const sourceOptions = computed(() => [
  { value: 'external', label: t('origin.external') },
  { value: 'internal', label: t('origin.internal') },
])

function emitList(list) { emit('update:modelValue', list) }
function set(i, k, v) {
  const list = props.modelValue.map((x) => Object.assign({}, x))
  if (v === undefined) delete list[i][k]
  else list[i][k] = v
  emitList(list)
}
function add() {
  emitList(props.modelValue.concat([{ expect: 403, source: 'external', method: 'GET', host: props.defaultHost, path: '/' }]))
}
function remove(i) { emitList(props.modelValue.filter((_, j) => j !== i)) }
function headersText(tc) {
  return Object.entries(tc.headers || {}).map(([k, v]) => k + ': ' + v).join('\n')
}
function setHeaders(i, text) {
  const h = {}
  for (const line of String(text).split('\n')) {
    const p = line.indexOf(':')
    if (p > 0) h[line.slice(0, p).trim()] = line.slice(p + 1).trim()
  }
  set(i, 'headers', Object.keys(h).length ? h : undefined)
}
function ids(s) {
  return String(s).split(/[\s,]+/).filter((x) => /^\d{1,9}$/.test(x)).map(Number)
}
</script>
