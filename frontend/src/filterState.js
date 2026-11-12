// Filter forms: which conditions are applied (shown in colour) and which were changed but not applied yet (the
// field is marked and the Apply button asks to be pressed).
//   form: the reactive form; applied(): the applied values in the same shape (from the URL);
//   defaults: values that mean "no condition" (e.g. rules source "local").
import { computed } from 'vue'

export function useFilterState(form, applied, defaults = {}) {
  const norm = (v) => (v === null || v === undefined ? '' : String(v))
  const dirtyKeys = computed(() => {
    const a = applied()
    return Object.keys(form).filter((k) => norm(form[k]) !== norm(a[k]))
  })
  const dirty = computed(() => dirtyKeys.value.length > 0)
  function fieldClass(k) {
    const a = norm(applied()[k])
    const changed = dirtyKeys.value.includes(k)
    return { 'f-dirty': changed, 'f-applied': !changed && a !== '' && a !== norm(defaults[k]) }
  }
  return { dirty, fieldClass }
}
