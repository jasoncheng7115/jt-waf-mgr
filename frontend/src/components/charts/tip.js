// One hover / focus tooltip per chart. Values lead, labels follow; everything is rendered as text.
import { reactive } from 'vue'

export function useTip() {
  const tip = reactive({ show: false, x: 0, y: 0, title: '', rows: [], below: false })
  function at(e, title, rows, opts) {
    let x, y
    if (e && e.clientX !== undefined && e.type !== 'focus') { x = e.clientX; y = e.clientY }
    else if (e && e.target && e.target.getBoundingClientRect) {
      const r = e.target.getBoundingClientRect(); x = r.left + r.width / 2; y = r.top
    }
    if (opts && opts.y !== undefined) y = opts.y
    Object.assign(tip, { show: true, x, y, title, rows, below: !!(opts && opts.below) })
  }
  function hide() { tip.show = false }
  return { tip, at, hide }
}
