// The rows of a list inside the time range picked on its RowTimeline (all rows when none is picked).
export function inWindow(rows, key, win) {
  if (!win) return rows
  return rows.filter((r) => { const ms = new Date(r[key]).getTime(); return ms >= win.since && ms < win.until })
}
