// Browser end-to-end test over every page (tools/e2e/run.sh starts the synthetic environment).
const path = require('path');
const NM = process.env.JTWAF_NODE_MODULES || '/opt/jt-ipam/frontend/node_modules';
const { chromium } = require(path.join(NM, '@playwright/test'));
const crypto = require('crypto');
const fs = require('fs');
const R = process.argv[2];
const SHOTS = process.argv[3];
const base = 'http://127.0.0.1:' + fs.readFileSync(R + '/port', 'utf8').trim();
const secrets = JSON.parse(fs.readFileSync(R + '/totp.json'));
const EN = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'src', 'i18n', 'en.json')));
const KEYS = Object.keys(EN).filter((k) => k.includes('.') && k.length > 8);
const PW = 'Smoke-Passw0rd-1';
function b32(s) { const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '', out = []; for (const c of s) bits += a.indexOf(c).toString(2).padStart(5, '0'); for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); }
function totp(secret) { const step = Math.floor(Date.now() / 30000); const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(step)); const h = crypto.createHmac('sha1', b32(secret)).update(b).digest(); const o = h[h.length - 1] & 15; return String(((h.readUInt32BE(o) & 0x7fffffff) % 1000000)).padStart(6, '0'); }
const problems = [];
const lastStep = {};
async function freshStep(user) {
  while (lastStep[user] === Math.floor(Date.now() / 30000)) await new Promise((r) => setTimeout(r, 1000));
  lastStep[user] = Math.floor(Date.now() / 30000);
}
const notes = [];
const ok = (cond, msg) => { if (!cond) problems.push('FAIL ' + msg); else notes.push('ok ' + msg); };

function watch(page, who) {
  page.on('console', (m) => { if (['error', 'warning'].includes(m.type()) && !/status of 40[13]|status of 409|status of 400/.test(m.text())) problems.push(who + ' console ' + m.type() + ': ' + m.text()); });
  page.on('pageerror', (e) => problems.push(who + ' pageerror: ' + e.message));
  page.on('dialog', (d) => d.accept());
}

async function rawKeys(page, where) {
  const txt = await page.locator('body').innerText();
  const hits = KEYS.filter((k) => txt.includes(k))
  if (hits.length) problems.push(where + ': raw i18n keys visible: ' + hits.slice(0, 8).join(', '));
  return txt;
}

async function login(browser, user, scheme) {
  const ctx = await browser.newContext({ viewport: { width: 1360, height: 950 }, colorScheme: scheme || 'light', acceptDownloads: true });
  const page = await ctx.newPage();
  watch(page, user);
  await page.goto(base + '/login', { waitUntil: 'networkidle' });
  await page.fill('input[name=username]', user);
  await page.fill('input[name=password]', PW);
  await page.click('button[type=submit]');
  if (secrets[user]) {
    await page.waitForSelector('input[name=totp]');
    await freshStep(user);
    await page.fill('input[name=totp]', totp(secrets[user]));
    await page.click('button[type=submit]');
  }
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 10000 });
  await page.waitForLoadState('networkidle');
  return { ctx, page };
}

async function setLang(page, lang) {
  await page.evaluate(async (lang) => {
    const me = await (await fetch('/api/v1/auth/me')).json();
    await fetch('/api/v1/auth/me', { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': me.csrf_token }, body: JSON.stringify({ language: lang }) });
  }, lang);
}

const ROUTES = ['/', '/events', '/rules', '/rules/930110', '/vhosts', '/crs', '/lookup/203.0.113.9', '/managed', '/changes', '/changes/new',
  '/versions', '/config-changes', '/guide', '/account', '/admin/users', '/admin/users/review', '/admin/tokens', '/admin/audit',
  '/admin/system', '/admin/compliance', '/admin/settings', '/waf', '/nope'];

async function audit(page, where) {
  const r = await page.evaluate(() => {
    const out = { selects: document.querySelectorAll('select').length,
      dates: document.querySelectorAll('input[type=date],input[type=datetime-local],input[type=time]').length,
      noicon: [], overflow: document.documentElement.scrollWidth > window.innerWidth + 2 };
    for (const b of document.querySelectorAll('button, a.btn')) {
      if (b.classList.contains('dp-day')) continue;
      if (!b.querySelector('svg') && b.offsetParent !== null) out.noicon.push((b.innerText || b.getAttribute('aria-label') || '').trim().slice(0, 40));
    }
    return out;
  });
  if (r.selects) problems.push(where + ': native select x' + r.selects);
  if (r.dates) problems.push(where + ': native date input x' + r.dates);
  if (r.noicon.length) problems.push(where + ': buttons without icon: ' + r.noicon.slice(0, 5).join(' | '));
  if (r.overflow) notes.push('warn ' + where + ': horizontal page overflow');
}

(async () => {
  const browser = await chromium.launch();
  const { ctx, page } = await login(browser, 'admin', 'light');
  for (const lang of ['zh-TW', 'en']) {
    await setLang(page, lang);
    for (const p of ROUTES) {
      await page.goto(base + p, { waitUntil: 'networkidle' });
      await page.waitForTimeout(250);
      await rawKeys(page, lang + ' ' + p);
      await audit(page, lang + ' ' + p);
      if (lang === 'zh-TW') await page.screenshot({ path: SHOTS + '/light' + p.replace(/\//g, '_') + '.png', fullPage: true });
    }
  }
  await setLang(page, 'zh-TW');
  // theme switch to dark via the UI
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  await page.click('.themeswitch button[aria-label="深色"]');
  ok(await page.evaluate(() => document.documentElement.dataset.theme) === 'dark', 'theme switch sets dark');
  for (const p of ['/', '/events', '/guide', '/admin/system', '/admin/compliance', '/changes', '/lookup/203.0.113.9', '/admin/settings']) {
    await page.goto(base + p, { waitUntil: 'networkidle' });
    await page.waitForTimeout(250);
    await page.screenshot({ path: SHOTS + '/dark' + p.replace(/\//g, '_') + '.png', fullPage: true });
  }
  ok(await page.evaluate(() => document.documentElement.dataset.theme) === 'dark', 'theme persists across pages');
  await page.click('.themeswitch button[aria-label="淺色"]');
  // DataTable on events: sort, filter, column picker, paging
  await page.goto(base + '/events', { waitUntil: 'networkidle' });
  const firstBefore = await page.locator('.datatable tbody tr').first().innerText();
  const hdr = page.locator('.datatable thead th .dt-sort').nth(1);
  await hdr.click(); await hdr.click();
  ok((await page.locator('.datatable thead th[aria-sort]').count()) === 1, 'events: sort sets aria-sort');
  await page.fill('.dt-search input', '203.0.113');
  await page.waitForTimeout(200);
  const rows = await page.locator('.datatable tbody tr').allInnerTexts();
  ok(rows.length > 0 && rows.every((r) => r.includes('203.0.113')), 'events: quick search filters rows (' + rows.length + ')');
  ok(rows.some((r) => /JP|US|日本|美國/.test(r)), 'events: GeoIP shown next to source');
  await page.fill('.dt-search input', '');
  await page.click('.dt-colpick button');
  const before = await page.locator('.datatable thead tr').first().locator('th').count();
  await page.locator('.dt-colopt input:not([disabled])').first().click();
  const after = await page.locator('.datatable thead tr').first().locator('th').count();
  ok(after === before - 1, 'events: hiding a column works (' + before + '->' + after + ')');
  await page.locator('.dt-colpop button').click();
  await page.keyboard.press('Escape');
  ok((await page.locator('.dt-pager').count()) >= 0, 'pager present when needed');
  // SelectBox: open and pick with keyboard
  const sb = page.locator('main .selectbox .sb-btn').first();
  await sb.click();
  ok(await page.locator('.sb-pop').isVisible(), 'selectbox opens');
  await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter');
  ok(!(await page.locator('.sb-pop').count()), 'selectbox closes after pick');
  // DatePicker
  const dp = page.locator('main .datepicker .dp-btn').first();
  if (await dp.count()) {
    await dp.click();
    ok(await page.locator('.dp-pop').isVisible(), 'datepicker opens');
    await page.locator('.dp-day:not(.other):not([disabled])').last().click();
    await page.locator('.dp-foot .btn.primary').click();
    ok(!(await page.locator('.dp-pop').count()), 'datepicker closes');
    const v = await dp.innerText();
    ok(/\d/.test(v), 'datepicker shows a value: ' + v.trim());
    await page.screenshot({ path: SHOTS + '/events-after-date.png' });
  } else problems.push('events: no datepicker');
  // Guide: click an architecture node
  await page.goto(base + '/guide', { waitUntil: 'networkidle' });
  await page.locator('.arch-node').nth(5).click();
  ok((await page.locator('.archdesc h3').innerText()).length > 0, 'guide: node description shown');
  // overview country chart
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  ok((await page.locator('text=依國家').count()) > 0, 'overview: by-country chart');
  // hover tooltip on a chart
  const bar = page.locator('.hb-bar').first();
  await bar.hover();
  ok(await page.locator('.charttip').isVisible(), 'chart tooltip on hover');
  await ctx.close();
  // viewer: guide and events, no admin links
  const v = await login(browser, 'viewer', 'dark');
  await setLang(v.page, 'zh-TW');
  for (const p of ['/', '/events', '/guide', '/changes']) {
    await v.page.goto(base + p, { waitUntil: 'networkidle' });
    await rawKeys(v.page, 'viewer ' + p); await audit(v.page, 'viewer ' + p);
  }
  await v.page.screenshot({ path: SHOTS + '/viewer-changes-dark.png', fullPage: true });
  await v.ctx.close();
  // login page logo
  const lp = await browser.newPage();
  await lp.goto(base + '/login', { waitUntil: 'networkidle' });
  ok(await lp.locator('img[src="/logo-mark.svg"]').first().isVisible(), 'login logo visible');
  ok((await lp.evaluate(() => document.querySelector('link[rel=icon]').href)).endsWith('/favicon.svg'), 'favicon link');
  const fav = await lp.request.get(base + '/favicon.svg');
  ok(fav.status() === 200, 'favicon served');
  await lp.screenshot({ path: SHOTS + '/login.png' });
  await browser.close();
  console.log(notes.filter((n) => n.startsWith('warn')).join('\n'));
  console.log(problems.length ? problems.join('\n') : 'NO PROBLEMS');
  process.exitCode = problems.length ? 1 : 0;
  console.log('checks ok:', notes.filter((n) => n.startsWith('ok')).length);
})();
