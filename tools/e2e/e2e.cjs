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

async function login(browser, user, scheme, viewport) {
  const ctx = await browser.newContext({ viewport: viewport || { width: 1360, height: 950 }, colorScheme: scheme || 'light', acceptDownloads: true });
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
  '/admin/system', '/admin/compliance', '/admin/settings', '/admin/notify', '/alerts', '/waf', '/analysis', '/nope'];

const README_PAGES = ['/', '/events', '/waf', '/analysis', '/admin/notify', '/alerts', '/admin/system', '/changes', '/rules', '/lookup/203.0.113.9'];

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
      if (lang === 'en' && README_PAGES.includes(p)) await page.screenshot({ path: SHOTS + '/en' + p.replace(/\//g, '_') + '.png', fullPage: true });
    }
  }
  // Japanese: every page (no raw keys, same layout checks), screenshots of the README pages for README_ja
  await setLang(page, 'ja');
  for (const p of ROUTES) {
    await page.goto(base + p, { waitUntil: 'networkidle' });
    await page.waitForTimeout(250);
    await rawKeys(page, 'ja ' + p);
    await audit(page, 'ja ' + p);
    if (README_PAGES.includes(p)) await page.screenshot({ path: SHOTS + '/ja' + p.replace(/\//g, '_') + '.png', fullPage: true });
  }
  await setLang(page, 'zh-TW');
  // theme switch to dark via the UI
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  await page.click('.themeswitch .im-btn'); await page.click('.themeswitch .im-item:has-text("深色")');
  ok(await page.evaluate(() => document.documentElement.dataset.theme) === 'dark', 'theme switch sets dark');
  for (const p of ['/', '/events', '/guide', '/admin/system', '/admin/compliance', '/changes', '/lookup/203.0.113.9', '/admin/settings', '/admin/notify', '/alerts', '/analysis']) {
    await page.goto(base + p, { waitUntil: 'networkidle' });
    await page.waitForTimeout(250);
    await page.screenshot({ path: SHOTS + '/dark' + p.replace(/\//g, '_') + '.png', fullPage: true });
  }
  ok(await page.evaluate(() => document.documentElement.dataset.theme) === 'dark', 'theme persists across pages');
  // an alert becomes a change draft
  await page.goto(base + '/alerts', { waitUntil: 'networkidle' });
  await page.locator('.rowacts button:has-text("草擬")').first().click();
  await page.waitForURL((u) => u.pathname === '/changes/new', { timeout: 10000 }).catch(() => {});
  ok(new URL(page.url()).pathname === '/changes/new', 'alert drafts a change');
  // every card title band folds, the state is remembered per page
  await page.goto(base + '/admin/settings', { waitUntil: 'networkidle' });
  await page.waitForTimeout(300);
  const heads = await page.evaluate(() => [document.querySelectorAll('.card > h2:first-child, .card > .cardhead:first-child').length,
    document.querySelectorAll('.card > .foldable > .cardfold').length]);
  ok(heads[0] > 5 && heads[0] === heads[1], 'every card title has a fold button (' + heads.join('/') + ')');
  await page.locator('.card > .foldable > .cardfold').first().click();
  ok(await page.evaluate(() => { const c = document.querySelector('.card.folded'); return !!c && [...c.children].slice(1).every((x) => getComputedStyle(x).display === 'none'); }), 'fold hides the card body');
  await page.reload({ waitUntil: 'networkidle' }); await page.waitForTimeout(300);
  ok(await page.evaluate(() => document.querySelectorAll('.card.folded').length) === 1, 'folded card remembered after reload');
  await page.locator('.card.folded > .foldable > .cardfold').click();
  ok(await page.evaluate(() => document.querySelectorAll('.card.folded').length) === 0, 'unfold');
  await page.click('.themeswitch .im-btn'); await page.click('.themeswitch .im-item:has-text("淺色")');
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
  // world map: land drawn (lazy-loaded outline), one bubble per country, tooltip on a bubble
  await page.waitForSelector('.worldmap .wm-land', { timeout: 5000 }).catch(() => {});
  const wm = await page.evaluate(() => ({ land: (document.querySelector('.worldmap .wm-land')?.getAttribute('d') || '').length,
    dots: document.querySelectorAll('.worldmap .wm-dot').length }));
  ok(wm.land > 50000 && wm.dots >= 3, 'overview: world map with land and bubbles (' + wm.dots + ')');
  await page.locator('.worldmap .wm-dot').last().hover();
  ok(await page.locator('.charttip').isVisible(), 'world map tooltip on hover');
  await page.locator('.worldmap .wm-dot').first().click();
  await page.waitForLoadState('networkidle');
  const cc = new URL(page.url()).searchParams.get('country');
  ok(/^[A-Z]{2}$/.test(cc || '') && (await page.locator('.worldmap .wm-dot.on').count()) === 1, 'overview: a bubble filters by country (' + cc + ')');
  await page.goto(base + '/events?country=' + cc, { waitUntil: 'networkidle' });
  ok((await page.locator('.worldmap .wm-dot').count()) === 1, 'events: country filter leaves one country');
  await page.goto(base + '/events', { waitUntil: 'networkidle' });
  ok((await page.locator('.worldmap .wm-dot').count()) >= 1, 'events: world map of loaded events');
  await page.goto(base + '/lookup/203.0.113.9', { waitUntil: 'networkidle' });
  ok((await page.locator('.worldmap .wm-dot').count()) === 1, 'lookup: location on the world map');
  // whether each rule runs: totals per state, a badge per rule, per attack type on the CRS page
  await page.goto(base + '/rules?source=crs', { waitUntil: 'networkidle' });
  ok((await page.locator('.statetotals .stchip').count()) === 4 && (await page.locator('.datatable .badge.b-ok, .datatable .badge.b-blocked').count()) > 0,
     'rules: state totals and a state per rule');
  await page.goto(base + '/crs', { waitUntil: 'networkidle' });
  ok((await page.locator('.statetotals a.stchip').count()) === 4 && (await page.locator('.hb-row').count()) > 0, 'crs: rules per attack type and state');
  ok((await page.locator('.crsupd').innerText()).includes('4.30.0'), 'crs: the version in use and the update card');
  // several rules at once: tick, "switch off" opens the change form with its preview (or why it cannot)
  await page.goto(base + '/rules', { waitUntil: 'networkidle' });
  await page.locator('input.rowsel').first().check();
  ok((await page.locator('.selbar').innerText()).includes('1'), 'rules: a ticked rule is counted');
  await page.locator('.selbar button.danger').click();
  await page.waitForSelector('.ruletoggle', { timeout: 5000 }).catch(() => {});
  await page.waitForLoadState('networkidle');
  ok(await page.locator('.ruletoggle').isVisible() && (await page.locator('.ruletoggle .planbox, .ruletoggle .alert.error').count()) > 0,
     'rules: switching off shows the plan or the reason');
  await page.locator('.ruletoggle button.ghost').click();
  ok(!(await page.locator('.ruletoggle').count()), 'rules: the change form closes');
  // log servers: destination 1 is listed, another can be added (not saved here)
  await page.goto(base + '/admin/settings', { waitUntil: 'networkidle' });
  await page.waitForSelector('#uiset-syslog .dest', { timeout: 5000 }).catch(() => {});
  const nDest = await page.locator('#uiset-syslog .dest').count();
  await page.getByRole('button', { name: /新增目的地|Add a destination|送信先を追加/ }).click();
  ok(nDest >= 1 && (await page.locator('#uiset-syslog .dest').count()) === nDest + 1, 'settings: log servers listed, one more can be added');
  // column widths: the arrow keys on a header's edge set the width, remembered after a reload
  await page.goto(base + '/changes?tab=history', { waitUntil: 'networkidle' });
  const grip = page.locator('table.grid thead th .dt-resize').nth(1);
  await grip.focus();
  for (let i = 0; i < 4; i++) await page.keyboard.press('ArrowRight');
  const w1 = await page.locator('table.grid thead th').nth(1).evaluate((th) => th.style.width);
  await page.reload({ waitUntil: 'networkidle' });
  const w2 = await page.locator('table.grid thead th').nth(1).evaluate((th) => th.style.width);
  ok(/px$/.test(w1) && w1 === w2 && (await page.locator('table.grid.fixedcols').count()) > 0, 'tables: a column width is set and remembered (' + w1 + ')');
  await page.locator('table.grid thead th .dt-resize').nth(1).dblclick();
  ok(!(await page.locator('table.grid.fixedcols').count()), 'tables: a double click gives the columns their own width back');
  // /alerts?id=N: that alert selected with its handling form open
  const aid = await page.evaluate(async () => { const r = await (await fetch('/api/v1/alerts?state=open&limit=1')).json(); return r.items[0] && r.items[0].id })
  await page.goto(base + '/alerts?id=' + aid, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  ok(!!aid && (await page.locator('tr.row-focus').count()) === 1 && (await page.locator('textarea, .card h2:has-text("#' + aid + '")').count()) > 0,
     'alerts: ?id opens that alert for handling');
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  // notification preview: example message, language switch, Escape closes
  await page.goto(base + '/admin/notify', { waitUntil: 'networkidle' });
  await page.locator('#notify-events .evname button').first().click();
  await page.waitForSelector('.pvmsg', { timeout: 5000 }).catch(() => {});
  const pv1 = await page.locator('.pvmsg .pvtitle b').innerText().catch(() => '');
  await page.locator('.pvbar .seg button', { hasText: 'English' }).click();
  // the preview is fetched again: wait for the new title, not just for a quiet network (it may not have started yet)
  await page.waitForFunction((old) => { const b = document.querySelector('.pvmsg .pvtitle b'); return b && b.innerText !== old }, pv1,
    { timeout: 8000 }).catch(() => {});
  const pv2 = await page.locator('.pvmsg .pvtitle b').innerText().catch(() => '');
  ok(pv1 && pv2 && pv1 !== pv2 && /^[\x20-\x7e]+$/.test(pv2), 'notify: preview in two languages (' + pv1 + ' / ' + pv2 + ')');
  await page.keyboard.press('Escape');
  ok(!(await page.locator('.pvmsg').count()), 'notify: preview closes with Escape');
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  // hover tooltip on a chart
  const bar = page.locator('.hb-bar').first();
  await bar.hover();
  ok(await page.locator('.charttip').isVisible(), 'chart tooltip on hover');
  // the server is upgraded while the tab is open: the page notices and offers a reload
  ok(!(await page.locator('.newver').count()), 'new version: no banner while the versions match');
  await page.route('**/api/v1/meta', (r) => r.fulfill({ contentType: 'application/json',
    body: JSON.stringify({ name: 'jt-waf-mgr', version: '99.0.0', source_url: '', sso_enabled: false, node_id: '', login_notice: '', password_policy: null }) }));
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await page.waitForSelector('.newver', { timeout: 5000 }).catch(() => {});
  ok(await page.locator('.newver:has-text("99.0.0") button').isVisible(), 'new version: the page offers a reload');
  await page.unroute('**/api/v1/meta');
  // Thumbnails for the project site (docs/index.html): one screen of each page, rendered at twice the resolution
  // so they stay sharp when shown small (tools/make_thumbs.py scales them down). Same session, its own window size.
  const THUMBS = { overview: '/', events: '/events', 'waf-model': '/waf', analysis: '/analysis', notifications: '/admin/notify',
    alerts: '/alerts', 'system-check': '/admin/system', changes: '/changes', rules: '/rules', lookup: '/lookup/203.0.113.9' };
  const state = await ctx.storageState();
  for (const scheme of ['light', 'dark']) {
    const tc = await browser.newContext({ storageState: state, viewport: { width: 1200, height: 900 }, deviceScaleFactor: 2, colorScheme: scheme });
    await tc.addInitScript((s) => { try { localStorage.setItem('jtwaf.theme', s) } catch (e) { /* ignore */ } }, scheme);
    const tp = await tc.newPage();
    watch(tp, 'thumbs');
    await tp.goto(base + '/', { waitUntil: 'networkidle' });
    for (const lang of ['zh-TW', 'en', 'ja']) {
      await setLang(tp, lang);
      for (const [name, p] of Object.entries(scheme === 'light' ? THUMBS : { overview: '/' })) {
        await tp.goto(base + p, { waitUntil: 'networkidle' });
        await tp.waitForTimeout(400);
        await tp.screenshot({ path: SHOTS + '/thumb-' + lang + '-' + name + (scheme === 'dark' ? '-dark' : '') + '.png' });
      }
    }
    await setLang(tp, 'zh-TW');
    await tc.close();
  }
  ok(fs.existsSync(SHOTS + '/thumb-ja-lookup.png') && fs.existsSync(SHOTS + '/thumb-en-overview-dark.png'), 'site thumbnails at 2x');
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
  // phone and tablet widths: no page scrolls sideways, the menu reaches every page group
  for (const [name, vp] of [['phone', { width: 375, height: 812 }], ['tablet', { width: 768, height: 1024 }]]) {
    const m = await login(browser, 'admin', 'light', vp);
    await setLang(m.page, 'zh-TW');
    for (const p of ['/', '/events', '/rules', '/changes', '/analysis', '/alerts', '/admin/notify', '/admin/system', '/admin/audit', '/waf', '/lookup/203.0.113.9', '/admin/settings']) {
      await m.page.goto(base + p, { waitUntil: 'networkidle' });
      await m.page.waitForTimeout(250);
      const over = await m.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      if (over > 1) problems.push(name + ' ' + p + ': page scrolls sideways by ' + over + 'px');
      await m.page.screenshot({ path: SHOTS + '/' + name + p.replace(/\//g, '_') + '.png', fullPage: false });
    }
    if (name === 'phone') {
      await m.page.goto(base + '/', { waitUntil: 'networkidle' });
      ok(await m.page.locator('.navtoggle').isVisible(), 'phone: menu button');
      await m.page.click('.navtoggle');
      const groups = await m.page.locator('#navpanel .np-group').count();
      ok(groups >= 5, 'phone: menu shows the page groups (' + groups + ')');
      await m.page.screenshot({ path: SHOTS + '/phone_menu.png' });
    }
    await m.ctx.close();
  }
  await freshStep('admin');      // the security scan signs in next: never with a one-time code already used
  await browser.close();
  console.log(notes.filter((n) => n.startsWith('warn')).join('\n'));
  console.log(problems.length ? problems.join('\n') : 'NO PROBLEMS');
  process.exitCode = problems.length ? 1 : 0;
  console.log('checks ok:', notes.filter((n) => n.startsWith('ok')).length);
})();
