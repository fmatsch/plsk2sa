'use strict';
(function () {

// ---------------------------------------------------------------------
// API access. The token arrives in the URL fragment and is moved to
// sessionStorage, then removed from the address bar.
// ---------------------------------------------------------------------
let token = null;
(function initToken() {
  const m = location.hash.match(/token=([\w-]+)/);
  try {
    if (m) {
      token = m[1];
      sessionStorage.setItem('plsk2sa-token', token);
      history.replaceState(null, '', location.pathname);
    } else {
      token = sessionStorage.getItem('plsk2sa-token');
    }
  } catch (e) { /* storage blocked: token only lives for this page load */ }
})();

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Plsk2sa-Token': token || '' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* non-JSON error */ }
  if (!res.ok) throw new Error(data.error || 'Request failed (' + res.status + ')');
  return data;
}

// ---------------------------------------------------------------------
// Small DOM helpers. Text is always inserted as text nodes, never as
// HTML: check results and domain names come from remote servers.
// ---------------------------------------------------------------------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (['checked', 'disabled', 'hidden', 'selected'].includes(k)) el[k] = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function fmtMb(mb) {
  if (mb == null) return '-';
  return mb >= 1024 ? (mb / 1024).toFixed(1) + ' GB' : Math.round(mb) + ' MB';
}
function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many || one + 's'); }

const ICON = { ok: '\u2713', warn: '!', fail: '\u2715', pending: '', skipped: '\u2013', running: '', done: '\u2713', failed: '\u2715' };
function statusIcon(status) {
  if (status === 'running') return h('span', { class: 'spinner' });
  const cls = status === 'done' ? 'ok' : status === 'failed' ? 'fail' : status;
  return h('span', { class: 'icon ' + cls }, ICON[status] || '');
}

function alertBox(kind, title, text) {
  return h('div', { class: 'alert ' + kind, role: kind === 'fail' ? 'alert' : 'status' },
    title ? h('strong', {}, title) : null, text || null);
}
function loading(text) { return h('div', { class: 'loading' }, h('span', { class: 'spinner' }), text); }

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const old = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => { button.textContent = old; }, 1500);
  } catch (e) { button.textContent = 'Select and copy manually'; }
}

// ---------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------
const STEPS = ['Plesk server', 'Checks', 'Select domains', 'Target server', 'Migrate'];
const S = {
  step: 0, maxStep: 0, demo: false,
  source: null, target: null,
  sourceReport: null, targetReport: null,
  selected: new Set(),
  mailHostname: '',
  forms: {
    source: { host: '', port: '22', user: 'root', auth: 'password', key_path: '' },
    target: { host: '', port: '22', user: 'root', auth: 'password', key_path: '' },
  },
  options: { mode: 'full', dry_run: true, restrict_ip: true, confirmed: false },
  dns: { mode: 'external', old_ips: '', new_ipv4: '', new_ipv6: '', prefilled: false },
  prepareSel: null,
  run: { state: 'idle', steps: [], next: 0, result: null, source_changes: [], source_state: 'unchanged' },
};
let pollTimer = null;

function persist() {
  try {
    sessionStorage.setItem('plsk2sa-ui', JSON.stringify({
      selected: [...S.selected], mailHostname: S.mailHostname, forms: S.forms,
      dns: S.dns, options: { mode: S.options.mode, dry_run: S.options.dry_run, restrict_ip: S.options.restrict_ip },
    }));
  } catch (e) { /* ignore */ }
}
function restoreLocal() {
  try {
    const saved = JSON.parse(sessionStorage.getItem('plsk2sa-ui') || 'null');
    if (!saved) return;
    S.selected = new Set(saved.selected || []);
    S.mailHostname = saved.mailHostname || '';
    for (const role of ['source', 'target']) Object.assign(S.forms[role], (saved.forms || {})[role] || {});
    Object.assign(S.dns, saved.dns || {});
    Object.assign(S.options, saved.options || {});
  } catch (e) { /* ignore */ }
}

function inventoryDomains() {
  return (S.sourceReport && S.sourceReport.inventory) ? S.sourceReport.inventory.domains : [];
}
function selectedDomains() { return inventoryDomains().filter(d => S.selected.has(d.name)); }
function runActive() { return S.run.state === 'running'; }

function gotoStep(n) {
  S.step = n;
  S.maxStep = Math.max(S.maxStep, n);
  render();
  window.scrollTo(0, 0);
  $main().focus({ preventScroll: true });
}
const $main = () => document.getElementById('main');

// ---------------------------------------------------------------------
// Stepper + render
// ---------------------------------------------------------------------
function renderStepper() {
  const nav = document.getElementById('stepper');
  nav.replaceChildren(...STEPS.map((name, i) => {
    const done = i < S.step || (i < S.maxStep && i !== S.step);
    const reachable = i <= S.maxStep && i !== S.step && !runActive();
    return h('button', {
      type: 'button',
      class: 'step' + (i === S.step ? ' active' : '') + (done ? ' done' : '') + (reachable ? ' reachable' : ''),
      'aria-current': i === S.step ? 'step' : null,
      disabled: !reachable && i !== S.step,
      onclick: reachable ? () => gotoStep(i) : null,
    }, h('span', { class: 'num' }, done && i !== S.step ? '\u2713' : String(i + 1)), name);
  }));
}

function render() {
  renderStepper();
  const views = [renderSource, renderChecks, renderSelect, renderTarget, renderRun];
  $main().replaceChildren(views[S.step]());
}

// ---------------------------------------------------------------------
// Connection form (shared by source and target)
// ---------------------------------------------------------------------
function connectionForm(role) {
  const f = S.forms[role];
  const bind = (key) => (e) => { f[key] = e.target.value; persist(); };

  const host = h('input', { type: 'text', id: role + '-host', value: f.host, autocomplete: 'off',
    spellcheck: 'false', placeholder: 'server.example.com or 203.0.113.10', oninput: bind('host') });
  const port = h('input', { type: 'number', id: role + '-port', value: f.port, min: '1', max: '65535', oninput: bind('port') });
  const user = h('input', { type: 'text', id: role + '-user', value: f.user, autocomplete: 'off',
    spellcheck: 'false', oninput: bind('user') });
  const password = h('input', { type: 'password', id: role + '-password', autocomplete: 'off' });
  const keyPath = h('input', { type: 'text', id: role + '-key', value: f.key_path, spellcheck: 'false',
    placeholder: '~/.ssh/id_ed25519   or   C:\\Users\\you\\.ssh\\id_ed25519', oninput: bind('key_path') });
  const passphrase = h('input', { type: 'password', id: role + '-passphrase', autocomplete: 'off' });

  const pwField = h('div', { class: 'field' }, h('label', { for: role + '-password' }, 'Password'), password);
  const keyField = h('div', {},
    h('div', { class: 'field' }, h('label', { for: role + '-key' }, 'Private key file'), keyPath),
    h('div', { class: 'field' }, h('label', { for: role + '-passphrase' }, 'Key passphrase (if the key is encrypted)'), passphrase));
  const agentField = h('p', { class: 'muted small' },
    'Uses a running SSH agent and the default keys in your ~/.ssh folder.');

  function syncAuth() {
    pwField.hidden = f.auth !== 'password';
    keyField.hidden = f.auth !== 'key';
    agentField.hidden = f.auth !== 'agent';
  }
  const radio = (value, label) => h('label', {},
    h('input', { type: 'radio', name: role + '-auth', value, checked: f.auth === value,
      onchange: () => { f.auth = value; persist(); syncAuth(); } }), label);

  const el = h('div', {},
    h('div', { class: 'grid three' },
      h('div', { class: 'field' }, h('label', { for: role + '-host' }, 'Host'), host),
      h('div', { class: 'field' }, h('label', { for: role + '-port' }, 'SSH port'), port),
      h('div', { class: 'field' }, h('label', { for: role + '-user' }, 'User'), user)),
    h('div', { class: 'field' }, h('span', { class: 'label' }, 'Sign in with'),
      h('div', { class: 'choice' }, radio('password', 'Password'), radio('key', 'Private key file'),
        radio('agent', 'SSH agent / default keys'))),
    pwField, keyField, agentField);
  syncAuth();

  return {
    el,
    values: () => ({ host: host.value.trim(), port: port.value, user: user.value.trim() || 'root',
      auth: f.auth, password: password.value, key_path: keyPath.value.trim(), passphrase: passphrase.value }),
    clearSecrets: () => { password.value = ''; passphrase.value = ''; },
  };
}

// Connect, asking the user to confirm an unknown host key if needed.
async function connectFlow(role, form, hostKeyBox, message) {
  let accept = null;
  for (;;) {
    const values = form.values();
    if (accept) values.accept_fingerprint = accept;
    const r = await api('POST', '/api/' + role + '/connect', values);
    if (r.ok) { form.clearSecrets(); return r.endpoint; }
    if (r.host_key) {
      message.replaceChildren();  // no spinner while we wait for the user
      accept = await askHostKey(r.host_key, hostKeyBox);
      if (!accept) return null;
      message.replaceChildren(loading('Connecting...'));
      continue;
    }
    throw new Error(r.error || 'Connection failed');
  }
}

function askHostKey(hk, box) {
  return new Promise((resolve) => {
    const done = (value) => { box.replaceChildren(); resolve(value); };
    box.replaceChildren(h('div', { class: 'alert warn', role: 'alertdialog' },
      h('strong', {}, 'First connection to ' + hk.host + ':' + hk.port),
      h('p', {}, 'Make sure this is really your server before you continue. Compare the fingerprint of its ',
        hk.key_type, ' host key with the one in your hosting provider\u2019s panel, or run ',
        h('code', {}, 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'), ' on the server.'),
      h('code', { class: 'fingerprint' }, hk.fingerprint),
      h('div', { class: 'actions' },
        h('button', { class: 'btn primary', type: 'button', onclick: () => done(hk.fingerprint) }, 'Trust and connect'),
        h('button', { class: 'btn', type: 'button', onclick: () => done(null) }, 'Cancel'))));
  });
}

// ---------------------------------------------------------------------
// Step 1: Plesk server
// ---------------------------------------------------------------------
function renderSource() {
  const form = connectionForm('source');
  const hostKeyBox = h('div');
  const message = h('div');
  const connect = h('button', { class: 'btn primary', type: 'button' }, 'Connect');

  connect.addEventListener('click', async () => {
    connect.disabled = true;
    message.replaceChildren(loading('Connecting...'));
    try {
      const endpoint = await connectFlow('source', form, hostKeyBox, message);
      if (!endpoint) { message.replaceChildren(); return; }
      S.source = endpoint;
      S.sourceReport = null; S.targetReport = null; S.target = null;
      S.selected = new Set(); persist();
      gotoStep(1);
    } catch (e) {
      message.replaceChildren(alertBox('fail', 'Could not connect', e.message));
    } finally { connect.disabled = false; }
  });

  return h('section', { class: 'card' },
    h('h1', {}, 'Connect to the Plesk server'),
    h('p', { class: 'lead' }, 'The server you are migrating away from. Its configuration, databases and files are ',
      'copied; nothing on it is modified or deleted. The only change is a temporary SSH key that lets the ',
      'target server pull the data directly - it is added during a real migration and removed again at the end. ',
      'The checks and the preview only read. You need root access.'),
    S.source ? alertBox('ok', 'Connected to ' + S.source.user + '@' + S.source.host,
      'You can continue with the checks, or connect to a different server below.') : null,
    form.el, hostKeyBox, message,
    h('div', { class: 'actions' }, connect,
      S.source ? h('button', { class: 'btn', type: 'button', onclick: () => gotoStep(1) }, 'Continue with this server') : null));
}

// ---------------------------------------------------------------------
// Check list (shared)
// ---------------------------------------------------------------------
function checkList(checks) {
  const fails = checks.filter(c => c.status === 'fail').length;
  const warns = checks.filter(c => c.status === 'warn').length;
  let summary;
  if (fails) summary = alertBox('fail', plural(fails, 'problem') + ' must be fixed before you can continue',
    'Fix the items marked \u2715 below, then run the checks again.');
  else if (warns) summary = alertBox('warn', plural(warns, 'warning'),
    'You can continue. Read the items marked ! so nothing surprises you later.');
  else summary = alertBox('ok', 'All checks passed');
  const list = h('ul', { class: 'checks' }, checks.map(c => h('li', {},
    statusIcon(c.status),
    h('div', {}, h('div', { class: 'check-title' }, c.title),
      c.detail ? h('div', { class: 'check-detail' }, c.detail) : null))));
  return h('div', {}, summary, list);
}

// ---------------------------------------------------------------------
// Step 2: checks on the Plesk server
// ---------------------------------------------------------------------
function renderChecks() {
  const body = h('div');
  const rerun = h('button', { class: 'btn', type: 'button' }, 'Run checks again');
  const next = h('button', { class: 'btn primary', type: 'button', disabled: true, onclick: () => gotoStep(2) }, 'Continue');

  function paint() {
    body.replaceChildren(checkList(S.sourceReport.checks));
    next.disabled = !S.sourceReport.can_continue;
    rerun.disabled = false;
  }
  async function run() {
    rerun.disabled = true; next.disabled = true;
    body.replaceChildren(loading('Running checks and reading your Plesk configuration - this can take a minute...'));
    try {
      S.sourceReport = await api('POST', '/api/source/checks');
      S.targetReport = null;
      const names = new Set(inventoryDomains().map(d => d.name));
      S.selected = new Set([...S.selected].filter(n => names.has(n)));
      if (!S.selected.size) S.selected = names;
      persist();
      paint();
    } catch (e) {
      body.replaceChildren(alertBox('fail', 'The checks could not run', e.message));
      rerun.disabled = false;
    }
  }
  rerun.addEventListener('click', run);
  if (S.sourceReport) paint(); else run();

  return h('section', { class: 'card' },
    h('h1', {}, 'Checking the Plesk server'),
    h('p', { class: 'lead' }, 'Connected as ' + S.source.user + '@' + S.source.host +
      '. These checks are read-only.'),
    body,
    h('div', { class: 'actions' },
      h('button', { class: 'btn', type: 'button', onclick: () => gotoStep(0) }, 'Back'),
      rerun, h('span', { class: 'spacer' }), next));
}

// ---------------------------------------------------------------------
// Step 3: choose domains / subscriptions
// ---------------------------------------------------------------------
function renderSelect() {
  const domains = inventoryDomains();
  const groups = new Map();
  for (const d of domains) {
    if (!groups.has(d.subscription)) groups.set(d.subscription, []);
    groups.get(d.subscription).push(d);
  }
  const footer = h('span', { class: 'muted' });
  const next = h('button', { class: 'btn primary', type: 'button', onclick: () => gotoStep(3) }, 'Continue');
  const boxes = new Map();   // domain name -> checkbox
  const groupBoxes = [];     // [checkbox, [domains]]

  const domainTotal = (d) => (d.size_mb.web || 0) + (d.size_mb.mail || 0) + (d.size_mb.db || 0);

  function sync() {
    for (const [name, box] of boxes) box.checked = S.selected.has(name);
    for (const [box, list] of groupBoxes) {
      const n = list.filter(d => S.selected.has(d.name)).length;
      box.checked = n === list.length;
      box.indeterminate = n > 0 && n < list.length;
    }
    const chosen = selectedDomains();
    footer.textContent = chosen.length + ' of ' + domains.length + ' selected \u00b7 ' +
      fmtMb(chosen.reduce((a, d) => a + domainTotal(d), 0)) + ' of data';
    next.disabled = chosen.length === 0;
    persist();
  }
  function toggle(names, on) {
    for (const n of names) on ? S.selected.add(n) : S.selected.delete(n);
    S.targetReport = null;  // checks on the target depend on the selection
    S.prepareSel = null;
    sync();
  }

  const rows = [];
  for (const [sub, list] of groups) {
    const gbox = h('input', { type: 'checkbox', 'aria-label': 'Select all in ' + sub,
      onchange: (e) => toggle(list.map(d => d.name), e.target.checked) });
    groupBoxes.push([gbox, list]);
    rows.push(h('tr', { class: 'group' },
      h('td', {}, gbox),
      h('td', { colspan: 5 }, sub, ' ', h('span', { class: 'badge' }, 'subscription \u00b7 ' + plural(list.length, 'domain')))));
    for (const d of list) {
      const box = h('input', { type: 'checkbox', 'aria-label': 'Select ' + d.name,
        onchange: (e) => toggle([d.name], e.target.checked) });
      boxes.set(d.name, box);
      const notes = [];
      if (d.subdomains.length) notes.push(h('span', { class: 'badge warn', title: d.subdomains.join(', ') },
        plural(d.subdomains.length, 'subdomain') + ' not migrated'));
      if (d.domain_aliases.length) notes.push(h('span', { class: 'badge warn', title: d.domain_aliases.join(', ') },
        plural(d.domain_aliases.length, 'alias', 'aliases') + ' not migrated'));
      rows.push(h('tr', { class: 'row' },
        h('td', {}, box),
        h('td', {}, h('div', { class: 'dname' }, d.name), h('div', { class: 'dpath' }, d.docroot),
          notes.length ? h('div', {}, notes.flatMap(n => [n, ' '])) : null),
        h('td', { class: 'nowrap' }, d.php ? 'PHP ' + d.php : '-'),
        h('td', { class: 'num' }, d.databases.length || '-'),
        h('td', { class: 'num' }, d.mailboxes || '-'),
        h('td', { class: 'num' }, fmtMb(domainTotal(d)))));
    }
  }

  const table = h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, ''), h('th', {}, 'Domain'), h('th', {}, 'PHP'),
      h('th', { class: 'num' }, 'DBs'), h('th', { class: 'num' }, 'Mailboxes'), h('th', { class: 'num' }, 'Size'))),
    h('tbody', {}, rows)));

  const notes = (S.sourceReport.inventory.notes || []);
  const view = h('section', { class: 'card' },
    h('h1', {}, 'Choose what to migrate'),
    h('p', { class: 'lead' }, 'Tick the domains to move. Domains of one subscription share a hosting space, ',
      'so they are usually best migrated together.'),
    notes.map(n => alertBox('warn', null, n)),
    h('div', { class: 'toolbar' },
      h('button', { class: 'btn small', type: 'button', onclick: () => toggle(domains.map(d => d.name), true) }, 'Select all'),
      h('button', { class: 'btn small', type: 'button', onclick: () => toggle(domains.map(d => d.name), false) }, 'Select none'),
      h('span', { class: 'spacer' }), footer),
    table,
    h('div', { class: 'actions' },
      h('button', { class: 'btn', type: 'button', onclick: () => gotoStep(1) }, 'Back'),
      h('span', { class: 'spacer' }), next));
  sync();
  return view;
}

// ---------------------------------------------------------------------
// Step 4: target server
// ---------------------------------------------------------------------
function renderTarget() {
  const form = connectionForm('target');
  const hostKeyBox = h('div');
  const message = h('div');
  const results = h('div');
  const first = selectedDomains()[0];
  if (!S.mailHostname && first) S.mailHostname = 'mail.' + first.name.replace(/^www\./, '');
  const mailHost = h('input', { type: 'text', id: 'mail-host', value: S.mailHostname, spellcheck: 'false',
    autocomplete: 'off', oninput: (e) => { S.mailHostname = e.target.value.trim(); persist(); } });

  const connect = h('button', { class: 'btn primary', type: 'button' }, S.target ? 'Reconnect and check' : 'Connect and check');
  const recheck = h('button', { class: 'btn', type: 'button', hidden: !S.target }, 'Run checks again');
  const next = h('button', { class: 'btn primary', type: 'button', disabled: true, onclick: () => gotoStep(4) }, 'Continue');

  function paint() {
    results.replaceChildren(S.targetReport ? checkList(S.targetReport.checks) : '');
    next.disabled = !(S.targetReport && S.targetReport.can_continue);
  }
  async function runChecks() {
    results.replaceChildren(loading('Running checks on the target server...'));
    S.targetReport = await api('POST', '/api/target/checks', {
      domains: selectedDomains().map(d => d.name), mail_hostname: S.mailHostname });
    S.prepareSel = null;
    paint();
  }
  async function guarded(fn) {
    connect.disabled = recheck.disabled = true; next.disabled = true;
    message.replaceChildren();
    try { await fn(); }
    catch (e) { results.replaceChildren(); message.replaceChildren(alertBox('fail', 'That did not work', e.message)); }
    finally { connect.disabled = recheck.disabled = false; if (S.targetReport) paint(); }
  }
  connect.addEventListener('click', () => guarded(async () => {
    message.replaceChildren(loading('Connecting...'));
    const endpoint = await connectFlow('target', form, hostKeyBox, message);
    if (!endpoint) { message.replaceChildren(); return; }
    S.target = endpoint; S.targetReport = null;
    message.replaceChildren();
    recheck.hidden = false;
    await runChecks();
  }));
  recheck.addEventListener('click', () => guarded(runChecks));
  if (S.targetReport) paint();

  return h('section', { class: 'card' },
    h('h1', {}, 'Connect to the target server'),
    h('p', { class: 'lead' }, 'A fresh Ubuntu 22.04 or 24.04 server with root access. plsk2sa installs and ',
      'configures nginx, PHP-FPM, MariaDB, Postfix, Dovecot and OpenDKIM on it.'),
    S.target ? alertBox('ok', 'Connected to ' + S.target.user + '@' + S.target.host) : null,
    form.el,
    h('div', { class: 'field' }, h('label', { for: 'mail-host' }, 'Mail server hostname'), mailHost,
      h('span', { class: 'hint' }, 'The name your mail server will identify itself with. It should resolve to the new server and match its reverse DNS (PTR) record.')),
    hostKeyBox, message,
    h('div', { class: 'actions' }, connect, recheck),
    results,
    h('div', { class: 'actions' },
      h('button', { class: 'btn', type: 'button', onclick: () => gotoStep(2) }, 'Back'),
      h('span', { class: 'spacer' }), next));
}

// ---------------------------------------------------------------------
// Step 5: run
// ---------------------------------------------------------------------
const NEXT_STEPS = [
  'Test every website against the new server before touching DNS: curl -H "Host: yourdomain.tld" http://NEW_SERVER_IP/',
  'Enter the new database credentials (file shown above) into your applications, e.g. wp-config.php.',
  'Lower the DNS TTL to 300 seconds a day or two ahead of the switch.',
  'The DKIM record can go live early. Apply the other DNS changes shown above on switch day.',
  'On switch day: run “Final sync” here, then change the DNS records.',
  'Once DNS points to the new server, issue certificates: certbot --nginx -d yourdomain.tld -d www.yourdomain.tld',
  'Keep the Plesk server for 2–4 weeks before cancelling it.',
];

const NEXT_STEPS_PREPARE = [
  'The target server is ready. Run the wizard again with \u201cFull migration\u201d to copy configuration, files, databases and mailboxes.',
  'Items marked \u201cInstalled only\u201d (spam filter, virus scanner, PostgreSQL) still need to be connected or filled by you.',
  'Check the notes above - .htaccess rules and tools outside Ubuntu\u2019s repositories have to be handled by hand.',
];

const STATUS_ICON = { installed: 'ok', planned: 'pending', partial: 'warn', failed: 'fail' };

function softwareResult(res) {
  const rows = res.prepare.map(r => h('li', {},
    statusIcon(STATUS_ICON[r.status] || 'pending'),
    h('div', {}, h('div', { class: 'check-title' }, r.title, ' ', h('span', { class: 'badge' }, r.status === 'planned' ? 'would install' : r.status)),
      h('div', { class: 'check-detail' }, h('code', { class: 'pkgs' }, r.packages.join(' '))),
      r.failed.length ? h('div', { class: 'check-detail' }, 'Not installed: ' + r.failed.join(' ')) : null,
      r.note ? h('div', { class: 'check-detail' }, r.note) : null)));
  const notes = ((S.targetReport && S.targetReport.prepare_plan && S.targetReport.prepare_plan.notes) || []).map(n => alertBox('warn', null, n));
  return [h('h2', {}, 'Software on the target server'), h('ul', { class: 'checks' }, rows), ...notes];
}

function renderRun() {
  return S.run.state === 'idle' ? renderRunSetup() : renderRunProgress();
}

// What a run does to the Plesk server - shown before, during and after a run.
function plannedSourceChanges(readOnly, mode) {
  const target = S.target ? S.target.host : 'the target';
  return readOnly
    ? alertBox('ok', 'Changes on the Plesk server: none',
        mode === 'prepare'
          ? 'Preparing the target does not touch the Plesk server; what it needs was read earlier, during the checks.'
          : 'A preview only reads from the Plesk server. Everything it would change is listed with “WOULD CHANGE” in the log.')
    : h('div', { class: 'alert source', role: 'status' },
        h('strong', {}, 'Changes on the Plesk server'),
        h('ul', { class: 'plain' },
          h('li', {}, 'A temporary SSH key (comment ', h('code', {}, 'plsk2sa-temporary'), ') is added to ',
            h('code', {}, '~/.ssh/authorized_keys'), ' of ' + S.source.user + '@' + S.source.host +
            ', so that ' + target + ' can pull the data directly.'),
          h('li', {}, 'The key is removed again at the end - also if something fails or you cancel.'),
          h('li', {}, 'Nothing else is changed: no files, databases, mail or DNS settings are modified or deleted.')),
        h('span', { class: 'small muted' }, 'Every change is announced live in this window and recorded in the log file.'));
}

function field(id, label, input, hint) {
  return h('div', { class: 'field' }, h('label', { for: id }, label), input,
    hint ? h('span', { class: 'hint' }, hint) : null);
}

function renderRunSetup() {
  const o = S.options;
  const dns = S.dns;
  const chosen = selectedDomains();
  const plan = S.targetReport && S.targetReport.prepare_plan;
  const confirmBox = h('div');
  const sourceBox = h('div');
  const softwareBox = h('div');
  const dnsBox = h('div');
  const start = h('button', { class: 'btn primary', type: 'button' });
  const msg = h('div');

  if (!dns.prefilled && S.targetReport && S.targetReport.dns_defaults) {
    const d = S.targetReport.dns_defaults;
    dns.old_ips = (d.old_ips || []).join(', ');
    dns.new_ipv4 = d.new_ipv4 || '';
    dns.new_ipv6 = d.new_ipv6 || '';
    dns.prefilled = true;
  }
  if (plan && !S.prepareSel) S.prepareSel = new Set(plan.default_selection);

  const radio = (name, group, value, label, hint, onpick) => h('label', { class: 'check' },
    h('input', { type: 'radio', name, checked: group === value, onchange: onpick }),
    h('span', {}, h('strong', {}, label), h('br'), h('span', { class: 'muted small' }, hint)));
  const text = (id, key, placeholder) => h('input', { type: 'text', id, value: dns[key], spellcheck: 'false',
    autocomplete: 'off', placeholder, oninput: (e) => { dns[key] = e.target.value.trim(); persist(); } });

  function paintSoftware() {
    if (o.mode === 'sync' || !plan) { softwareBox.replaceChildren(); return; }
    const rows = plan.items.map(it => {
      const box = h('input', { type: 'checkbox', checked: it.required || S.prepareSel.has(it.id), disabled: it.required,
        'aria-label': it.title, onchange: (e) => { e.target.checked ? S.prepareSel.add(it.id) : S.prepareSel.delete(it.id); } });
      return h('label', { class: 'check plan-item' }, box, h('span', {},
        h('strong', {}, it.title), ' ',
        it.required ? h('span', { class: 'badge' }, 'always') : null,
        it.third_party ? h('span', { class: 'badge warn' }, 'third-party repository') : null,
        h('br'), h('span', { class: 'muted small' }, it.reason),
        h('br'), h('code', { class: 'pkgs' }, it.packages.join(' ')),
        it.note ? h('div', { class: 'dnote' }, it.note) : null));
    });
    softwareBox.replaceChildren(
      h('h2', {}, 'Software on the target server'),
      h('p', { class: 'muted small' }, 'Found on the Plesk server and needed by the selected sites. ' +
        'Untick what you do not want installed.'),
      ...rows, ...(plan.notes || []).map(n => alertBox('warn', null, n)));
  }

  function paintDns() {
    if (o.mode === 'prepare') { dnsBox.replaceChildren(); return; }
    dnsBox.replaceChildren(
      h('h2', {}, 'DNS'),
      h('p', { class: 'muted small' }, 'Who answers DNS queries for your domains?'),
      radio('dns-mode', dns.mode, 'external', 'Somewhere else (registrar, Cloudflare, ...)',
        'plsk2sa reads the records Plesk holds and lists exactly which ones must change, with the new values.',
        () => { dns.mode = 'external'; persist(); }),
      radio('dns-mode', dns.mode, 'plesk', 'This Plesk server (its name servers answer for my domains)',
        'The zones have to move with the domains. You get complete zone files with the new addresses to import at your new DNS provider.',
        () => { dns.mode = 'plesk'; persist(); }),
      h('div', { class: 'grid three' },
        field('dns-old', 'Old server address(es)', text('dns-old', 'old_ips', '203.0.113.10'),
          'IPv4, comma separated. Records and SPF entries with these addresses are rewritten.'),
        field('dns-new', 'New server IPv4', text('dns-new', 'new_ipv4', '203.0.113.20'), 'Public address of the target.'),
        field('dns-new6', 'New server IPv6 (optional)', text('dns-new6', 'new_ipv6', '2001:db8::20'), 'Leave empty if there is none.')));
  }

  function sync() {
    start.textContent = o.dry_run ? 'Start preview' : ({ full: 'Start migration', prepare: 'Prepare the target', sync: 'Start final sync' })[o.mode];
    const changes = { full: ': packages are installed and the web, database and mail configuration there is created or overwritten.',
      prepare: ': packages are installed and the web, database and mail services there are configured. No data is copied.',
      sync: ': web files, mail and databases there are overwritten with the current state of the Plesk server.' };
    confirmBox.replaceChildren(o.dry_run ? '' : h('label', { class: 'check' },
      h('input', { type: 'checkbox', checked: o.confirmed, onchange: (e) => { o.confirmed = e.target.checked; sync(); } }),
      h('span', {}, 'I understand that this changes ', h('strong', {}, S.target.host), changes[o.mode])));
    sourceBox.replaceChildren(plannedSourceChanges(o.dry_run || o.mode === 'prepare', o.mode));
    paintSoftware();
    paintDns();
    start.disabled = !o.dry_run && !o.confirmed;
    persist();
  }

  start.addEventListener('click', async () => {
    start.disabled = true;
    try {
      const body = { mode: o.mode, dry_run: o.dry_run, restrict_ip: o.restrict_ip, confirmed: o.confirmed,
        domains: chosen.map(d => d.name), mail_hostname: S.mailHostname };
      if (o.mode !== 'prepare') body.dns = { mode: dns.mode, old_ips: dns.old_ips, new_ipv4: dns.new_ipv4, new_ipv6: dns.new_ipv6 };
      if (o.mode !== 'sync' && S.prepareSel) body.prepare = { selected: [...S.prepareSel] };
      await api('POST', '/api/run/start', body);
      S.run = { state: 'running', steps: [], next: 0, result: null, source_changes: [], source_state: 'unchanged' };
      render();
      poll();
    } catch (e) { msg.replaceChildren(alertBox('fail', 'Cannot start', e.message)); sync(); }
  });

  const pick = (mode) => () => { o.mode = mode; o.confirmed = false; sync(); };
  const view = h('section', { class: 'card' },
    h('h1', {}, 'Ready to migrate'),
    h('dl', { class: 'summary' },
      h('dt', {}, 'From'), h('dd', {}, S.source.user + '@' + S.source.host),
      h('dt', {}, 'To'), h('dd', {}, S.target.user + '@' + S.target.host),
      h('dt', {}, 'Domains'), h('dd', {}, chosen.map(d => d.name).join(', ')),
      h('dt', {}, 'Mail hostname'), h('dd', {}, S.mailHostname),
      h('dt', {}, 'PHP on target'), h('dd', {}, S.targetReport ? S.targetReport.php_version : '-')),

    h('h2', {}, 'What should happen?'),
    radio('mode', o.mode, 'full', 'Full migration', 'Install the stack, then copy configuration, files, databases and mailboxes.', pick('full')),
    radio('mode', o.mode, 'prepare', 'Prepare the target server only',
      'Install and set up everything the Plesk sites need - PHP versions, extensions, tools, services - without copying any data. A good first step.', pick('prepare')),
    radio('mode', o.mode, 'sync', 'Final sync only', 'For switch day: refresh files, databases and mailboxes on an already migrated server.', pick('sync')),
    h('label', { class: 'check' },
      h('input', { type: 'checkbox', checked: o.dry_run, onchange: (e) => { o.dry_run = e.target.checked; sync(); } }),
      h('span', {}, h('strong', {}, 'Preview only (recommended for the first run)'), h('br'),
        h('span', { class: 'muted small' }, 'Lists every change that would be made, without changing anything. Also shows the plan for the target and DNS.'))),

    softwareBox,
    dnsBox,
    sourceBox,
    confirmBox,
    h('details', {}, h('summary', {}, 'Advanced'),
      h('label', { class: 'check' },
        h('input', { type: 'checkbox', checked: o.restrict_ip, onchange: (e) => { o.restrict_ip = e.target.checked; } }),
        h('span', {}, 'Restrict the temporary server-to-server key to the target’s IP address',
          h('br'), h('span', { class: 'muted small' }, 'Disable the restriction only if the copy fails because the target connects from a different address (NAT).')))),
    msg,
    h('div', { class: 'actions' },
      h('button', { class: 'btn', type: 'button', onclick: () => gotoStep(3) }, 'Back'),
      h('span', { class: 'spacer' }), start));
  sync();
  return view;
}

function renderRunProgress() {
  const stepsEl = h('ul', { class: 'steps', id: 'run-steps' });
  const bar = h('div', { id: 'run-bar' });
  const logEl = h('div', { class: 'log', id: 'run-log', role: 'log', 'aria-live': 'off' });
  const heading = h('h1', { id: 'run-heading' });
  const banner = h('div', { id: 'source-banner' });
  const body = h('div', { id: 'run-result' });
  const cancel = h('button', { class: 'btn danger', type: 'button', id: 'run-cancel',
    onclick: async (e) => { e.target.disabled = true; try { await api('POST', '/api/run/cancel'); } catch (x) { /* shown via log */ } } }, 'Cancel');
  const view = h('section', { class: 'card' }, heading,
    h('div', { class: 'progress' }, bar), stepsEl, banner, body,
    h('div', { class: 'actions' }, cancel), logEl);
  S.run.logEl = logEl;
  queueMicrotask(paintRun);
  return view;
}

function appendLog(entries) {
  const el = S.run.logEl;
  if (!el) return;
  const stick = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  for (const e of entries) {
    el.append(h('div', { class: 'l-' + e.level }, h('span', { class: 'l-time' }, e.time + '  '),
      e.level === 'source' ? '⚠ ' : '', e.message));
  }
  if (stick) el.scrollTop = el.scrollHeight;
}

// The Plesk-server notice: live while running, summary afterwards.
function sourceNotice(r, final) {
  const changes = r.source_changes || [];
  const real = changes.filter(c => !c.dry_run);
  const list = (items) => h('ul', { class: 'plain' }, items.map(c =>
    h('li', {}, h('span', { class: 'l-time' }, c.time + '  '), c.text.replace(/^(CHANGING|WOULD CHANGE) the Plesk server: /, ''))));
  if (!changes.length) {
    return alertBox('ok', 'Plesk server: unchanged', final ? 'No changes were made to the Plesk server.' : 'Nothing has been changed on the Plesk server so far.');
  }
  if (!real.length) {
    return alertBox('ok', 'Plesk server: not changed (preview)', h('div', {}, 'A real run would make these changes:', list(changes)));
  }
  if (r.source_state === 'restored') {
    return h('div', { class: 'alert source', role: 'status' }, h('strong', {}, 'Plesk server: changed and restored'),
      list(real), 'The temporary change has been removed again.');
  }
  if (final) {
    return h('div', { class: 'alert fail', role: 'alert' }, h('strong', {}, 'Plesk server: still contains a change'), list(real),
      h('p', {}, 'The temporary key could not be removed. Remove the line containing ', h('code', {}, 'plsk2sa-temporary'),
        ' from ', h('code', {}, '~/.ssh/authorized_keys'), ' on the Plesk server.'));
  }
  return h('div', { class: 'alert source', role: 'status' }, h('strong', {}, 'Plesk server: CHANGED'), list(real));
}

function paintRun() {
  const r = S.run;
  const stepsEl = document.getElementById('run-steps');
  if (!stepsEl) return;
  stepsEl.replaceChildren(...r.steps.map(s => h('li', { class: s.state }, statusIcon(s.state), s.label)));
  const done = r.steps.filter(s => ['done', 'failed', 'skipped'].includes(s.state)).length;
  document.getElementById('run-bar').style.width = (r.steps.length ? Math.round(100 * done / r.steps.length) : 0) + '%';

  const titles = { running: 'Working...', done: 'Finished', failed: 'Stopped with an error', cancelled: 'Cancelled' };
  const res = r.result;
  document.getElementById('run-heading').textContent =
    r.state === 'done' && res && res.dry_run ? 'Preview finished' : (titles[r.state] || '');
  document.getElementById('run-cancel').hidden = r.state !== 'running';
  document.getElementById('source-banner').replaceChildren(sourceNotice(r, r.state !== 'running'));
  if (r.state !== 'running' && res) paintResult(document.getElementById('run-result'));
}

function badge(action) { return h('span', { class: 'badge act-' + action }, action.toUpperCase()); }

function download(filename, text) {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: filename });
  document.body.append(a);
  a.click();
  a.remove();
}

function dnsSection(dns) {
  const kids = [h('h2', {}, 'DNS'), h('ul', { class: 'plain' }, dns.notes.map(n => h('li', {}, n)))];
  for (const dom of dns.domains) {
    const shown = dom.changes.filter(c => c.action !== 'keep');
    const unchanged = dom.changes.length - shown.length;
    const rows = shown.map(c => {
      const copy = c.new ? h('button', { class: 'btn small', type: 'button' }, 'Copy') : null;
      if (copy) copy.addEventListener('click', () => copyText(c.new, copy));
      return h('tr', { class: 'row' },
        h('td', {}, badge(c.action)), h('td', { class: 'nowrap' }, c.type),
        h('td', {}, h('div', { class: 'dname' }, c.name), c.note ? h('div', { class: 'dnote' }, c.note) : null),
        h('td', {}, c.old ? h('code', { class: 'val-inline' }, c.old) : '-'),
        h('td', {}, c.new ? h('code', { class: 'val-inline' }, c.new) : '-'), h('td', {}, copy));
    });
    const parts = [dom.note ? alertBox('warn', null, dom.note) : null];
    if (rows.length) {
      parts.push(h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Action'), h('th', {}, 'Type'), h('th', {}, 'Name'),
          h('th', {}, 'Now'), h('th', {}, dns.mode === 'plesk' ? 'In the new zone' : 'New value'), h('th', {}, ''))),
        h('tbody', {}, rows))));
    }
    if (unchanged) parts.push(h('p', { class: 'muted small' }, plural(unchanged, 'record') + ' stay as they are.'));
    if (dom.zone) {
      const copy = h('button', { class: 'btn small', type: 'button' }, 'Copy zone');
      copy.addEventListener('click', () => copyText(dom.zone, copy));
      parts.push(h('h3', { class: 'sub' }, 'Complete zone file'),
        h('pre', { class: 'zone' }, dom.zone),
        h('div', { class: 'actions' }, copy,
          h('button', { class: 'btn small', type: 'button', onclick: () => download(dom.domain + '.zone', dom.zone) }, 'Download ' + dom.domain + '.zone')));
    }
    kids.push(h('details', { open: true }, h('summary', {}, dom.domain, ' ',
      h('span', { class: 'badge' }, plural(shown.length, 'change'))), parts));
  }
  return kids;
}

function paintResult(box) {
  const r = S.run, res = r.result;
  const kids = [];
  if (r.state === 'failed') kids.push(alertBox('fail', 'The run stopped', res.error));
  else if (r.state === 'cancelled') kids.push(alertBox('warn', 'Cancelled', 'Everything that was started has been cleaned up. You can run it again at any time; runs are repeatable.'));
  else if (res.error) kids.push(alertBox('warn', 'Finished with a problem', res.error));
  else if (res.dry_run) kids.push(alertBox('ok', 'Preview complete',
    'The log below lists every command that would run. Nothing was changed.'));
  else if (res.mode === 'prepare') kids.push(alertBox('ok', 'Target server prepared',
    'The software the Plesk sites need is installed. No data has been copied yet.'));
  else kids.push(alertBox('ok', 'Migration complete', 'Work through the next steps below to finish the switch.'));

  if (res.verify && res.verify.length) {
    const failed = res.verify.filter(v => !v.ok);
    kids.push(h('h2', {}, 'Verification'),
      failed.length ? alertBox('warn', plural(failed.length, 'check') + ' failed', failed.map(v => v.message).join(' · '))
        : alertBox('ok', 'All ' + res.verify.length + ' verification checks passed'));
  }
  if (res.prepare && res.prepare.length) kids.push(...softwareResult(res));
  if (res.dns) kids.push(...dnsSection(res.dns));
  else if (res.dkim && res.dkim.length) {
    kids.push(h('h2', {}, 'DKIM records to publish'));
    for (const rec of res.dkim) kids.push(h('div', { class: 'record' }, h('strong', {}, rec.domain),
      h('code', { class: 'val' }, rec.name), h('code', { class: 'val' }, rec.value)));
  }
  if (res.credentials_file) {
    kids.push(h('h2', {}, 'New database credentials'),
      h('p', {}, 'Saved on this computer in ', h('code', {}, res.credentials_file),
        '. Enter them into your applications (for WordPress: wp-config.php).'));
  }
  if (!res.dry_run && r.state === 'done') {
    kids.push(h('h2', {}, 'Next steps'), h('ol', { class: 'next' }, (res.mode === 'prepare' ? NEXT_STEPS_PREPARE : NEXT_STEPS).map(t => h('li', {}, t))),
      h('p', { class: 'small' }, h('a', { href: 'https://github.com/fmatsch/plsk2sa/blob/main/docs/cutover.md', target: '_blank', rel: 'noopener noreferrer' }, 'Full cutover checklist')));
  }
  kids.push(h('div', { class: 'actions' },
    h('button', { class: 'btn', type: 'button', onclick: () => api('POST', '/api/open-workdir').catch(() => {}) }, 'Open working folder'),
    h('span', { class: 'spacer' }),
    h('button', { class: 'btn primary', type: 'button', onclick: async () => {
      await api('POST', '/api/run/reset'); S.run = { state: 'idle', steps: [], next: 0, result: null, source_changes: [], source_state: 'unchanged' };
      S.options.confirmed = false; render(); } }, res.dry_run ? 'Back to setup' : 'Run again')));
  box.replaceChildren(...kids);
}

async function poll() {
  clearTimeout(pollTimer);
  try {
    const r = await api('GET', '/api/run/status?since=' + S.run.next);
    Object.assign(S.run, { state: r.state, steps: r.steps, result: r.result, next: r.next,
      source_changes: r.source_changes, source_state: r.source_state });
    appendLog(r.log);
    paintRun();
    renderStepper();
    if (r.state === 'running') pollTimer = setTimeout(poll, 800);
  } catch (e) {
    pollTimer = setTimeout(poll, 2000);
  }
}

// ---------------------------------------------------------------------
// Start-up: restore what the server already knows (page reload)
// ---------------------------------------------------------------------
async function start() {
  document.getElementById('quit').addEventListener('click', async () => {
    if (!confirm('Quit plsk2sa? Connections are closed and this page stops working.')) return;
    try { await api('POST', '/api/quit'); } catch (e) { /* server is gone */ }
    document.body.replaceChildren(h('main', { class: 'card', style: null }, h('h1', {}, 'plsk2sa has stopped'),
      h('p', {}, 'You can close this tab.')));
  });
  restoreLocal();
  let info;
  try { info = await api('GET', '/api/state'); }
  catch (e) {
    $main().replaceChildren(alertBox('fail', 'Cannot reach plsk2sa',
      'Open the link printed in the terminal window where plsk2sa is running. ' + e.message));
    return;
  }
  S.demo = info.demo;
  document.getElementById('demo-badge').hidden = !info.demo;
  S.source = info.source; S.target = info.target;
  S.sourceReport = info.source_report; S.targetReport = info.target_report;
  if (S.sourceReport && S.sourceReport.inventory && !S.selected.size) {
    S.selected = new Set(S.sourceReport.inventory.domains.map(d => d.name));
  }

  // Resume at the furthest step the server already has a result for.
  let step = 0;
  if (S.source) step = 1;
  if (S.sourceReport && S.sourceReport.can_continue) step = 2;
  if (S.target) step = 3;
  if (S.target && S.targetReport && S.targetReport.can_continue) step = 4;
  S.step = step; S.maxStep = step;
  if (info.run.state !== 'idle') {
    S.run = { state: info.run.state, steps: [], next: 0, result: null, source_changes: [], source_state: 'unchanged' };
    S.step = S.maxStep = 4;
  }
  render();
  if (info.run.state !== 'idle') poll();
}

start();
})();
