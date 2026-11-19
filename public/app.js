'use strict';

// Live-first dashboard: machines table refreshes every 3 s, matching the
// client's ping rate.

const $ = (sel) => document.querySelector(sel);

function toast(msg, bad = false) {
  const el = $('#toast');
  el.textContent = msg;
  el.style.borderColor = bad ? 'rgba(248,113,113,.5)' : 'rgba(74,222,128,.4)';
  el.classList.remove('hidden');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.add('hidden'), 2600);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `http ${res.status}`);
  return data;
}

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function ago(iso) {
  if (!iso) return 'never';
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 2) return 'now';
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  return `${Math.round(s / 3600)}h`;
}

const hw = (info, field) => (info && info[field]) ? String(info[field]) : '–';

// ── tabs ──────────────────────────────────────────────────────────────────

for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    tab.classList.add('active');
    for (const pane of ['live', 'keys', 'updates', 'users']) {
      $(`#pane-${pane}`).classList.toggle('hidden', pane !== tab.dataset.tab);
    }
    if (tab.dataset.tab === 'keys') loadKeys();
    if (tab.dataset.tab === 'updates') loadUpdates();
    if (tab.dataset.tab === 'users') loadUsers();
  });
}

// ── stats ─────────────────────────────────────────────────────────────────

async function loadStats() {
  try {
    const s = await api('/api/admin/stats');
    $('#stat-live').textContent = s.live;
    $('#stat-keys').textContent = s.keys;
    $('#stat-banned').textContent = s.banned;
    $('#stat-hwids').textContent = s.hwids;
  } catch { /* keep old */ }
}

// ── live machines ─────────────────────────────────────────────────────────

async function loadLive() {
  try {
    const { devices } = await api('/api/admin/live');
    const body = $('#live-table tbody');

    body.innerHTML = devices.map((d) => {
      const info = d.hw_info || {};
      const machine = [
        hw(info, 'cpu'),
        hw(info, 'gpu'),
        info.ram_gb ? `${info.ram_gb} GB` : null,
        hw(info, 'disk'),
        hw(info, 'monitor'),
      ].filter(Boolean).join(' · ');

      const state = d.banned
        ? `<span class="pill off">banned${d.ban_reason ? `: ${esc(d.ban_reason)}` : ''}</span>`
        : (d.live ? '<span class="pill on">live</span>' : '<span class="pill off">offline</span>');

      return `
        <tr>
          <td class="mono">${esc(d.key)}</td>
          <td>
            <div class="mono">${esc((d.machine_id || d.hwid || '').replace(/^guid:|^hwid:/, '').slice(0, 16))}…</div>
            <div class="muted small">${esc(machine)}</div>
            <div class="muted small mono">${esc(hw(info, 'volume'))} ${esc(hw(info, 'machine_guid').slice(0, 8))}</div>
          </td>
          <td class="mono">${esc(d.ip || '–')}</td>
          <td title="${esc(d.last_seen)}">${ago(d.last_seen)}</td>
          <td>${state}</td>
          <td class="right">
            <button class="${d.banned ? 'ghost' : 'danger'}" data-ban="${d.key_id}" data-state="${d.banned}">
              ${d.banned ? 'unban' : 'ban key'}
            </button>
            <button class="ghost" data-forget="${d.id}" title="remove this machine row">forget</button>
          </td>
        </tr>`;
    }).join('') || '<tr><td colspan="6" class="muted">nothing connected yet</td></tr>';

    for (const btn of body.querySelectorAll('[data-forget]')) {
      btn.addEventListener('click', async () => {
        try {
          await api(`/api/admin/devices/${btn.dataset.forget}`, { method: 'DELETE' });
          toast('machine row removed');
          loadLive(); loadStats();
        } catch (e) { toast(e.message, true); }
      });
    }

    for (const btn of body.querySelectorAll('[data-ban]')) {
      btn.addEventListener('click', async () => {
        const ban = btn.dataset.state !== 'true';
        try {
          await api(`/api/admin/keys/${btn.dataset.ban}/ban`, {
            method: 'POST', body: JSON.stringify({ banned: ban, reason: 'manual ban' }),
          });
          toast(ban ? 'key banned - client drops on next ping' : 'key unbanned');
          loadLive(); loadStats();
        } catch (e) { toast(e.message, true); }
      });
    }

    $('#live-updated').textContent = 'updated ' + new Date().toLocaleTimeString();
  } catch (e) { toast(e.message, true); }
}

// ── keys ──────────────────────────────────────────────────────────────────

async function loadKeys() {
  try {
    const { keys } = await api('/api/admin/keys');
    const body = $('#keys-table tbody');

    body.innerHTML = keys.map((k) => `
      <tr>
        <td class="mono">${esc(k.code)}</td>
        <td>${k.days}</td>
        <td class="mono">${k.hwid ? esc(k.hwid.slice(0, 12)) + '…' : '<span class="muted">unused</span>'}</td>
        <td class="mono">${esc(k.last_ip || '–')}</td>
        <td>${esc(k.note || '')}</td>
        <td>${k.banned
          ? `<span class="pill off">banned</span>`
          : (k.devices ? '<span class="pill on">in use</span>' : '<span class="pill">new</span>')}</td>
        <td class="right">
          <button class="${k.banned ? 'ghost' : 'danger'}" data-ban="${k.id}" data-state="${k.banned}">
            ${k.banned ? 'unban' : 'ban'}
          </button>
          <button class="ghost" data-reset="${k.id}">reset</button>
          <button class="danger" data-del="${k.id}">delete</button>
        </td>
      </tr>`).join('') || '<tr><td colspan="7" class="muted">no keys</td></tr>';

    for (const btn of body.querySelectorAll('[data-ban]')) {
      btn.addEventListener('click', async () => {
        const ban = btn.dataset.state !== 'true';
        try {
          await api(`/api/admin/keys/${btn.dataset.ban}/ban`, {
            method: 'POST', body: JSON.stringify({ banned: ban }),
          });
          toast(ban ? 'banned' : 'unbanned');
          loadKeys(); loadStats();
        } catch (e) { toast(e.message, true); }
      });
    }

    for (const btn of body.querySelectorAll('[data-reset]')) {
      btn.addEventListener('click', async () => {
        if (!confirm('reset this key? it forgets the machine and can be used on a new one')) return;
        try {
          await api(`/api/admin/keys/${btn.dataset.reset}/reset`, { method: 'POST' });
          toast('key reset');
          loadKeys(); loadStats();
        } catch (e) { toast(e.message, true); }
      });
    }

    for (const btn of body.querySelectorAll('[data-del]')) {
      btn.addEventListener('click', async () => {
        if (!confirm('delete this key?')) return;
        try {
          await api(`/api/admin/keys/${btn.dataset.del}`, { method: 'DELETE' });
          toast('deleted');
          loadKeys(); loadStats();
        } catch (e) { toast(e.message, true); }
      });
    }
  } catch (e) { toast(e.message, true); }
}

$('#key-create').addEventListener('click', async () => {
  try {
    const out = await api('/api/admin/keys', {
      method: 'POST',
      body: JSON.stringify({
        days: Number($('#key-days').value),
        count: Number($('#key-count').value),
        note: $('#key-note').value,
      }),
    });
    const box = $('#key-result');
    box.textContent = out.keys.join('\n');
    box.classList.remove('hidden');
    box.onclick = () => navigator.clipboard?.writeText(out.keys.join('\n'));
    toast(`${out.keys.length} key(s) created`);
    loadKeys(); loadStats();
  } catch (e) { toast(e.message, true); }
});

// ── offsets / updates ─────────────────────────────────────────────────────

async function loadUpdates() {
  try {
    const { updates } = await api('/api/admin/updates');
    const body = $('#updates-table tbody');
    body.innerHTML = updates.map((u) => `
      <tr>
        <td class="mono">v${u.version}</td>
        <td>${esc(u.note || '')}</td>
        <td class="mono">${esc((u.sha || '').slice(0, 16))}…</td>
        <td>${u.size} B</td>
        <td>${ago(u.created_at)}</td>
        <td class="right"><button class="ghost" data-view="${u.id}">view</button></td>
      </tr>`).join('') || '<tr><td colspan="6" class="muted">nothing pushed yet</td></tr>';

    for (const btn of body.querySelectorAll('[data-view]')) {
      btn.addEventListener('click', async () => {
        try {
          const { update } = await api(`/api/admin/updates/${btn.dataset.view}`);
          const box = $('#update-payload');
          box.value = update.payload;
          $('#update-note').value = update.note || '';
          toast(`loaded v${update.version} into the editor`);
        } catch (e) { toast(e.message, true); }
      });
    }
  } catch (e) { toast(e.message, true); }
}

$('#update-push').addEventListener('click', async () => {
  const payload = $('#update-payload').value.trim();
  if (!payload) return toast('paste the offsets first', true);

  try { JSON.parse(payload); } catch { return toast('payload is not valid json', true); }

  try {
    const out = await api('/api/admin/updates', {
      method: 'POST',
      body: JSON.stringify({ payload, note: $('#update-note').value }),
    });
    $('#update-result').textContent =
      `v${out.version} pushed · sha ${out.sha.slice(0, 12)}… — clients get it on the next ping`;
    toast(`offsets v${out.version} published`);
    loadUpdates();
  } catch (e) { toast(e.message, true); }
});

$('#updates-refresh').addEventListener('click', loadUpdates);

// ── panel users ───────────────────────────────────────────────────────────

async function loadUsers() {
  try {
    const { users } = await api('/api/admin/users');
    const body = $('#users-table tbody');
    body.innerHTML = users.map((u) => `
      <tr>
        <td class="mono">${u.id}</td>
        <td>${esc(u.username)}</td>
        <td>${ME.role === 'owner'
          ? `<select data-role="${u.id}">
               ${['staff', 'admin', 'owner'].map((r) =>
                 `<option value="${r}" ${r === u.role ? 'selected' : ''}>${r}</option>`).join('')}
             </select>`
          : `<span class="mono">${esc(u.role)}</span>`}</td>
        <td><span class="pill ${u.disabled ? 'off' : 'on'}">${u.disabled ? 'disabled' : 'active'}</span></td>
        <td class="right">
          <button class="ghost" data-pass="${u.id}">reset pw</button>
          ${ME.role === 'owner' ? `<button class="danger" data-deluser="${u.id}">delete</button>` : ''}
        </td>
      </tr>`).join('');

    for (const sel of body.querySelectorAll('[data-role]')) {
      sel.addEventListener('change', async () => {
        try {
          await api(`/api/admin/users/${sel.dataset.role}/role`, {
            method: 'POST', body: JSON.stringify({ role: sel.value }),
          });
          toast('role updated');
        } catch (e) { toast(e.message, true); }
      });
    }

    for (const btn of body.querySelectorAll('[data-pass]')) {
      btn.addEventListener('click', async () => {
        const pw = prompt('new password (min 6)');
        if (!pw) return;
        try {
          await api(`/api/admin/users/${btn.dataset.pass}/password`, {
            method: 'POST', body: JSON.stringify({ password: pw }),
          });
          toast('password changed');
        } catch (e) { toast(e.message, true); }
      });
    }

    for (const btn of body.querySelectorAll('[data-deluser]')) {
      btn.addEventListener('click', async () => {
        if (!confirm('delete this panel user?')) return;
        try {
          await api(`/api/admin/users/${btn.dataset.deluser}`, { method: 'DELETE' });
          toast('deleted');
          loadUsers();
        } catch (e) { toast(e.message, true); }
      });
    }
  } catch (e) { toast(e.message, true); }
}

$('#user-create').addEventListener('click', async () => {
  try {
    await api('/api/admin/users', {
      method: 'POST',
      body: JSON.stringify({
        username: $('#user-name').value.trim(),
        password: $('#user-pass').value,
        role: $('#user-role').value,
      }),
    });
    toast('panel user created');
    $('#user-name').value = '';
    $('#user-pass').value = '';
    loadUsers();
  } catch (e) { toast(e.message, true); }
});

// ── wiring ────────────────────────────────────────────────────────────────

$('#keys-refresh').addEventListener('click', loadKeys);
$('#users-refresh').addEventListener('click', loadUsers);

function clock() {
  $('#clock').textContent = new Date().toLocaleTimeString();
}

loadStats();
loadLive();
clock();
setInterval(clock, 1000);
setInterval(loadLive, 3_000);      // matches the client ping rate
setInterval(loadStats, 5_000);
