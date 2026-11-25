// Console behaviour without inline script (CSP). Everything works without
// JavaScript too; this only adds dialogs and filtering.
//
// Device actions: menu entries with data-open show their dialog instead of
// following the link (the link to the commands tab stays as fallback).
document.addEventListener('click', (e) => {
  const open = e.target.closest('[data-open]');
  if (open) {
    const dlg = document.getElementById(open.dataset.open);
    if (dlg && dlg.showModal) {
      e.preventDefault();
      open.closest('details.menu')?.removeAttribute('open');
      dlg.showModal();
    }
    return;
  }
  const close = e.target.closest('[data-close]');
  if (close) close.closest('dialog')?.close();
});
// close the action menu when clicking elsewhere
document.addEventListener('click', (e) => {
  document.querySelectorAll('details.menu[open]').forEach((m) => { if (!m.contains(e.target)) m.removeAttribute('open'); });
});

// live filter: <input data-filter="table-id"> hides rows (tr[data-row]) that
// do not contain the text, and groups (tbody) without visible rows
document.addEventListener('input', (e) => {
  const input = e.target.closest('[data-filter]');
  if (!input) return;
  const table = document.getElementById(input.dataset.filter);
  if (!table) return;
  const q = input.value.trim().toLowerCase();
  table.querySelectorAll('tbody').forEach((body) => {
    let shown = 0;
    body.querySelectorAll('tr[data-row]').forEach((row) => {
      const hit = !q || row.textContent.toLowerCase().includes(q);
      row.hidden = !hit;
      if (hit) shown++;
    });
    body.hidden = shown === 0 && body.querySelector('tr[data-row]') !== null;
  });
});
// dialogs marked data-autoopen open on page load (results of a form post)
document.querySelectorAll('dialog[data-autoopen]').forEach((d) => d.showModal && d.showModal());

// forms with data-dialog-post="id" post in the background and show the
// [data-dialog-content] part of the answer in that dialog (recovery key)
document.addEventListener('submit', async (e) => {
  const form = e.target.closest('form[data-dialog-post]');
  const dlg = form && document.getElementById(form.dataset.dialogPost);
  if (!dlg || !dlg.showModal) return;
  e.preventDefault();
  const resp = await fetch(form.action, { method: 'POST', body: new FormData(form), credentials: 'same-origin' });
  const doc = new DOMParser().parseFromString(await resp.text(), 'text/html');
  const part = doc.querySelector('[data-dialog-content]');
  if (!resp.ok || !part) { form.submit(); return; }
  dlg.querySelector('[data-dialog-body]').replaceChildren(document.importNode(part, true));
  dlg.showModal();
});
// do not keep secrets in the page after a dialog closes
document.addEventListener('close', (e) => {
  const body = e.target.querySelector && e.target.querySelector('[data-dialog-body]');
  if (body) body.replaceChildren();
}, true);
document.addEventListener('click', async (e) => {
  const b = e.target.closest('[data-copy]');
  if (!b || !navigator.clipboard) return;
  await navigator.clipboard.writeText(b.dataset.copy);
  b.textContent = b.dataset.copied || '✓';
});

// library item editor: a type change swaps the example settings, unless the
// settings were edited (then only the example card changes)
document.addEventListener('change', (e) => {
  const sel = e.target.closest('select[data-examples]');
  if (!sel) return;
  let examples;
  try { examples = JSON.parse(document.getElementById(sel.dataset.examples).textContent); } catch { return; }
  const ex = examples[sel.value];
  if (ex === undefined) return;
  const card = document.getElementById(sel.dataset.exampleTarget);
  const area = sel.form && sel.form.querySelector('textarea[name=payload]');
  if (area) {
    const prev = sel.dataset.prevExample !== undefined ? sel.dataset.prevExample : (card ? card.textContent : '');
    const norm = (s) => s.replace(/\s+/g, '');
    if (area.value.trim() === '' || norm(area.value) === norm(prev)) area.value = ex;
  }
  if (card) card.textContent = ex;
  sel.dataset.prevExample = ex;
});

// add app: search Flathub through the server and add a hit with one click
document.addEventListener('submit', async (e) => {
  const form = e.target.closest('form[data-flathub-search]');
  if (!form) return;
  e.preventDefault();
  const box = form.closest('.flathub-search');
  const out = box.querySelector('[data-flathub-results]');
  const q = form.q.value.trim();
  out.replaceChildren();
  out.setAttribute('aria-busy', 'true');
  let hits = [];
  try {
    const r = await fetch('/software/flathub/search?q=' + encodeURIComponent(q), { credentials: 'same-origin' });
    if (r.ok) hits = await r.json();
  } catch { /* shown as empty */ }
  out.removeAttribute('aria-busy');
  if (!hits.length) {
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = out.dataset.empty;
    out.append(p);
    return;
  }
  for (const h of hits) {
    const card = document.createElement('form');
    card.method = 'post';
    card.action = '/software/flathub';
    card.className = 'flathub-hit';
    const add = (tag, cls, text) => { const el = document.createElement(tag); if (cls) el.className = cls; if (text) el.textContent = text; card.append(el); return el; };
    const icon = add('img', 'hit-icon');
    icon.alt = '';
    if (h.icon) icon.src = '/software/flathub/icon?u=' + encodeURIComponent(h.icon);
    const text = add('div', 'hit-text');
    const name = document.createElement('strong'); name.textContent = h.name; text.append(name);
    const sum = document.createElement('span'); sum.className = 'muted'; sum.textContent = h.summary || ''; text.append(sum);
    const meta = document.createElement('span'); meta.className = 'sub mono'; meta.textContent = [h.id, h.category, h.developer].filter(Boolean).join(' · '); text.append(meta);
    for (const [n, v] of [['csrf', box.dataset.csrf], ['id', h.id], ['mode', form.mode.value]]) {
      const i = document.createElement('input'); i.type = 'hidden'; i.name = n; i.value = v; card.append(i);
    }
    const b = add('button', 'small', out.dataset.add);
    b.type = 'submit';
    out.append(card);
  }
});
