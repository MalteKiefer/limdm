// Console behaviour without inline script (CSP). Everything works without
// JavaScript too; this only adds dialogs, filtering and bulk selection.
// One delegated listener per event type; each handler returns early when
// the event is not its business.
(() => {
  'use strict';
  document.documentElement.classList.add('js'); // hides what only makes sense with a selection

  // el builds an element with an optional class and text (never innerHTML)
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text) n.textContent = text;
    return n;
  };

  // ---- click ----
  document.addEventListener('click', async (e) => {
    const t = e.target;
    // close open action menus when clicking elsewhere
    for (const m of document.querySelectorAll('details.menu[open]')) if (!m.contains(t)) m.removeAttribute('open');

    // [data-confirm] asks in the console's own dialog, then submits with that button
    const confirmBtn = t.closest('[data-confirm]');
    const dlg = document.getElementById('dlg-confirm');
    if (confirmBtn && dlg && dlg.showModal && !confirmBtn.dataset.confirmed) {
      e.preventDefault();
      dlg.querySelector('[data-confirm-text]').textContent = confirmBtn.dataset.confirm;
      const ok = dlg.querySelector('[data-confirm-ok]');
      ok.className = confirmBtn.classList.contains('danger') || confirmBtn.classList.contains('warn') ? 'danger' : '';
      ok.onclick = () => {
        dlg.close();
        confirmBtn.dataset.confirmed = '1';
        if (confirmBtn.form) confirmBtn.form.requestSubmit(confirmBtn.type === 'submit' || confirmBtn.tagName === 'BUTTON' ? confirmBtn : undefined);
        else confirmBtn.click();
        delete confirmBtn.dataset.confirmed;
      };
      dlg.showModal();
      return;
    }

    // menu entries with data-open show their dialog instead of following the link
    const open = t.closest('[data-open]');
    if (open) {
      const dlg = document.getElementById(open.dataset.open);
      if (dlg && dlg.showModal) {
        e.preventDefault();
        open.closest('details.menu')?.removeAttribute('open');
        dlg.showModal();
      }
      return;
    }
    const navToggle = t.closest('[data-nav-toggle]');
    if (navToggle) {
      const side = document.getElementById(navToggle.getAttribute('aria-controls'));
      navToggle.setAttribute('aria-expanded', String(side.classList.toggle('open')));
      return;
    }
    const close = t.closest('[data-close]');
    if (close) { close.closest('dialog')?.close(); return; }

    // [data-pwgen="min length"] fills the password and its repeat field with
    // a generated password and shows it once with a copy button
    const gen = t.closest('[data-pwgen]');
    if (gen) {
      const pw = genPassword(Number(gen.dataset.pwgen) || 12);
      const scope = gen.closest('form');
      for (const f of scope.querySelectorAll('input[name=password], input[name=password2]')) { f.value = pw; f.setCustomValidity(''); }
      const out = gen.parentElement.querySelector('[data-pwgen-out]');
      const cp = gen.parentElement.querySelector('[data-copy]');
      out.textContent = pw; out.hidden = false;
      cp.dataset.copy = pw; cp.hidden = false;
      return;
    }

    // [data-copy] copies its value, [data-copy-from] the text of the element it names
    const copy = t.closest('[data-copy], [data-copy-from]');
    if (copy && navigator.clipboard) {
      const src = copy.dataset.copyFrom && document.getElementById(copy.dataset.copyFrom);
      await navigator.clipboard.writeText(src ? src.textContent.trim() : copy.dataset.copy);
      const label = copy.textContent;
      copy.textContent = copy.dataset.copied || '✓';
      setTimeout(() => { copy.textContent = label; }, 2000);
    }
  });

  // genPassword returns a random password of at least 16 characters with an
  // uppercase and a lowercase letter, a digit and a symbol, so it meets every
  // combination of the password policy's character classes
  const genPassword = (min) => {
    const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '-_.!#%+=?'];
    const all = sets.join('');
    const rnd = (n) => { // uniform in [0, n) without modulo bias
      const lim = Math.floor(0x100000000 / n) * n, buf = new Uint32Array(1);
      do crypto.getRandomValues(buf); while (buf[0] >= lim);
      return buf[0] % n;
    };
    const chars = sets.map((s) => s[rnd(s.length)]);
    while (chars.length < Math.max(min, 16)) chars.push(all[rnd(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) { const j = rnd(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
    return chars.join('');
  };

  // ---- live filter: <input data-filter="table-id"> ----
  // Hides rows (tr[data-row]) without the text and groups (tbody) without
  // visible rows. Row texts are lowercased once; typing is debounced.
  const rowText = new WeakMap();
  let pending = null;
  const filter = (input) => {
    const table = document.getElementById(input.dataset.filter);
    if (!table) return; // a table or an element around tables
    const q = input.value.trim().toLowerCase();
    for (const body of table.querySelectorAll('tbody')) { // the target may wrap several tables
      let shown = 0, rows = 0;
      for (const row of body.querySelectorAll('tr[data-row]')) {
        rows++;
        let text = rowText.get(row);
        if (text === undefined) { text = row.textContent.toLowerCase(); rowText.set(row, text); }
        const hit = !q || text.includes(q);
        if (row.hidden === hit) row.hidden = !hit;
        if (hit) shown++;
      }
      body.hidden = rows > 0 && shown === 0;
    }
  };
  // a repeat field ([data-match="name"]) must equal the field it names
  document.addEventListener('input', (e) => {
    const form = e.target.form;
    const rep = form && form.querySelector('[data-match]');
    if (rep && (e.target === rep || e.target.name === rep.dataset.match)) {
      const orig = form.querySelector(`[name="${CSS.escape(rep.dataset.match)}"]`);
      rep.setCustomValidity(rep.value && orig && rep.value !== orig.value ? rep.dataset.mismatch : '');
    }
  });
  document.addEventListener('input', (e) => {
    const input = e.target.closest('[data-filter]');
    if (!input) return;
    clearTimeout(pending);
    pending = setTimeout(() => filter(input), 60);
  });

  // ---- device list: select all, selection count, bulk bar only with a selection ----
  const bulkSync = () => {
    const form = document.querySelector('form[data-bulk]');
    if (!form) return;
    const fid = form.getAttribute('id'); // form.id would be the checkboxes named id
    const boxes = document.querySelectorAll('input[form="' + fid + '"][name=id]');
    let n = 0;
    for (const b of boxes) if (b.checked) n++;
    form.querySelector('[data-bulk-count]').textContent = n;
    form.classList.toggle('active', n > 0);
    const all = document.querySelector('[data-select-all="' + fid + '"]');
    if (all) { all.checked = n > 0 && n === boxes.length; all.indeterminate = n > 0 && n < boxes.length; }
  };

  // library item editor: a type change swaps the example settings, unless the
  // settings were edited (then only the example card changes)
  const swapExample = (sel) => {
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
  };

  // library item editor: description, documentation link and field
  // reference follow the type picker
  const swapMeta = (sel) => {
    let meta;
    try { meta = JSON.parse(document.getElementById(sel.dataset.meta).textContent)[sel.value]; } catch { return; }
    if (!meta) return;
    const form = sel.closest('form').parentElement;
    const desc = form.querySelector('[data-type-desc]'), doc = form.querySelector('[data-type-doc]'), body = form.querySelector('[data-type-fields]');
    if (desc) desc.textContent = meta.desc;
    if (doc) doc.href = meta.doc;
    if (body) body.replaceChildren(...(meta.fields || []).map(([p, k]) => {
      const tr = el('tr'); tr.append(el('td', 'mono', p), el('td', 'muted', k)); return tr;
    }));
  };

  // JSON settings: live syntax check and a format button
  const jsonCheck = (area) => {
    const state = area.form && area.form.querySelector('[data-json-state]');
    if (!state) return null;
    try {
      const v = area.value.trim() === '' ? null : JSON.parse(area.value);
      state.textContent = v === null ? '' : state.dataset.ok;
      state.classList.remove('bad');
      area.setCustomValidity('');
      return v;
    } catch (err) {
      state.textContent = state.dataset.bad + ' ' + err.message;
      state.classList.add('bad');
      return undefined;
    }
  };
  let jsonTimer = null;
  document.addEventListener('input', (e) => {
    if (!e.target.matches('textarea[data-json-check]')) return;
    clearTimeout(jsonTimer);
    jsonTimer = setTimeout(() => jsonCheck(e.target), 250);
  });
  document.addEventListener('click', (e) => {
    const b = e.target.closest('[data-json-format]');
    const area = b && b.form && b.form.querySelector('textarea[data-json-check]');
    if (!area) return;
    const v = jsonCheck(area);
    if (v !== undefined && v !== null) area.value = JSON.stringify(v, null, 2);
  });

  // ---- change ----
  document.addEventListener('change', (e) => {
    const t = e.target;
    const all = t.closest('[data-select-all]');
    if (all) {
      for (const b of document.querySelectorAll('input[form="' + all.dataset.selectAll + '"][name=id]')) b.checked = all.checked;
      bulkSync();
    } else if (t.matches('input[name=id][form]')) {
      bulkSync();
    } else if (t.matches('select[data-autosubmit]')) {
      t.form.submit();
    } else if (t.matches('select[data-examples]')) {
      swapExample(t);
      if (t.dataset.meta) swapMeta(t);
    }
  });

  // ---- submit ----
  // forms with data-dialog-post="id" post in the background and show the
  // [data-dialog-content] part of the answer in that dialog (recovery key)
  const dialogPost = async (form, dlg) => {
    const resp = await fetch(form.action, { method: 'POST', body: new FormData(form), credentials: 'same-origin' });
    const doc = new DOMParser().parseFromString(await resp.text(), 'text/html');
    const part = doc.querySelector('[data-dialog-content]');
    if (!resp.ok || !part) { form.submit(); return; }
    dlg.querySelector('[data-dialog-body]').replaceChildren(document.importNode(part, true));
    dlg.showModal();
  };

  // add app: search Flathub through the server and add a hit with one click
  const flathubSearch = async (form) => {
    const box = form.closest('.flathub-search');
    const out = box.querySelector('[data-flathub-results]');
    out.replaceChildren();
    out.setAttribute('aria-busy', 'true');
    let hits = [];
    try {
      const r = await fetch('/software/flathub/search?q=' + encodeURIComponent(form.q.value.trim()), { credentials: 'same-origin' });
      if (r.ok) hits = await r.json();
    } catch { /* shown as empty */ }
    out.removeAttribute('aria-busy');
    if (!hits.length) { out.append(el('p', 'muted', out.dataset.empty)); return; }
    const frag = document.createDocumentFragment();
    for (const h of hits) {
      const card = el('form', 'flathub-hit');
      card.method = 'post';
      card.action = '/software/flathub';
      const icon = el('img', 'hit-icon');
      icon.alt = '';
      icon.width = icon.height = 44;
      icon.loading = 'lazy';
      if (h.icon) icon.src = '/software/flathub/icon?u=' + encodeURIComponent(h.icon);
      const text = el('div', 'hit-text');
      text.append(el('strong', '', h.name), el('span', 'muted', h.summary || ''),
        el('span', 'sub mono', [h.id, h.category, h.developer].filter(Boolean).join(' · ')));
      card.append(icon, text);
      for (const [n, v] of [['csrf', box.dataset.csrf], ['id', h.id], ['mode', form.mode.value]]) {
        const i = el('input'); i.type = 'hidden'; i.name = n; i.value = v; card.append(i);
      }
      const b = el('button', 'small', out.dataset.add);
      b.type = 'submit';
      card.append(b);
      frag.append(card);
    }
    out.append(frag);
  };

  // action menus: arrow keys move between the entries of one level, Right
  // opens a submenu, Left returns from it, Home and End jump, Escape closes
  // the menu and returns to its button
  const levelItems = (list) => [...list.querySelectorAll(':scope > [role=menuitem], :scope > form > [role=menuitem], :scope > .sub > .sub-head')];
  document.addEventListener('keydown', (e) => {
    const menu = e.target.closest && e.target.closest('details.menu');
    if (!menu || !['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight', 'Home', 'End', 'Escape'].includes(e.key)) return;
    if (e.target.matches('input, textarea, select')) return;
    const summary = menu.querySelector('summary');
    if (e.key === 'Escape') {
      if (menu.open) { e.preventDefault(); menu.removeAttribute('open'); summary.focus(); }
      return;
    }
    e.preventDefault();
    if (!menu.open) menu.setAttribute('open', '');
    const cur = document.activeElement;
    if (e.key === 'ArrowRight' && cur.matches('.sub-head')) { levelItems(cur.nextElementSibling)[0]?.focus(); return; }
    if (e.key === 'ArrowLeft') { cur.closest('.sub')?.querySelector('.sub-head')?.focus(); return; }
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') return;
    const list = (cur !== summary && cur.closest('.sub-list, .menu-list')) || menu.querySelector('.menu-list');
    const items = levelItems(list);
    if (!items.length) return;
    const i = items.indexOf(cur);
    let n = 0;
    if (e.key === 'End') n = items.length - 1;
    else if (e.key === 'ArrowDown') n = i < 0 ? 0 : (i + 1) % items.length;
    else if (e.key === 'ArrowUp') n = i < 0 ? items.length - 1 : (i - 1 + items.length) % items.length;
    items[n].focus();
  });

  // Enter in a field with data-enter submits with that field's own button,
  // not with the form's first one ("Sync now" in the bulk bar)
  document.addEventListener('keydown', (e) => {
    const name = e.key === 'Enter' && e.target.dataset && e.target.dataset.enter;
    const btn = name && e.target.form && e.target.form.querySelector(`button[name="action"][value="${CSS.escape(name)}"]`);
    if (btn) { e.preventDefault(); e.target.form.requestSubmit(btn); }
  });

  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (form.matches('form[data-flathub-search]')) { e.preventDefault(); flathubSearch(form); return; }
    const dlg = form.dataset.dialogPost && document.getElementById(form.dataset.dialogPost);
    if (dlg && dlg.showModal) { e.preventDefault(); dialogPost(form, dlg); }
  });

  // do not keep secrets in the page after a dialog closes
  document.addEventListener('close', (e) => {
    const body = e.target.querySelector && e.target.querySelector('[data-dialog-body]');
    if (body) body.replaceChildren();
  }, true);

  // flyout submenus open to the side with room; measured once per entry
  let lastSub = null;
  const placeSub = (e) => {
    const sub = e.target.closest('.menu-list .sub');
    if (!sub || sub === lastSub) return;
    lastSub = sub;
    const r = sub.getBoundingClientRect();
    sub.classList.toggle('right', r.left < 250 && window.innerWidth - r.right > r.left);
  };
  document.addEventListener('mouseover', placeSub, { passive: true });
  document.addEventListener('focusin', placeSub);

  // pages with running work reload until it is done ([data-refresh] seconds),
  // but not while the user types or a dialog or menu is open
  const refresh = document.querySelector('[data-refresh]');
  if (refresh) {
    setTimeout(function reload() {
      const busy = document.querySelector('dialog[open], details.menu[open]') || document.activeElement?.matches('input, textarea, select');
      if (busy) { setTimeout(reload, 2000); return; }
      location.reload();
    }, Number(refresh.dataset.refresh || 5) * 1000);
  }

  // dialogs marked data-autoopen open on page load (results of a form post)
  for (const d of document.querySelectorAll('dialog[data-autoopen]')) d.showModal && d.showModal();
  bulkSync();
})();
