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
