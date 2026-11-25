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
