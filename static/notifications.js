// ── AETHER_SCAN Bildirim Sistemi ─────────────────────────────────────────────
// localStorage tabanlı, tüm sayfalar arasında paylaşımlı

const NOTIF_KEY = 'aether_notifications';
const MAX_NOTIFS = 50;

const LEVEL_CONFIG = {
  success: { icon: 'check_circle',    color: 'text-primary',   bg: 'bg-primary/10',   border: 'border-primary/30' },
  info:    { icon: 'info',            color: 'text-secondary', bg: 'bg-secondary/10', border: 'border-secondary/30' },
  warn:    { icon: 'warning',         color: 'text-[#eab308]', bg: 'bg-yellow-500/10',border: 'border-yellow-500/30' },
  error:   { icon: 'error',           color: 'text-error',     bg: 'bg-error/10',     border: 'border-error/30' },
};

function addNotification(title, body, level = 'info') {
  const notifs = getNotifications();
  notifs.unshift({
    id: Date.now(),
    title,
    body,
    level,
    time: new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }),
    read: false,
  });
  localStorage.setItem(NOTIF_KEY, JSON.stringify(notifs.slice(0, MAX_NOTIFS)));
  updateBadge();
  renderPanel();
}

function getNotifications() {
  try { return JSON.parse(localStorage.getItem(NOTIF_KEY) || '[]'); }
  catch { return []; }
}

function markAllRead() {
  const notifs = getNotifications().map(n => ({ ...n, read: true }));
  localStorage.setItem(NOTIF_KEY, JSON.stringify(notifs));
  updateBadge();
  renderPanel();
}

function clearNotifications() {
  localStorage.removeItem(NOTIF_KEY);
  updateBadge();
  renderPanel();
}

function getUnreadCount() {
  return getNotifications().filter(n => !n.read).length;
}

function updateBadge() {
  const badge = document.getElementById('notif-badge');
  const count = getUnreadCount();
  if (!badge) return;
  badge.textContent = count > 9 ? '9+' : count;
  badge.classList.toggle('hidden', count === 0);
}

function renderPanel() {
  const list = document.getElementById('notif-list');
  if (!list) return;
  const notifs = getNotifications();

  if (!notifs.length) {
    list.innerHTML = `<div class="py-8 text-center mono text-xs text-on-surface-variant">Bildirim yok.</div>`;
    return;
  }

  list.innerHTML = notifs.map(n => {
    const cfg = LEVEL_CONFIG[n.level] || LEVEL_CONFIG.info;
    return `
      <div class="flex items-start gap-3 px-4 py-3 border-b border-outline-variant/20 hover:bg-surface-variant/10 transition-colors ${n.read ? 'opacity-60' : ''}">
        <span class="material-symbols-outlined text-[18px] flex-shrink-0 mt-0.5 ${cfg.color}">${cfg.icon}</span>
        <div class="flex-1 min-w-0">
          <div class="text-xs font-semibold text-on-surface">${n.title}</div>
          <div class="text-[11px] text-on-surface-variant mt-0.5 break-words">${n.body}</div>
        </div>
        <div class="mono text-[10px] text-on-surface-variant flex-shrink-0">${n.time}</div>
      </div>`;
  }).join('');
}

function toggleNotifications() {
  const panel = document.getElementById('notif-panel');
  if (!panel) return;
  const isHidden = panel.classList.toggle('hidden');
  if (!isHidden) {
    markAllRead();
  }
}

// Dışarı tıklayınca kapat
document.addEventListener('click', (e) => {
  const panel = document.getElementById('notif-panel');
  const btn   = document.getElementById('notif-btn');
  if (panel && !panel.contains(e.target) && btn && !btn.contains(e.target)) {
    panel.classList.add('hidden');
  }
});

// Sayfa yüklenince rozeti güncelle
document.addEventListener('DOMContentLoaded', () => {
  updateBadge();
  renderPanel();
});
