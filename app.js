const $ = (id) => document.getElementById(id);
const state = { threats: [], stats: null, view: 'overview' };
const severityClass = (s) => `severity-${String(s).toLowerCase()}`;
const statusClass = (s) => `status-${String(s).toLowerCase()}`;
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const iconForType = (type) => ({Authentication:'⌁',Network:'⌘','Web Attack':'⚠',Endpoint:'▣',Malware:'◈',Other:'◇'}[type] || '◇');
function relativeTime(dateValue) {
  const diff = Math.max(0, Date.now() - new Date(dateValue).getTime());
  if (!Number.isFinite(diff)) return '—';
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
  return `${Math.floor(diff/86400000)}d ago`;
}
function threatRow(t, compact = false) {
  return `<tr>
    <td><div class="threat-name"><span class="threat-symbol">${iconForType(t.type)}</span><div><strong>${escapeHtml(t.title)}</strong><small>${escapeHtml(t.id)} · ${escapeHtml(t.asset)}</small></div></div></td>
    <td><span class="ip">${escapeHtml(t.sourceIp)}</span></td>
    ${compact ? '' : `<td>${escapeHtml(t.type)}</td>`}
    <td><span class="pill ${severityClass(t.severity)}">${escapeHtml(t.severity)}</span></td>
    <td><span class="pill ${statusClass(t.status)}">${escapeHtml(t.status)}</span></td>
    <td>${relativeTime(t.createdAt)}</td>
    ${compact ? `<td><button class="text-btn" data-view-threats="true">Details →</button></td>` : `<td><div class="table-actions"><select class="action-select" data-status-id="${escapeHtml(t.id)}" aria-label="Update status for ${escapeHtml(t.id)}"><option ${t.status==='Open'?'selected':''}>Open</option><option ${t.status==='Investigating'?'selected':''}>Investigating</option><option ${t.status==='Resolved'?'selected':''}>Resolved</option></select><button class="delete-btn" data-delete-id="${escapeHtml(t.id)}" title="Delete demo event">Delete</button></div></td>`}
  </tr>`;
}
async function api(url, options = {}) {
  const response = await fetch(url, { headers: {'Content-Type':'application/json', ...(options.headers || {})}, ...options });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}
async function loadData() {
  try {
    const [threatData, stats] = await Promise.all([api('/api/threats'), api('/api/stats')]);
    state.threats = threatData.data || [];
    state.stats = stats;
    $('apiStatus').textContent = 'Connected';
    $('storageMode').textContent = 'Online';
    $('navCount').textContent = stats.open;
    renderOverview();
    renderThreats();
    renderAnalytics();
    return true;
  } catch (err) {
    $('apiStatus').textContent = 'Offline';
    showToast(`Could not load dashboard: ${err.message}`);
    return false;
  }
}
async function checkHealth() {
  try {
    const data = await api('/api/health');
    $('apiStatus').textContent = 'Connected';
    $('storageMode').textContent = data.storage === 'mongodb' ? 'MongoDB' : 'Local JSON';
  } catch {
    $('apiStatus').textContent = 'Offline';
    $('storageMode').textContent = 'Unavailable';
  }
}
function renderOverview() {
  const s = state.stats;
  if (!s) return;
  $('totalStat').textContent = s.total;
  $('openStat').textContent = s.open;
  $('criticalStat').textContent = s.critical;
  $('resolvedStat').textContent = s.resolved;
  $('recentBody').innerHTML = state.threats.slice(0,5).map(t => threatRow(t,true)).join('');
  $('recentEmpty').classList.toggle('hidden', state.threats.length > 0);
  $('statusTotal').textContent = s.total;
  $('legendOpen').textContent = s.open;
  $('legendInvestigating').textContent = s.investigating;
  $('legendResolved').textContent = s.resolved;
  const total = Math.max(s.total, 1);
  const openDeg = s.open/total*360;
  const investigatingDeg = s.investigating/total*360;
  $('statusDonut').style.background = `conic-gradient(#f59e0b 0deg ${openDeg}deg,#7357e8 ${openDeg}deg ${openDeg+investigatingDeg}deg,#27b78b ${openDeg+investigatingDeg}deg 360deg)`;
  const items = [
    ['Critical',s.bySeverity.Critical || 0,'critical-bg'],
    ['High',s.bySeverity.High || 0,'high-bg'],
    ['Medium',s.bySeverity.Medium || 0,'medium-bg'],
    ['Low',s.bySeverity.Low || 0,'low-bg']
  ];
  const max = Math.max(1,...items.map(x=>x[1]));
  $('severityChart').innerHTML = items.map(([label,count,cls]) => `<div class="bar-group"><span class="bar-count">${count}</span><div class="bar-outer"><div class="bar-inner ${cls}" style="height:${Math.max(count ? 7 : 2,count/max*100)}%"></div></div><span class="bar-label">${label}</span></div>`).join('');
}
function renderThreats() {
  const search = $('searchInput').value.trim().toLowerCase();
  const severity = $('severityFilter').value;
  const status = $('statusFilter').value;
  const type = $('typeFilter').value;
  const list = state.threats.filter(t =>
    (!search || [t.id,t.title,t.sourceIp,t.asset,t.type].some(v => String(v).toLowerCase().includes(search))) &&
    (!severity || t.severity === severity) && (!status || t.status === status) && (!type || t.type === type)
  );
  $('threatsBody').innerHTML = list.map(t => threatRow(t,false)).join('');
  $('threatsEmpty').classList.toggle('hidden', list.length > 0);
  $('resultCount').textContent = `${list.length} result${list.length===1?'':'s'}`;
}
function renderAnalytics() {
  const s = state.stats;
  if (!s) return;
  const types = Object.entries(s.byType || {}).sort((a,b)=>b[1]-a[1]);
  const maxType = Math.max(1,...types.map(x=>x[1]));
  $('typeChart').innerHTML = types.length ? types.map(([name,count]) => `<div class="type-row"><span>${escapeHtml(name)}</span><div class="type-track"><div class="type-fill" style="width:${count/maxType*100}%"></div></div><strong>${count}</strong></div>`).join('') : '<div class="empty-state">No data yet.</div>';
  const order = [['Critical','critical-bg'],['High','high-bg'],['Medium','medium-bg'],['Low','low-bg']];
  $('severitySummary').innerHTML = order.map(([name,cls]) => {
    const count = s.bySeverity[name] || 0;
    return `<div class="summary-row"><span>${name}</span><div class="summary-track"><div class="summary-fill ${cls}" style="width:${s.total ? count/s.total*100 : 0}%"></div></div><strong>${s.total ? Math.round(count/s.total*100) : 0}%</strong></div>`;
  }).join('');
}
function showToast(message) {
  const toast = $('toast');
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove('show'), 3000);
}
function setView(view) {
  state.view = view;
  document.querySelectorAll('.nav-link').forEach(a => a.classList.toggle('active', a.dataset.view === view));
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active-page'));
  $(`${view}Page`).classList.add('active-page');
  $('pageName').textContent = view === 'overview' ? 'Overview' : view === 'threats' ? 'Threat activity' : 'Analytics';
  $('sidebar').classList.remove('open');
}
function openModal() {
  $('threatForm').reset();
  $('formError').classList.add('hidden');
  $('modalBackdrop').classList.remove('hidden');
  setTimeout(() => $('threatForm').elements.title.focus(), 30);
}
function closeModal() { $('modalBackdrop').classList.add('hidden'); }
document.querySelectorAll('.nav-link').forEach(a => a.addEventListener('click', e => { e.preventDefault(); setView(a.dataset.view); }));
$('menuBtn').addEventListener('click', () => $('sidebar').classList.toggle('open'));
$('addThreatBtn').addEventListener('click', openModal);
$('addThreatBtn2').addEventListener('click', openModal);
$('closeModal').addEventListener('click', closeModal);
$('cancelModal').addEventListener('click', closeModal);
$('modalBackdrop').addEventListener('click', e => { if (e.target === $('modalBackdrop')) closeModal(); });
$('viewAllBtn').addEventListener('click', () => setView('threats'));
$('refreshBtn').addEventListener('click', async () => { await loadData(); await checkHealth(); showToast('Dashboard refreshed'); });
$('analyticsRefresh').addEventListener('click', async () => { await loadData(); showToast('Analytics refreshed'); });
['searchInput','severityFilter','statusFilter','typeFilter'].forEach(id => $(id).addEventListener(id==='searchInput'?'input':'change', renderThreats));
document.addEventListener('click', async e => {
  const viewBtn = e.target.closest('[data-view-threats]');
  if (viewBtn) { setView('threats'); return; }
  const deleteBtn = e.target.closest('[data-delete-id]');
  if (deleteBtn) {
    const id = deleteBtn.dataset.deleteId;
    if (!confirm(`Delete demo threat ${id}?`)) return;
    try { await api(`/api/threats/${encodeURIComponent(id)}`, {method:'DELETE'}); showToast('Threat deleted'); await loadData(); }
    catch (err) { showToast(err.message); }
  }
});
document.addEventListener('change', async e => {
  const select = e.target.closest('[data-status-id]');
  if (!select) return;
  try {
    await api(`/api/threats/${encodeURIComponent(select.dataset.statusId)}`, {method:'PATCH', body:JSON.stringify({status:select.value})});
    showToast('Threat status updated');
    await loadData();
  } catch (err) { showToast(err.message); }
});
$('threatForm').addEventListener('submit', async e => {
  e.preventDefault();
  const form = new FormData(e.currentTarget);
  const payload = Object.fromEntries(form.entries());
  const btn = $('saveThreatBtn');
  btn.disabled = true;
  btn.textContent = 'Saving…';
  $('formError').classList.add('hidden');
  try {
    await api('/api/threats', {method:'POST', body:JSON.stringify(payload)});
    closeModal();
    showToast('Threat event added successfully');
    await loadData();
    setView('threats');
  } catch (err) {
    $('formError').textContent = err.message;
    $('formError').classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save threat';
  }
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
checkHealth();
loadData();
setInterval(() => { if (!document.hidden) loadData(); }, 30000);
