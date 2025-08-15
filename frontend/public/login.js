const API_BASE = (window.API_BASE) || 'http://localhost:8000/api';
let threatChart, domainsChart;
let refreshHandle = null;
let paused = false;
let ingestModalOpen = false;
let suppressAutoScroll = true; // prevents any scripted scroll adjustments
let ws = null;
let recentAlertsBuffer = [];
const MAX_ALERTS = 20;

function isNearBottom() {
  return (window.innerHeight + window.scrollY) >= (document.body.offsetHeight - 48);
}

function scheduleRefresh() {
  if (refreshHandle) clearInterval(refreshHandle);
  refreshHandle = setInterval(() => {
    if (paused) return;
    // Only refresh if user is near top to avoid shifting scroll context
    if (window.scrollY < 300 && !ingestModalOpen) {
      loadData();
    }
  }, 20000);
}

function getTokenFromFragment() {
  const hash = window.location.hash;
  if (!hash.startsWith('#')) return null;
  const params = new URLSearchParams(hash.substring(1));
  return params.get('token');
}

function setAuth(token, refreshToken, expiresInSeconds) {
  if (token) {
    localStorage.setItem('authToken', token);
    if (refreshToken) localStorage.setItem('refreshToken', refreshToken);
    if (expiresInSeconds) {
      const exp = Date.now() + (expiresInSeconds * 1000) - 5000; // small skew
      localStorage.setItem('authTokenExpiry', String(exp));
    }
    document.getElementById('authStatus').textContent = 'Authenticated';
    document.getElementById('loginBtn').style.display = 'none';
    document.getElementById('logoutBtn').style.display = 'inline-block';
    document.getElementById('dashboard').style.display = 'block';
  } else {
    localStorage.removeItem('authToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('authTokenExpiry');
    document.getElementById('authStatus').textContent = 'Not authenticated';
    document.getElementById('loginBtn').style.display = 'inline-block';
    document.getElementById('logoutBtn').style.display = 'none';
    document.getElementById('dashboard').style.display = 'none';
  }
}

let refreshing = null; // Promise when refresh in progress

async function refreshAccessToken() {
  if (refreshing) return refreshing; // de-duplicate concurrent refreshes
  const rt = localStorage.getItem('refreshToken');
  if (!rt) {
    setAuth(null); return Promise.reject(new Error('No refresh token'));
  }
  refreshing = (async () => {
    try {
      const res = await fetch(`${API_BASE}/users/token/refresh`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: rt })
      });
      if (!res.ok) throw new Error('Refresh failed');
      const data = await res.json();
      if (!data.access_token) throw new Error('No access token');
      setAuth(data.access_token, data.refresh_token || rt, data.expires_in || 900);
      return data.access_token;
    } catch (e) {
      setAuth(null); throw e;
    } finally { refreshing = null; }
  })();
  return refreshing;
}

function accessTokenValidSoon() {
  const exp = parseInt(localStorage.getItem('authTokenExpiry') || '0', 10);
  if (!exp) return false;
  return Date.now() < exp && (exp - Date.now()) < 30000; // <30s left
}

async function fetchWithAuth(path, opts = {}, retry = true) {
  let token = localStorage.getItem('authToken');
  if (token && accessTokenValidSoon()) {
    try { token = await refreshAccessToken(); } catch { /* fallthrough */ }
  }
  const headers = Object.assign({ 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }, opts.headers || {});
  const res = await fetch(`${API_BASE}${path}`, { ...opts, headers });
  if (res.status === 401 && retry) {
    try {
      await refreshAccessToken();
      return fetchWithAuth(path, opts, false);
    } catch {
      setAuth(null); throw new Error('Unauthorized');
    }
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  if (res.status === 204) return null;
  return res.json();
}

async function loadData() {
  if (paused || isNearBottom()) return;
  try {
    const [analytics, threats, devices, summary, collectors, endpoints] = await Promise.all([
      fetchWithAuth('/dns/analytics/network'),
      fetchWithAuth('/dns/threats?limit=5'),
      fetchWithAuth('/dns/devices'),
      fetchWithAuth('/dns/threats/summary'),
      fetchWithAuth('/dns/collectors').catch(()=>[]),
      fetchWithAuth('/dns/endpoints').catch(()=>[])
    ]);
  // cache for delta updates
  window.__lastTopBlockedDomains = analytics.top_blocked_domains || [];
  window.__lastThreatTimeline = analytics.threat_timeline || [];
  console.log('Analytics loaded', analytics.total_queries_24h, analytics.blocked_queries_24h);
    updateStats(analytics);
    updateDevices(devices);
    updateAlerts(threats);
    updateCharts(summary, analytics);
    updateCollectors(collectors);
    updateEndpoints(endpoints);
  } catch (e) {
    console.error(e);
  }
}

function initCharts() {
  const tEl = document.getElementById('threatChart');
  const dEl = document.getElementById('domainsChart');
  if (!tEl || !dEl) return;
  const tctx = tEl.getContext('2d');
  threatChart = new Chart(tctx, {
    type: 'line',
  data: { labels: [], datasets: [{ label: 'Threats', data: [], borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.15)', tension: 0.3, fill: true }]},
  options: { responsive:true, maintainAspectRatio:false, animation: { duration: 0 }, scales:{ y:{ beginAtZero:true } } }
  });
  const dctx = dEl.getContext('2d');
  domainsChart = new Chart(dctx, {
    type: 'doughnut',
  data: { labels: [], datasets: [{ data: [], backgroundColor: ['#ef4444','#f59e0b','#0ea5e9','#10b981','#6366f1'] }]},
  options: { responsive:true, maintainAspectRatio:false, animation: { duration: 0 } }
  });
}

function updateStats(analytics) {
  const tq = document.getElementById('totalQueries');
  if (!tq) return; // not on dashboard
  tq.textContent = (analytics.total_queries_24h || 0).toLocaleString();
  document.getElementById('blockedQueries').textContent = (analytics.blocked_queries_24h || 0).toLocaleString();
  document.getElementById('activeDevices').textContent = analytics.active_devices || 0;
  const top = analytics.top_blocked_domains || [];
  domainsChart.data.labels = top.map(d => d.domain);
  domainsChart.data.datasets[0].data = top.map(d => d.count);
  domainsChart.update();
}

function updateDevices(devices) {
  const c = document.getElementById('devicesList');
  if (!c) return;
  c.innerHTML = '';
  devices.forEach(d => {
    const isActive = d.is_active && new Date() - new Date(d.last_seen) < 3600000;
    const el = document.createElement('div');
    el.className = 'device';
    el.innerHTML = `<div><div><strong>${d.name}</strong></div><div class="hint">${d.ip_address}</div></div><div class="badge ${isActive?'ok':'off'}">${isActive?'Active':'Inactive'}</div>`;
    c.appendChild(el);
  });
}

function updateCollectors(list) {
  const c = document.getElementById('collectorsList');
  if (!c) return; c.innerHTML='';
  list.forEach(col => {
    const el = document.createElement('div');
    el.className='row';
    el.innerHTML = `<div><strong>${col.name}</strong><div class="hint">${col.uuid}</div></div><div class="endpoint-status ${col.status}">${col.status||''}</div>`;
    c.appendChild(el);
  });
  if (!list.length) c.innerHTML = '<div class="hint">No collectors yet.</div>';
}

function updateEndpoints(list) {
  const c = document.getElementById('endpointsList');
  if (!c) return; c.innerHTML='';
  list.forEach(ep => {
    const el = document.createElement('div');
    el.className='row';
    const name = ep.friendly_name || ep.hostname || ep.mac_address;
    el.innerHTML = `<div style="flex:1; overflow:hidden;">
        <div style="font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${name}</div>
        <div class="hint">${ep.mac_address}${ep.ip_address? ' • '+ep.ip_address:''}</div>
      </div>
      <div style="display:flex; gap:4px; align-items:center;">
        <span class="endpoint-status ${ep.status}">${ep.status}</span>
        <input class="label-edit" data-ep="${ep.id}" value="${ep.friendly_name||''}" placeholder="Label" />
      </div>`;
    c.appendChild(el);
  });
  if (!list.length) c.innerHTML = '<div class="hint">Endpoints appear automatically as traffic is observed.</div>';
  // Attach change listeners
  c.querySelectorAll('input.label-edit').forEach(inp => {
    inp.addEventListener('change', async (e) => {
      const id = e.target.getAttribute('data-ep');
      const val = e.target.value.trim();
      try {
        await fetchWithAuth(`/dns/endpoints/${id}`, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ friendly_name: val || null }) });
        loadData();
      } catch(err) { console.error('Label update failed', err); }
    });
  });
}

function updateAlerts(threats) {
  const c = document.getElementById('alertsList');
  if (!c) return;
  c.innerHTML = '';
  threats.forEach(t => {
    const el = document.createElement('div');
    el.className = 'device';
    el.innerHTML = `<div><div><strong>${(t.threat_type || '').replace('_',' ').toUpperCase()}</strong></div><div class="hint">${t.description || ''}</div></div><div class="badge ${t.threat_level==='critical' || t.threat_level==='high' ? 'off' : 'ok'}">${t.threat_level || ''}</div>`;
    c.appendChild(el);
  });
}

function updateCharts(summary, analytics) {
  if (!threatChart) return;
  const timeline = analytics && Array.isArray(analytics.threat_timeline) ? analytics.threat_timeline : [];
  const labels = timeline.map(b => {
    try {
      const d = new Date(b.time);
      return `${String(d.getHours()).padStart(2,'0')}:00`;
    } catch { return ''; }
  });
  const data = timeline.map(b => b.threats || 0);
  threatChart.data.labels = labels;
  threatChart.data.datasets[0].data = data;
  threatChart.update();
}

async function startOAuth() {
  try {
  const res = await fetch(`${API_BASE}/users/oauth/google/login`);
    const data = await res.json();
    if (!data.authorization_url) throw new Error('No auth URL');
    window.location.href = data.authorization_url;
  } catch (e) {
    console.error('OAuth start failed', e);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const tokenFromHash = getTokenFromFragment();
  if (tokenFromHash) {
    // Clear fragment quickly to avoid reusing token on refresh
    history.replaceState(null, '', window.location.pathname + window.location.search);
    setAuth(tokenFromHash, localStorage.getItem('refreshToken'), 900);
  } else {
    const existing = localStorage.getItem('authToken');
    if (existing) setAuth(existing, localStorage.getItem('refreshToken'), (parseInt(localStorage.getItem('authTokenExpiry')||'0',10)-Date.now())/1000);
    else setAuth(null);
  }

  if (localStorage.getItem('authToken')) {
    initCharts();
    loadData();
    scheduleRefresh();
  initStream();
  }

  document.getElementById('loginBtn').addEventListener('click', startOAuth);
  document.getElementById('emailBtn').addEventListener('click', () => {
    document.getElementById('emailLogin').style.display = 'block';
  });
  document.getElementById('cancelEmail').addEventListener('click', () => {
    document.getElementById('emailLogin').style.display = 'none';
  });
  document.getElementById('emailForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const err = document.getElementById('emailError');
    err.style.display = 'none';
    try {
      const form = new URLSearchParams();
      form.append('username', email);
      form.append('password', password);
      const res = await fetch(`${API_BASE}/users/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString()
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(`Login failed: ${t}`);
      }
      const data = await res.json();
      if (data && data.access_token) {
        setAuth(data.access_token, data.refresh_token, data.expires_in);
        document.getElementById('emailLogin').style.display = 'none';
        loadData();
      } else if (data && data["2fa_required"]) {
        err.textContent = '2FA is enabled; use Google login or implement 2FA UI.';
        err.style.display = 'block';
      } else {
        throw new Error('Invalid login response');
      }
    } catch (e) {
      err.textContent = e.message;
      err.style.display = 'block';
    }
  });
  document.getElementById('registerBtn').addEventListener('click', async () => {
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const err = document.getElementById('emailError');
    err.style.display = 'none';
    try {
      const res = await fetch(`${API_BASE}/users/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: email.split('@')[0] || 'user', email, password })
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(`Register failed: ${t}`);
      }
      const regData = await res.json();
      // Attempt auto-verification if a dev token is returned; then auto-login
      let autoLogin = false;
      if (regData.verification_token_dev) {
        try {
          const v = await fetch(`${API_BASE}/users/verify/${regData.verification_token_dev}`);
          if (v.ok) {
            autoLogin = true;
          } else {
            // fallback: show manual verification message
            err.textContent = `Registered. Check email or paste dev token: ${regData.verification_token_dev}`;
            err.style.display = 'block';
          }
        } catch {
          err.textContent = `Registered. Verify with token: ${regData.verification_token_dev}`;
          err.style.display = 'block';
        }
      } else {
        // Either auto-verified or email already existed
        autoLogin = true;
      }
      if (autoLogin) {
        // Perform login automatically using provided credentials
        const form = new URLSearchParams();
        form.append('username', email);
        form.append('password', password);
        try {
          const loginRes = await fetch(`${API_BASE}/users/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: form.toString()
          });
          if (!loginRes.ok) {
            const t = await loginRes.text();
            throw new Error(`Login after register failed: ${t}`);
          }
            const data = await loginRes.json();
            if (data && data.access_token) {
              setAuth(data.access_token, data.refresh_token, data.expires_in);
              document.getElementById('emailLogin').style.display = 'none';
              initCharts();
              loadData();
              scheduleRefresh();
              initStream();
              return;
            }
        } catch (e2) {
          err.textContent = e2.message;
          err.style.display = 'block';
        }
      }
    } catch (e) {
      err.textContent = e.message;
      err.style.display = 'block';
    }
  });
  document.getElementById('logoutBtn').addEventListener('click', async () => {
    const rt = localStorage.getItem('refreshToken');
    if (rt) {
      try { await fetch(`${API_BASE}/users/logout`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ refresh_token: rt }) }); } catch {}
    }
    setAuth(null);
  });

  const sendBtn = document.getElementById('sendSampleBtn');
  if (sendBtn) sendBtn.addEventListener('click', sendSampleBatch);

  // Floating button + modal wiring
  const fab = document.getElementById('fabIngest');
  const modal = document.getElementById('ingestModal');
  const closeBtn = document.getElementById('closeIngest');
  const sendModalBtn = document.getElementById('sendSampleBtnModal');
  const modalToken = document.getElementById('ingestTokenModal');
  const modalMsg = document.getElementById('ingestMsgModal');
  if (fab && modal) {
    fab.addEventListener('click', () => {
      ingestModalOpen = true; paused = true; modal.style.display = 'flex';
      setTimeout(() => modalToken && modalToken.focus(), 50);
    });
  }
  if (closeBtn && modal) {
    closeBtn.addEventListener('click', () => { modal.style.display = 'none'; ingestModalOpen = false; paused = false; });
  }
  if (modal) {
    modal.addEventListener('click', (e) => { if (e.target === modal) { modal.style.display = 'none'; ingestModalOpen = false; paused = false; } });
  }
  if (sendModalBtn) {
    sendModalBtn.addEventListener('click', async () => {
      const tokenField = document.getElementById('ingestToken');
      if (modalToken && tokenField && modalToken.value) tokenField.value = modalToken.value;
      modalMsg && (modalMsg.textContent = 'Sending...');
      await sendSampleBatch();
      modalMsg && (modalMsg.textContent = 'Done.');
    });
  }

  const tokenInput = document.getElementById('ingestToken');
  if (tokenInput) {
    tokenInput.addEventListener('focusin', () => { paused = true; });
    tokenInput.addEventListener('focusout', () => { paused = false; });
  }
  const sampleCard = sendBtn ? sendBtn.closest('.card') : null;
  if (sampleCard) {
    sampleCard.addEventListener('mouseenter', () => { paused = true; });
    sampleCard.addEventListener('mouseleave', () => { paused = false; });
  }

  let lastScrollY = window.scrollY;
  let scrollTick = false;
  function onScroll() {
    if (scrollTick) return; scrollTick = true;
    requestAnimationFrame(() => {
      const currentY = window.scrollY;
      // If user intentionally scrolling down, suspend refresh
      if (currentY > lastScrollY && currentY > 300) {
        paused = true;
      } else if (currentY < 150 && !ingestModalOpen) {
        paused = false;
      }
      lastScrollY = currentY;
      scrollTick = false;
    });
  }
  window.addEventListener('scroll', onScroll, { passive: true });

  // Enrollment modal logic
  const enrollModal = document.getElementById('enrollModal');
  const addDeviceBtn = document.getElementById('addDeviceBtn');
  const closeEnroll = document.getElementById('closeEnroll');
  const enrollRequestBtn = document.getElementById('enrollRequestBtn');
  const enrollCloseBtn = document.getElementById('enrollCloseBtn');
  const enrollAnotherBtn = document.getElementById('enrollAnotherBtn');
  const copyEnrollCode = document.getElementById('copyEnrollCode');
  const enrollStageRequest = document.getElementById('enrollStageRequest');
  const enrollStageCode = document.getElementById('enrollStageCode');
  const enrollCodeBox = document.getElementById('enrollCodeBox');
  const enrollExpiry = document.getElementById('enrollExpiry');
  const enrollError = document.getElementById('enrollError');
  const enrollName = document.getElementById('enrollName');
  const enrollLocation = document.getElementById('enrollLocation');
  function openEnroll() {
    enrollError && (enrollError.style.display='none');
    enrollStageRequest.style.display='block';
    enrollStageCode.style.display='none';
    enrollModal.style.display='flex';
    paused = true;
    setTimeout(()=> enrollName && enrollName.focus(), 30);
  }
  function closeEnrollModal() {
    enrollModal.style.display='none';
    paused = false;
  }
  async function requestEnrollment() {
    const token = localStorage.getItem('authToken');
    if (!token) return setAuth(null);
    const name = (enrollName?.value || 'New Device').trim();
    const loc = (enrollLocation?.value || '').trim();
    enrollError.style.display='none';
    try {
      const res = await fetch(`${API_BASE}/dns/devices/request-enrollment`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, location: loc })
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      enrollStageRequest.style.display='none';
      enrollStageCode.style.display='block';
      enrollCodeBox.textContent = data.enrollment_code;
      try {
        const exp = new Date(data.expires_at);
        enrollExpiry.textContent = 'Expires: ' + exp.toLocaleTimeString();
      } catch { enrollExpiry.textContent=''; }
      loadData();
    } catch(e) {
      enrollError.textContent = e.message;
      enrollError.style.display='block';
    }
  }
  if (addDeviceBtn) addDeviceBtn.addEventListener('click', openEnroll);
  if (closeEnroll) closeEnroll.addEventListener('click', closeEnrollModal);
  if (enrollRequestBtn) enrollRequestBtn.addEventListener('click', requestEnrollment);
  if (enrollCloseBtn) enrollCloseBtn.addEventListener('click', closeEnrollModal);
  if (enrollAnotherBtn) enrollAnotherBtn.addEventListener('click', () => { enrollStageCode.style.display='none'; enrollStageRequest.style.display='block'; });
  if (enrollModal) enrollModal.addEventListener('click', e => { if (e.target === enrollModal) closeEnrollModal(); });
  if (copyEnrollCode) copyEnrollCode.addEventListener('click', () => {
    const code = (document.getElementById('enrollCodeBox')?.textContent || '').trim();
    if (!code) return;
    navigator.clipboard.writeText(code).then(()=> { copyEnrollCode.textContent='Copied'; setTimeout(()=> copyEnrollCode.textContent='Copy', 1500); });
  });

  // Verification banner logic
  const verifyNotice = document.getElementById('verifyNotice');
  const manualVerifyBtn = document.getElementById('manualVerifyBtn');
  const manualVerifyToken = document.getElementById('manualVerifyToken');
  const verifyMsg = document.getElementById('verifyMsg');
  const resendVerifyBtn = document.getElementById('resendVerifyBtn');

  async function checkVerification() {
    // Attempt to call a protected endpoint; if 403 with email not verified show banner
    try {
      await fetchWithAuth('/dns/analytics/network');
      verifyNotice.style.display='none';
    } catch(e) {
      // If unauthorized attempt refresh; else show
      if (String(e.message).includes('403')) {
        verifyNotice.style.display='block';
      }
    }
  }

  if (manualVerifyBtn) manualVerifyBtn.addEventListener('click', async () => {
    const token = (manualVerifyToken?.value || '').trim();
    if (!token) return;
    verifyMsg.textContent='Verifying...';
    try {
      const res = await fetch(`${API_BASE}/users/verify/${token}`);
      if (!res.ok) throw new Error(await res.text());
      verifyMsg.textContent='Verified. Reloading...';
      setTimeout(()=>{ location.reload(); }, 1200);
    } catch(err) { verifyMsg.textContent='Failed: '+(err.message||err); }
  });
  if (resendVerifyBtn) resendVerifyBtn.addEventListener('click', async () => {
    const email = document.getElementById('email').value.trim();
    verifyMsg.textContent='Resending...';
    try {
      const res = await fetch(`${API_BASE}/users/resend-verification`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email }) });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      verifyMsg.textContent = `Sent. (Dev token: ${data.verification_token_dev || 'email'})`;
    } catch(err) { verifyMsg.textContent='Failed: '+(err.message||err); }
  });

  // Periodic check if verification pending
  setInterval(() => {
    if (localStorage.getItem('authToken')) checkVerification();
  }, 45000);
  checkVerification();
});

function initStream() {
  const token = localStorage.getItem('authToken');
  if (!token) return;
  try { if (ws) { ws.close(); ws=null; } } catch {}
  const url = (API_BASE.replace('http','ws') + '/dns/stream?token=' + encodeURIComponent(token)).replace(/\/api$/,'/api');
  ws = new WebSocket(url);
  ws.onopen = () => { console.log('WS connected'); };
  ws.onclose = () => { console.log('WS closed'); setTimeout(()=> initStream(), 5000); };
  ws.onerror = () => { try { ws.close(); } catch {}; };
  ws.onmessage = (ev) => {
    try {
      const data = JSON.parse(ev.data);
  if (data.type === 'dns') handleDnsEvent(data);
  if (data.type === 'analytics_delta') applyAnalyticsDelta(data);
    } catch(e){ console.error('WS parse', e); }
  };
}

function handleDnsEvent(evt) {
  // Maintain alert buffer (heuristic: show blocked or high score)
  if (evt.score >= 0.7 || evt.status === 'blocked') {
  const label = evt.endpoint_name ? `(${evt.endpoint_name})` : '';
  recentAlertsBuffer.unshift({ threat_type:'heuristic', description: `${evt.domain} ${label}`.trim(), threat_level: 'high' });
    if (recentAlertsBuffer.length > MAX_ALERTS) recentAlertsBuffer.pop();
    renderRecentAlerts();
  }
  // Update threat chart timeline last bucket increment
  if (threatChart && threatChart.data.labels.length) {
    const lastIdx = threatChart.data.labels.length - 1;
    // Increment last data point threats count if high
    if (evt.score >= 0.7) {
      threatChart.data.datasets[0].data[lastIdx] = (threatChart.data.datasets[0].data[lastIdx] || 0) + 1;
      threatChart.update('none');
    }
  }
}

function applyAnalyticsDelta(delta){
  try {
    const analytics = {
      total_queries_24h: delta.total_queries_24h,
      blocked_queries_24h: delta.blocked_queries_24h,
      active_devices: document.getElementById('activeDevices')?.textContent ? parseInt(document.getElementById('activeDevices').textContent,10) : 0,
      top_blocked_domains: window.__lastTopBlockedDomains || [],
      threat_timeline: window.__lastThreatTimeline || []
    };
    updateStats(analytics);
  } catch(e){ console.warn('analytics_delta update failed', e); }
}

function renderRecentAlerts() {
  const c = document.getElementById('alertsList');
  if (!c) return;
  c.innerHTML='';
  recentAlertsBuffer.slice(0,5).forEach(t => {
    const el = document.createElement('div');
    el.className='device';
    el.innerHTML = `<div><div><strong>${t.threat_type.toUpperCase()}</strong></div><div class="hint">${t.description}</div></div><div class="badge off">HIGH</div>`;
    c.appendChild(el);
  });
}

// Enhanced sample data function with fallback
async function sendSampleBatch() {
  console.log("Send Sample Data button clicked");
  const token = localStorage.getItem('authToken');
  if (!token) return setAuth(null);
  const devToken = (document.getElementById('ingestToken')?.value || '').trim();
  const msg = document.getElementById('ingestMsg');
  if (msg) msg.textContent = 'Sending sample data...';
  
  try {
    // Try using the simple test-ingest endpoint first (more reliable)
    console.log("Trying test-ingest endpoint");
    const testRes = await fetch(`${API_BASE}/dns/test-ingest?count=15`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (testRes.ok) {
      const result = await testRes.json();
      console.log("Test ingest successful:", result);
      if (msg) msg.textContent = `Sample data sent. Generated ${result.processed || 15} queries, blocked ${result.blocked || 0}. Updating...`;
      await loadData();
      if (msg) msg.textContent = 'Dashboard updated with sample data.';
      return;
    }
    
    // Fall back to the original batch method if test-ingest fails
    console.log("Test-ingest failed, trying batch method");
    const ts = Math.floor(Date.now()/1000);
    const body = [
      { device_id:'dev_web_demo', query_name:'malware.example.tk', query_type:'A', client_ip:'192.168.1.10', response_code:'NOERROR', response_ip:'1.2.3.4', timestamp:ts },
      { device_id:'dev_web_demo', query_name:'github.com', query_type:'A', client_ip:'192.168.1.10', response_code:'NOERROR', response_ip:'140.82.113.4', timestamp:ts },
      { device_id:'dev_web_demo', query_name:'phishing.bad.net', query_type:'A', client_ip:'192.168.1.10', response_code:'NOERROR', response_ip:'5.6.7.8', timestamp:ts }
    ];
    const res = await fetch(`${API_BASE}/dns/dns-queries/batch`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(devToken ? {'X-Device-Token': devToken} : {}),
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(body)
    });
    
    if (!res.ok) throw new Error(await res.text());
    if (msg) msg.textContent = 'Sample sent via batch method. Updating...';
    await loadData();
    if (msg) msg.textContent = 'Updated with batch data.';
  } catch (e) {
    console.error("Sample data error:", e);
    if (msg) msg.textContent = `Error: ${e.message || e}`;
  }
}
