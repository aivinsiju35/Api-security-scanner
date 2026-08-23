/* ============================================================
   API Security Scanner — Frontend Application
   ============================================================ */

const API_BASE = 'http://localhost:8000';

// ── Test definitions ──────────────────────────────────────────
const TESTS = [
  { id: 'API1',  name: 'BOLA',               full: 'Broken Object Level Authorization' },
  { id: 'API2',  name: 'Broken Auth',         full: 'Broken Authentication' },
  { id: 'API3',  name: 'Mass Assignment',     full: 'Broken Object Property Level Auth' },
  { id: 'API4',  name: 'Rate Limiting',       full: 'Unrestricted Resource Consumption' },
  { id: 'API5',  name: 'Func Auth',           full: 'Broken Function Level Authorization' },
  { id: 'API6',  name: 'Business Flow',       full: 'Unrestricted Sensitive Business Flows' },
  { id: 'API7',  name: 'SSRF',               full: 'Server Side Request Forgery' },
  { id: 'API8',  name: 'Misconfiguration',   full: 'Security Misconfiguration' },
  { id: 'API9',  name: 'Inventory',           full: 'Improper Inventory Management' },
  { id: 'API10', name: 'Unsafe API',          full: 'Unsafe Consumption of APIs' },
];

// ── State ─────────────────────────────────────────────────────
let selectedTests = new Set(TESTS.map(t => t.id));
let currentResults = [];
let currentFilter = 'all';
let severityChart = null;
let currentScanId = null;

// ── Init ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  renderTestChips();
  initChart();
});

// ── Test chip selection ───────────────────────────────────────
function renderTestChips() {
  const grid = document.getElementById('tests-grid');
  grid.innerHTML = TESTS.map(t => `
    <div
      class="test-chip selected"
      id="chip-${t.id}"
      onclick="toggleTest('${t.id}', this)"
      title="${t.full}"
    >
      <span class="test-chip-id">${t.id}</span>
      <span>${t.name}</span>
    </div>
  `).join('');
}

function toggleTest(id, el) {
  if (selectedTests.has(id)) {
    selectedTests.delete(id);
    el.classList.remove('selected');
  } else {
    selectedTests.add(id);
    el.classList.add('selected');
  }
}

function selectAllTests() {
  TESTS.forEach(t => {
    selectedTests.add(t.id);
    document.getElementById(`chip-${t.id}`)?.classList.add('selected');
  });
}

function deselectAllTests() {
  selectedTests.clear();
  TESTS.forEach(t => {
    document.getElementById(`chip-${t.id}`)?.classList.remove('selected');
  });
}

// ── Chart init ────────────────────────────────────────────────
function initChart() {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;
  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low', 'Passed'],
      datasets: [{
        data: [0, 0, 0, 0, 0],
        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#1e293b'],
        borderColor: ['#ef444440', '#f9731640', '#eab30840', '#22c55e40', '#1e293b40'],
        borderWidth: 1,
        hoverOffset: 6,
      }],
    },
    options: {
      responsive: true,
      cutout: '72%',
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.raw}`,
          },
          backgroundColor: '#0d1120',
          borderColor: 'rgba(255,255,255,0.08)',
          borderWidth: 1,
          titleColor: '#f1f5f9',
          bodyColor: '#94a3b8',
        },
      },
    },
  });
}

function updateChart(results) {
  if (!severityChart) return;
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Passed: 0 };
  results.forEach(r => {
    if (!r.found) { counts.Passed++; return; }
    const sev = r.cvss_severity || 'Unknown';
    if (sev in counts) counts[sev]++;
    else counts.High++;
  });
  severityChart.data.datasets[0].data = [
    counts.Critical, counts.High, counts.Medium, counts.Low, counts.Passed,
  ];
  severityChart.update();

  // Legend
  const legend = document.getElementById('chart-legend');
  legend.innerHTML = Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => `
      <div style="display:flex;align-items:center;gap:5px">
        <div style="width:8px;height:8px;border-radius:50%;background:${severityColor(k)}"></div>
        <span>${k}: ${v}</span>
      </div>
    `).join('') || '<span style="color:var(--text-muted)">No data yet</span>';
}

function severityColor(sev) {
  const map = { Critical:'#ef4444', High:'#f97316', Medium:'#eab308', Low:'#22c55e', Passed:'#1e293b', Unknown:'#94a3b8' };
  return map[sev] || '#94a3b8';
}

// ── Scan ──────────────────────────────────────────────────────
async function startScan() {
  const targetUrl = document.getElementById('target-url').value.trim();
  const authToken = document.getElementById('auth-token').value.trim();

  if (!targetUrl) {
    showToast('⚠️ Please enter a target API URL', 'warning');
    document.getElementById('target-url').focus();
    return;
  }
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    showToast('⚠️ URL must start with http:// or https://', 'warning');
    return;
  }
  if (selectedTests.size === 0) {
    showToast('⚠️ Select at least one test to run', 'warning');
    return;
  }

  // UI state
  setScanningState(true);
  clearTerminal();
  clearFindings();
  resetStats();

  try {
    const body = {
      target_url: targetUrl,
      selected_tests: [...selectedTests],
    };
    if (authToken) body.auth_token = authToken;

    const resp = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(err.detail || `HTTP ${resp.status}`);
    }

    const { scan_id } = await resp.json();
    currentScanId = scan_id;

    // Stream logs
    await streamScan(scan_id);

  } catch (err) {
    appendLog(`❌ Error: ${err.message}`, 'danger', '');
    setScanningState(false);
    showToast(`❌ ${err.message}`, 'error');
  }
}

async function streamScan(scanId) {
  const evtSource = new EventSource(`${API_BASE}/api/scan/${scanId}/stream`);

  evtSource.onmessage = (e) => {
    const msg = JSON.parse(e.data);

    if (msg.type === 'ping') return;

    if (msg.type === 'log') {
      appendLog(msg.message, msg.level, msg.timestamp);
    }

    if (msg.type === 'complete') {
      evtSource.close();
      fetchResults(scanId);
    }
  };

  evtSource.onerror = () => {
    evtSource.close();
    appendLog('Connection to scanner lost. Fetching results...', 'warning', '');
    setTimeout(() => fetchResults(scanId), 1000);
  };
}

async function fetchResults(scanId) {
  try {
    const resp = await fetch(`${API_BASE}/api/scan/${scanId}/results`);
    const data = await resp.json();
    currentResults = data.results || [];
    renderResults(currentResults, data.summary);
    setScanningState(false);
    document.getElementById('export-btn').style.display = 'flex';
    showToast(`✅ Scan complete — ${data.summary.vulnerable} vulnerabilities found`, 'success');
  } catch (err) {
    appendLog(`Error fetching results: ${err.message}`, 'danger', '');
    setScanningState(false);
  }
}

// ── Terminal ──────────────────────────────────────────────────
function clearTerminal() {
  document.getElementById('terminal-body').innerHTML = '';
}

function appendLog(message, level = 'info', ts = '') {
  const body = document.getElementById('terminal-body');
  const line = document.createElement('div');
  line.className = `log-line log-${level}`;
  line.innerHTML = ts
    ? `<span class="log-ts">[${ts}]</span><span>${escHtml(message)}</span>`
    : `<span>${escHtml(message)}</span>`;
  body.appendChild(line);
  body.scrollTop = body.scrollHeight;
}

// ── Results rendering ─────────────────────────────────────────
function renderResults(results, summary) {
  currentResults = results;
  updateStats(summary);
  updateChart(results);
  renderFindings(results);
}

function updateStats(summary) {
  if (!summary) return;
  document.getElementById('stat-total').textContent     = summary.total;
  document.getElementById('stat-vulnerable').textContent= summary.vulnerable;
  document.getElementById('stat-critical').textContent  = summary.critical;
  document.getElementById('stat-high').textContent      = summary.high;
  document.getElementById('stat-medium').textContent    = summary.medium;
  document.getElementById('stat-passed').textContent    = summary.total - summary.vulnerable;
}

function resetStats() {
  ['stat-total','stat-vulnerable','stat-critical','stat-high','stat-medium','stat-passed']
    .forEach(id => { document.getElementById(id).textContent = '—'; });
}

function clearFindings() {
  document.getElementById('findings-list').innerHTML = `
    <div class="empty-state">
      <div class="empty-state-icon">⏳</div>
      <div class="empty-state-text">Scanning in progress...</div>
    </div>`;
  document.getElementById('export-btn').style.display = 'none';
}

// ── Filter ────────────────────────────────────────────────────
function filterFindings(filter, btn) {
  currentFilter = filter;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderFindings(currentResults);
}

function renderFindings(results) {
  const list = document.getElementById('findings-list');
  if (!results || results.length === 0) {
    list.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🔬</div><div class="empty-state-text">No findings yet</div></div>';
    return;
  }

  let filtered = results;
  if (currentFilter === 'vulnerable') filtered = results.filter(r => r.found);
  if (currentFilter === 'passed')     filtered = results.filter(r => !r.found);

  if (filtered.length === 0) {
    list.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🎯</div><div class="empty-state-text">No ${currentFilter} findings</div></div>`;
    return;
  }

  list.innerHTML = filtered.map((r, i) => buildFindingCard(r, i)).join('');
}

function buildFindingCard(r, idx) {
  const found      = r.found;
  const severity   = r.cvss_severity || 'Unknown';
  const score      = typeof r.cvss_score === 'number' ? r.cvss_score.toFixed(1) : '—';
  const scoreColor = r.cvss_color || '#94a3b8';
  const remediation= r.remediation || {};
  const cves       = r.cve_references || [];
  const evidence   = r.evidence || {};

  const evidenceJson = JSON.stringify(evidence, null, 2);
  const cveHtml = cves.length
    ? cves.map(c => `
        <div class="cve-card">
          <div class="cve-header">
            <span class="cve-id">${escHtml(c.id)}</span>
            <span class="severity-badge severity-${escHtml(c.severity || 'Unknown')}">${escHtml(c.severity || 'Unknown')}</span>
          </div>
          <div class="cve-desc">${escHtml(c.description || '')}</div>
          <a href="${escHtml(c.url || '#')}" target="_blank" rel="noopener" class="cve-link">
            🔗 View on NVD ↗
          </a>
        </div>
      `).join('')
    : '<div class="text-muted">No CVE references available</div>';

  const remStepsHtml = (remediation.steps || [])
    .map(s => `<li>${escHtml(s)}</li>`)
    .join('');

  const codeExample = remediation.code_example || {};
  const codeHtml = codeExample.vulnerable ? `
    <div style="margin-top:16px">
      <div class="section-title" style="margin-bottom:12px">Code Fix Example</div>
      <div class="code-compare">
        <div>
          <div class="code-block-label bad">❌ Vulnerable</div>
          <div class="code-block">${escHtml(codeExample.vulnerable || '')}</div>
        </div>
        <div>
          <div class="code-block-label good">✅ Secure</div>
          <div class="code-block">${escHtml(codeExample.secure || '')}</div>
        </div>
      </div>
    </div>` : '';

  const refsHtml = (remediation.references || [])
    .map(ref => `<a href="${escHtml(ref)}" target="_blank" rel="noopener" class="cve-link" style="display:block;margin-bottom:4px">🔗 ${escHtml(ref)}</a>`)
    .join('');

  return `
    <div class="finding-card ${found ? 'found severity-' + severity : ''}" id="finding-${idx}">
      <div class="finding-header" onclick="toggleFinding(${idx})">
        <span class="finding-vuln-id">${escHtml(r.vuln_id)}</span>
        <div class="status-dot ${found ? 'vulnerable' : 'safe'}"></div>
        <span class="finding-name">${escHtml(r.name)}</span>
        <span class="severity-badge severity-${severity}">${severity}</span>
        <span class="cvss-score-display" style="color:${scoreColor}">${score}</span>
        <svg class="finding-chevron" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </div>
      <div class="finding-body">

        <!-- CVSS vector -->
        ${r.cvss_vector ? `
        <div class="cvss-vector-display" style="margin-top:16px">
          <span style="font-size:12px;color:var(--text-muted);flex-shrink:0">CVSS v3.1:</span>
          <span class="cvss-vector-chip">${escHtml(r.cvss_vector)}</span>
        </div>` : ''}

        <!-- Status banner -->
        <div style="padding:10px 14px;border-radius:var(--radius-md);margin-bottom:4px;font-size:13px;
          background:${found ? 'rgba(239,68,68,0.08)' : 'rgba(34,197,94,0.08)'};
          border:1px solid ${found ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)'};
          color:${found ? 'var(--critical)' : 'var(--low)'}">
          ${found ? '🔴 Vulnerability Detected — Immediate attention required' : '✅ No vulnerability detected for this category'}
        </div>

        <!-- Tabs -->
        <div class="finding-tabs">
          <button class="finding-tab active" onclick="switchTab(${idx},'evidence',this)">Evidence</button>
          <button class="finding-tab" onclick="switchTab(${idx},'remediation',this)">Remediation</button>
          <button class="finding-tab" onclick="switchTab(${idx},'cve',this)">CVE References (${cves.length})</button>
        </div>

        <!-- Evidence tab -->
        <div class="tab-content active" id="tab-${idx}-evidence">
          ${evidence.test_description ? `
            <div class="remediation-summary" style="margin-bottom:12px">
              📋 ${escHtml(evidence.test_description)}
            </div>` : ''}
          <div class="evidence-block">${formatEvidence(evidence)}</div>
        </div>

        <!-- Remediation tab -->
        <div class="tab-content" id="tab-${idx}-remediation">
          ${remediation.summary ? `<div class="remediation-summary">💡 ${escHtml(remediation.summary)}</div>` : ''}
          ${remediation.impact ? `
            <div style="padding:10px 14px;border-radius:var(--radius-md);margin-bottom:14px;font-size:13px;
              background:rgba(249,115,22,0.08);border:1px solid rgba(249,115,22,0.2);color:var(--high)">
              ⚠️ <strong>Impact:</strong> ${escHtml(remediation.impact)}
            </div>` : ''}
          ${remStepsHtml ? `
            <div class="section-title" style="margin:12px 0 8px">Remediation Steps</div>
            <ul class="remediation-steps">${remStepsHtml}</ul>` : ''}
          ${codeHtml}
          ${refsHtml ? `
            <div class="section-title" style="margin:16px 0 8px">References</div>
            ${refsHtml}` : ''}
        </div>

        <!-- CVE tab -->
        <div class="tab-content" id="tab-${idx}-cve">
          <div class="cve-list">${cveHtml}</div>
        </div>

      </div>
    </div>`;
}

function toggleFinding(idx) {
  const card = document.getElementById(`finding-${idx}`);
  card.classList.toggle('expanded');
}

function switchTab(idx, tabName, btn) {
  const card = document.getElementById(`finding-${idx}`);
  card.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
  card.querySelectorAll('.finding-tab').forEach(tb => tb.classList.remove('active'));
  document.getElementById(`tab-${idx}-${tabName}`).classList.add('active');
  btn.classList.add('active');
}

// ── Helpers ───────────────────────────────────────────────────
function formatEvidence(evidence) {
  if (typeof evidence !== 'object' || !evidence) return 'No evidence collected.';
  const lines = [];
  for (const [key, val] of Object.entries(evidence)) {
    if (key === 'test_description') continue;
    if (Array.isArray(val) && val.length === 0) continue;
    const displayVal = typeof val === 'object' ? JSON.stringify(val, null, 2) : String(val);
    lines.push(`${key}: ${displayVal}`);
  }
  return escHtml(lines.join('\n\n')) || 'No evidence data.';
}

function escHtml(str) {
  if (typeof str !== 'string') str = String(str || '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ── UI state ──────────────────────────────────────────────────
function setScanningState(scanning) {
  const btn = document.getElementById('scan-btn');
  const txt = document.getElementById('scan-btn-text');
  const ind = document.getElementById('scan-status-indicator');

  btn.disabled = scanning;
  txt.textContent = scanning ? '⏳ Scanning...' : '⚡ Start Security Scan';
  if (ind) {
    ind.style.display = scanning ? 'flex' : 'none';
  }
}

// ── Export ────────────────────────────────────────────────────
function exportJSON() {
  if (!currentResults.length) return;
  const data = {
    scan_id: currentScanId,
    exported_at: new Date().toISOString(),
    target: document.getElementById('target-url').value,
    results: currentResults,
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `api-scan-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('📥 Report exported as JSON', 'success');
}

// ── Toast ─────────────────────────────────────────────────────
function showToast(msg, type = 'info') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = msg;
  const colors = { success: 'var(--low)', error: 'var(--critical)', warning: 'var(--medium)', info: 'var(--accent-light)' };
  toast.style.borderColor = colors[type] || 'var(--border)';
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}
