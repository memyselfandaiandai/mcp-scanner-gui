/* MCP Security Scanner GUI — Frontend Logic */

const API_BASE = 'http://127.0.0.1:3030';

// State
let currentScanId = null;
let allFindings = [];
let currentFilter = 'all';

// DOM Elements
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const uploadSection = document.getElementById('upload-section');
const loadingSection = document.getElementById('loading-section');
const resultsSection = document.getElementById('results-section');
const errorSection = document.getElementById('error-section');
const findingsBody = document.getElementById('findings-body');
const noFindings = document.getElementById('no-findings');
const detailPanel = document.getElementById('detail-panel');

// Event Listeners
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', handleDrop);
fileInput.addEventListener('change', (e) => {
  if (e.target.files[0]) uploadFile(e.target.files[0]);
});

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.severity;
    renderFindings();
  });
});

document.querySelectorAll('.btn-export').forEach(btn => {
  btn.addEventListener('click', () => exportResults(btn.dataset.fmt));
});

document.getElementById('detail-close').addEventListener('click', () => {
  detailPanel.classList.add('hidden');
});

document.getElementById('new-scan-btn').addEventListener('click', resetToUpload);
document.getElementById('error-retry-btn').addEventListener('click', resetToUpload);

// File Handling
function handleDrop(e) {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  if (e.dataTransfer.files[0]) uploadFile(e.dataTransfer.files[0]);
}

async function uploadFile(file) {
  showSection('loading');

  const formData = new FormData();
  formData.append('config', file);

  try {
    const resp = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      body: formData,
    });

    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.detail || 'Scan failed');
    }

    const data = await resp.json();
    currentScanId = data.scan_id;
    allFindings = data.findings || [];
    renderResults(data);
    showSection('results');
  } catch (err) {
    showError(err.message);
  }
}

// Rendering
function renderResults(data) {
  const s = data.summary;
  document.getElementById('summary-servers').textContent = s.servers_scanned;
  document.getElementById('summary-total').textContent = s.total_findings;
  document.getElementById('summary-critical').textContent = s.severity_counts.CRITICAL || 0;
  document.getElementById('summary-high').textContent = s.severity_counts.HIGH || 0;
  document.getElementById('summary-medium').textContent = s.severity_counts.MEDIUM || 0;
  document.getElementById('summary-low').textContent =
    (s.severity_counts.LOW || 0) + (s.severity_counts.INFO || 0);

  renderFindings();
}

function renderFindings() {
  const filtered = currentFilter === 'all'
    ? allFindings
    : allFindings.filter(f => f.severity === currentFilter);

  if (filtered.length === 0) {
    findingsBody.innerHTML = '';
    noFindings.classList.remove('hidden');
    document.getElementById('findings-table').classList.add('hidden');
    return;
  }

  noFindings.classList.add('hidden');
  document.getElementById('findings-table').classList.remove('hidden');

  findingsBody.innerHTML = filtered.map(f => `
    <tr onclick="showDetail('${f.check_id}')">
      <td><span class="severity-badge ${f.severity}">${f.severity}</span></td>
      <td><code>${f.check_id}</code></td>
      <td>${escHtml(f.title)}</td>
      <td><code>${escHtml(f.server || '-')}</code></td>
      <td><code>${escHtml(f.tool || '-')}</code></td>
      <td><code>${escHtml(f.owasp_code || '-')}</code></td>
    </tr>
  `).join('');
}

function showDetail(checkId) {
  const f = allFindings.find(x => x.check_id === checkId);
  if (!f) return;

  document.getElementById('detail-title').textContent = f.title;
  document.getElementById('detail-severity').innerHTML =
    `<span class="severity-badge ${f.severity}">${f.severity}</span>`;
  document.getElementById('detail-check-id').textContent = f.check_id;
  document.getElementById('detail-description').textContent = f.description;

  toggleDetailRow('detail-server-row', 'detail-server', f.server);
  toggleDetailRow('detail-tool-row', 'detail-tool', f.tool);
  toggleDetailRow('detail-owasp-row', 'detail-owasp', f.owasp_code);
  toggleDetailRow('detail-evidence-row', 'detail-evidence', f.evidence);
  toggleDetailRow('detail-remediation-row', 'detail-remediation', f.remediation);

  detailPanel.classList.remove('hidden');
}

function toggleDetailRow(rowId, valueId, value) {
  const row = document.getElementById(rowId);
  if (value) {
    row.classList.remove('hidden');
    document.getElementById(valueId).textContent = value;
  } else {
    row.classList.add('hidden');
  }
}

async function exportResults(fmt) {
  if (!currentScanId) return;
  window.open(`${API_BASE}/api/export/${currentScanId}/${fmt}`, '_blank');
}

// Utilities
function showSection(name) {
  [uploadSection, loadingSection, resultsSection, errorSection].forEach(s => s.classList.add('hidden'));
  document.getElementById(`${name}-section`).classList.remove('hidden');
}

function showError(msg) {
  document.getElementById('error-message').textContent = msg;
  showSection('error');
}

function resetToUpload() {
  currentScanId = null;
  allFindings = [];
  currentFilter = 'all';
  fileInput.value = '';
  detailPanel.classList.add('hidden');
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  document.querySelector('[data-severity="all"]').classList.add('active');
  showSection('upload');
}

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
