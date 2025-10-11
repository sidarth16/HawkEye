// static/app.js — full file: inline codeify + enhanced progress + issue UI
const $ = (id) => document.getElementById(id);

/* ------------------------- safety & tiny helpers ------------------------- */
function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/* Convert text with `backticks` into escaped HTML where backtick parts become <code class="inline-code">..</code> */
function inlineCodeify(text) {
  if (text === null || text === undefined) return '';
  const s = String(text);
  // Split by segments like `code` and non-code, preserve order
  const parts = s.split(/(`[^`]+`)/g);
  return parts.map(part => {
    if (part.startsWith('`') && part.endsWith('`')) {
      const inner = part.slice(1, -1);
      return `<code class="inline-code">${escapeHtml(inner)}</code>`;
    }
    return escapeHtml(part);
  }).join('');
}

/* ------------------------- severity helpers ------------------------- */
function severityClass(sev) {
  if (!sev) return 'chip-low';
  const s = sev.toString().toUpperCase();
  if (s === 'HIGH' || s === 'CRITICAL') return 'chip-high';
  if (s === 'MEDIUM' || s === 'MODERATE') return 'chip-med';
  return 'chip-low';
}

function severityIcon(sev) {
  const s = (sev || 'LOW').toString().toUpperCase();
  if (s === 'HIGH') {
    return `<svg class="sev-icon" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M12 2 L2 20h20L12 2z" fill="#FF6E6E"/>
      <path d="M12 8v5" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="12" cy="16" r="1" fill="#fff"/>
    </svg>`;
  } else if (s === 'MEDIUM') {
    return `<svg class="sev-icon" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M12 2 L2 20h20L12 2z" fill="#FFD75B"/>
      <path d="M12 8v5" stroke="#000" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="12" cy="16" r="1" fill="#000"/>
    </svg>`;
  } else {
    return `<svg class="sev-icon" viewBox="0 0 24 24" fill="none" aria-hidden>
      <rect rx="5" ry="5" width="20" height="20" x="2" y="2" fill="#4EFF8C"/>
      <path d="M7 12l3 3 7-7" stroke="#042" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    </svg>`;
  }
}

/* ------------------------- function & variable formatting ------------------------- */
/* Format to Contract.func() or func() */
function formatFunctionLabel(funcName) {
  if (!funcName) return 'unknown()';
  try {
    const parts = funcName.split('.');
    if (parts.length > 1) {
      const contract = parts[0];
      const func = parts[1].split('(')[0];
      return `${contract}.${func}()`;
    }
    return funcName.split('(')[0] + '()';
  } catch {
    return 'unknown()';
  }
}

/* show variable inline (no trimming) — styled like function label */
function renderVariableInlineAsFuncStyle(variableStr) {
  if (variableStr === undefined || variableStr === null) return '';
  const s = String(variableStr).trim();
  if (!s) return '';
  return `<span class="func-label func-full-tooltip text-xs text-slate-400 ml-2" title="${escapeHtml(s)}">${escapeHtml(s)}</span>`;
}

/* ------------------------- suggested fixes (small map) ------------------------- */
function suggestedFixForCode(code) {
  const map = {
    'MCO-001' : "Override Core Vault contract functions which are exposed",
    'MCO-001' : "Override Core Token contract functions which are exposed",
    'MCO-001' : "Override Core Upgradeable/Proxy contract functions which are exposed",
    'MCO-001' : "Override Core Ownable contract functions which are exposed",

    'AC-101': "Avoid using `tx.origin` or trivial blaclisting like checks (`!=`) and use strong user validations. ",
    'AC-001': "Add strong user-validation checks and proper access control bounds. Try Adding `onlyOwner` or proper role based checks to this function.",
    'AC-002': "Add strong user-validation checks and proper access control bounds. Try Adding `onlyOwner` or proper role based checks to this function.",
    'AC-003': "Add strong user-validation checks and proper access control bounds. Try Adding `onlyOwner` or proper role based checks to this function.",

    'IVC-001': "Add proper input valdation checks to the exposed user-controlled call target address, before making delegateCall to it.",
    'IVC-002': "Add proper input valdation checks to the exposed user-controlled call target address, before using callcode on it.",
    'IVC-003': "Add proper input valdation checks to the exposed user-controlled call target address, before making low_level_call to it.",
    'IVC-004': "Add proper input valdation checks to the exposed user-controlled call target address, before making externalCall to it.",
    'IVC-005': "Add proper input valdation checks to the exposed user-controlled call target address, before making staticCall to it.",

    'ACM-101': "Avoid using `tx.origin` or trivial blaclisting like checks (`!=`) and use strong user validations. ",
    'ACM-001': "Add strong user-validation checks and proper access control bounds. Try Adding `onlyOwner` or proper role based checks to this function.",
    'ACM-002': "Add strong user-validation checks and proper access control bounds. Try Adding `onlyOwner` or proper role based checks to this function.",

    'AC01': 'Add `onlyOwner` or proper role checks to this function.',
    'IV12': 'Validate amount > 0 and check upper bounds, use SafeMath checks.',
    'OVR7': 'Add `override` keyword to child function and ensure visibility modifiers match.'
  };
  return map[code] || 'Review control flow, add explicit checks, and add unit tests / fuzzing for this path.';
}

/* ------------------------- render a single issue card ------------------------- */
function renderIssue(i, idx) {
  const id = i.ID || i.id || '—';
  const title = i.Title || i.title || 'Untitled';
  const type = i.Type || i.type || '—';
  const category = i.Category || i.category || '—';
  const func = i.Function || i.function || i.fn || '';
  const funcLabel = formatFunctionLabel(func) || 'unknown()';
  const desc = i.Description || i.description || '—';
  const sev = i.Severity || i.severity || 'LOW';
  const chip = severityClass(sev);
  const icon = severityIcon(sev);

  // variable inline displayed exactly (no chips)
  const variableInlineHtml = renderVariableInlineAsFuncStyle(i.Variable || i.variable || '');

  return `
    <div class="issue-card p-3 rounded-xl2 border issue-row min-w-0" 
         data-issue-idx="${idx}" data-issue-fn="${escapeHtml(func)}">
      <div class="flex items-center justify-between mb-2">
        <div class="flex items-center gap-2">
          ${type ? `<span class="badge-mini badge-type">${escapeHtml(type)}</span>` : `<span class="badge-mini">${escapeHtml(type)}</span>`}
          ${category ? `<span class="badge-mini badge-cat">${escapeHtml(category)}</span>` : `<span class="badge-mini">${escapeHtml(category)}</span>`}
        </div>
        <div class="text-xs text-slate-400">${escapeHtml(id)}</div>
      </div>

      <div class="flex items-start gap-3">
        <div class="flex-0">
          <div class="w-12 h-12 rounded-xl flex items-center justify-center bg-[rgba(255,255,255,0.02)]">
            ${icon}
          </div>
        </div>

        <div class="flex-1 min-w-0">
          <div class="flex items-center justify-between">
            <div class="min-w-0">
              <!-- title uses inlineCodeify so backtick parts become code-like -->
              <div class="font-semibold text-lg truncate">${inlineCodeify(title)}</div>
              <div class="text-xs text-slate-400 mt-1 truncate">
                <span class="func-label func-full-tooltip" title="${escapeHtml(func)}">${escapeHtml(funcLabel)}</span>
                ${variableInlineHtml}
              </div>
            </div>

            <div class="space-y-1 text-right">
              <div class="chip ${chip}">${escapeHtml(sev)}</div>
            </div>
          </div>

          <details class="mt-2 text-sm text-slate-300">
  <summary class="cursor-pointer text-slate-200 font-semibold">Details</summary>
  <div class="details-body-box mt-2">
    <div class="whitespace-pre-wrap">${escapeHtml(desc)}</div>
  </div>
</details>
        </div>
      </div>
    </div>
  `;
}

/* ------------------------- selected inspector (by index) ------------------------- */
function renderSelectedIssueInlineByIndex(idx) {
  const target = $('selectedIssueInline');
  if (idx === undefined || idx === null) { hideInspector(); return; }
  const issues = window.__lastIssues || [];
  const i = issues[idx];
  if (!i) { 
    target.innerHTML = `<div class="text-sm text-slate-300">Issue data not found (index ${idx}).</div>`; 
    target.classList.remove('hidden');
    return;
  }
  try {
    const funcSig = i.Function || i.function || i.fn || '';
    const variableHtml = renderVariableInlineAsFuncStyle(i.Variable || i.variable || '');
    const suggestedFix = suggestedFixForCode(i.ID || i.id);
    const titleHtml = inlineCodeify(i.Title || i.title || 'Untitled');

    const html = `
      <div>
        <div class="flex items-center justify-between">
          <div>
            <div class="font-semibold">${titleHtml}</div>
            <div class="text-xs text-slate-400">${escapeHtml(i.Type || i.type || '—')} | ${escapeHtml(i.Category || i.category || '—')} </div>
          </div>
          <div class="text-sm">
            <div class="chip ${severityClass(i.Severity || i.severity || 'LOW')}">${escapeHtml(i.Severity || i.severity || 'LOW')}</div>
          </div>
        </div>

        <div class="mt-3 text-sm text-slate-200">
          <div class="mb-2"><strong>Function:</strong> <code>${escapeHtml(funcSig)}</code> ${variableHtml ? variableHtml : ''}</div>
          <div class="whitespace-pre-wrap mb-3">${escapeHtml(i.Description || i.description || '—')}</div>

          <div class="mb-2">
            <strong>Suggested fix</strong>
            <div class="mt-1 text-xs text-slate-300 bg-[rgba(255,255,255,0.02)] p-2 rounded">${escapeHtml(suggestedFix)}</div>
          </div>

          <div class="flex gap-2 mt-3">
            <button id="copySigInline" class="btn-ghost px-2 py-1 rounded-xl text-xs">Copy signature</button>
            <button id="viewRawInline" class="border px-2 py-1 rounded-xl text-xs">View raw</button>
            <button id="closeInspector" class="border px-2 py-1 rounded-xl text-xs">Close</button>
          </div>
        </div>
      </div>
    `;
    target.innerHTML = html;
    target.classList.remove('hidden');

    const copy = document.getElementById('copySigInline');
    if (copy) copy.onclick = () => navigator.clipboard.writeText(funcSig || '').then(()=> copy.textContent='Copied').catch(()=> copy.textContent='Fail');
    const view = document.getElementById('viewRawInline');
    if (view) view.onclick = () => alert(JSON.stringify(i, null, 2));
    const closeBtn = document.getElementById('closeInspector');
    if (closeBtn) closeBtn.onclick = () => hideInspector();
  } catch (err) {
    console.error('renderSelectedIssueInlineByIndex error:', err, 'issue:', i);
    target.innerHTML = `<div class="text-sm text-yellow-200">Failed to render issue details. See console for details.</div>`;
    target.classList.remove('hidden');
  }
}

/* ------------------------- list rendering and event wiring ------------------------- */
function renderIssues(issues) {
  const wrap = $('issues');
  const html = issues && issues.length
    ? issues.map((it, idx) => renderIssue(it, idx)).join('')
    : '<div class="text-slate-400">No issues found — nice!</div>';
  wrap.innerHTML = html;

  // clear previous inspector selection but keep inspector visible state controlled
  hideInspector(false);

  Array.from(document.querySelectorAll('.issue-row')).forEach(el => {
    el.addEventListener('click', (ev) => {
      // ignore clicks originating inside <details> or on buttons
      if (ev.target.closest('details')) return;
      if (ev.target.closest('button')) return;

      const idxAttr = el.getAttribute('data-issue-idx');
      const idx = idxAttr !== null ? parseInt(idxAttr, 10) : NaN;
      if (Number.isNaN(idx)) {
        console.warn('issue clicked but index missing', el);
        return;
      }
      const already = el.classList.contains('selected');
      Array.from(document.querySelectorAll('.issue-row.selected')).forEach(c => c.classList.remove('selected'));
      if (already) { hideInspector(); return; }
      el.classList.add('selected');
      renderSelectedIssueInlineByIndex(idx);
      const details = el.querySelector('details');
      if (details) details.open = false; // auto close details in the card to avoid duplicate content
      const sel = $('selectedIssueInline'); sel.classList.remove('hidden');
      setTimeout(() => sel.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 150);
    });

    const summary = el.querySelector('details > summary');
    if (summary) summary.addEventListener('click', (e) => e.stopPropagation());
  });
}

function hideInspector(alsoClearSelection = true) {
  const sel = $('selectedIssueInline');
  if (!sel) return;
  sel.classList.add('hidden');
  if (alsoClearSelection) Array.from(document.querySelectorAll('.issue-row.selected')).forEach(c => c.classList.remove('selected'));
  sel.innerHTML = '';
}

/* click-outside and ESC support */
function setupGlobalDismiss() {
  document.addEventListener('click', (ev) => {
    if (ev.target.closest('.issue-row') || ev.target.closest('#selectedIssueInline')) return;
    hideInspector();
  });
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') hideInspector(); });
}

/* ------------------------- toolbar helpers ------------------------- */
function computeSeverityDistribution(issues) {
  return issues.reduce((acc, i) => {
    const s = (i.Severity || i.severity || 'LOW').toString().toUpperCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});
}
function topFunctions(issues, n = 8) {
  const byFn = issues.reduce((acc, i) => {
    const raw = i.Function || i.function || i.fn || 'unknown';
    const label = formatFunctionLabel(raw);
    acc[label] = (acc[label] || 0) + 1;
    return acc;
  }, {});
  return Object.entries(byFn).sort((a,b)=>b[1]-a[1]).slice(0,n);
}

/* Severity chips above issues */
function renderSeverityFiltersTop(issues) {
  const container = $('severityFiltersTop');
  container.innerHTML = '<span class="text-xs text-slate-400 mr-2">Severity</span>';
  const dist = computeSeverityDistribution(issues);
  ['HIGH','MEDIUM','LOW'].forEach(s => {
    const count = dist[s] || 0;
    const btn = document.createElement('button');
    btn.className = `chip ${severityClass(s)} ${count ? '' : 'opacity-40'}`;
    btn.disabled = (count === 0);
    btn.innerHTML = `${escapeHtml(s)} ${count ? `<span class="ml-2 text-xs">(${count})</span>` : ''}`;
    btn.onclick = () => {
      const issuesList = window.__lastIssues || [];
      const filtered = issuesList.filter(i => ((i.Severity || i.severity || '').toString().toUpperCase() === s));
      renderIssues(filtered);
      Array.from(container.querySelectorAll('button')).forEach(b => b.classList.remove('ring-2','ring-offset-1'));
      btn.classList.add('ring-2','ring-offset-1');
    };
    container.appendChild(btn);
  });
  const clear = document.createElement('button');
  clear.className = 'border rounded-xl px-2 py-1 text-xs text-slate-300 ml-2';
  clear.textContent = 'Clear';
  clear.onclick = () => {
    renderIssues(window.__lastIssues || []);
    Array.from(container.querySelectorAll('button')).forEach(b => b.classList.remove('ring-2','ring-offset-1'));
  };
  container.appendChild(clear);
}

/* Top functions inline */
function renderTopFunctionsInline(issues) {
  const wrap = $('topFunctions');
  wrap.innerHTML = '';
  const top = topFunctions(issues, 8);
  if (!top.length) { wrap.innerHTML = '<span class="text-slate-400">No data</span>'; return; }
  top.forEach(([label,count]) => {
    const btn = document.createElement('button');
    btn.className = 'badge-mini cursor-pointer';
    btn.innerHTML = `${escapeHtml(label)} <span class="text-xs ml-2 text-slate-400">(${count})</span>`;
    btn.onclick = () => {
      const issuesList = window.__lastIssues || [];
      const funcOnly = label.split('(')[0].split('.').slice(-1)[0];
      const filtered = issuesList.filter(i => {
        const raw = (i.Function || i.function || i.fn || '').toString();
        const rawName = raw.split('(')[0].split('.').slice(-1)[0];
        return rawName === funcOnly;
      });
      renderIssues(filtered);
      Array.from(wrap.querySelectorAll('button')).forEach(b => b.classList.remove('ring-2','ring-offset-1'));
      btn.classList.add('ring-2','ring-offset-1');
    };
    wrap.appendChild(btn);
  });
}

/* render top codes into stats card */
function renderCodeCountsIntoStats(issues) {
  const wrap = document.getElementById('stat-codes');
  if (!wrap) return;
  const byCode = issues.reduce((acc, i) => {
    const code = (i.ID || i.id || 'UNKNOWN').toString();
    acc[code] = (acc[code] || 0) + 1;
    return acc;
  }, {});
  const codes = Object.entries(byCode).sort((a,b) => b[1] - a[1]); // most frequent first
  if (!codes.length) {
    wrap.innerHTML = `<span class="text-slate-400">No codes</span>`;
    return;
  }

  wrap.innerHTML = codes.slice(0,8).map(([code,count]) => {
    return `<button data-code="${escapeHtml(code)}" class="badge-mini cursor-pointer" title="Filter by ${escapeHtml(code)}">${escapeHtml(code)} <span class="ml-1 text-xs text-slate-400">(${count})</span></button>`;
  }).join(' ');

  if (codes.length > 8) {
    const more = document.createElement('span');
    more.className = 'text-xs text-slate-400 ml-2';
    more.textContent = `+${codes.length - 8} more`;
    wrap.appendChild(more);
  }

  Array.from(wrap.querySelectorAll('button[data-code]')).forEach(btn => {
    btn.onclick = () => {
      const code = btn.getAttribute('data-code');
      const issuesList = window.__lastIssues || [];
      const filtered = issuesList.filter(i => (i.ID || i.id || '') === code);
      renderIssues(filtered);
      Array.from(wrap.querySelectorAll('button[data-code]')).forEach(b => b.classList.remove('ring-2','ring-offset-1'));
      btn.classList.add('ring-2','ring-offset-1');
    };
  });
}

/* ------------------------- progress controls ------------------------- */
let __progressTick = null;
let __progressValue = 0;

function startProgress(stage = 'Initializing') {
  const wrap = $('progressWrap');
  const bar = $('progressBar');
  const stageEl = $('progressStage');
  const percentEl = $('progressPercent');

  if (!wrap || !bar || !stageEl || !percentEl) return;

  wrap.classList.remove('hidden');
  bar.classList.add('active');
  __progressValue = Math.max(4, __progressValue || 6);
  bar.style.width = `${__progressValue}%`;
  stageEl.textContent = stage;
  percentEl.textContent = `${Math.round(__progressValue)}%`;

  if (__progressTick) { clearInterval(__progressTick); __progressTick = null; }

  __progressTick = setInterval(() => {
    const bump = Math.random() * 6;
    __progressValue = Math.min(90, __progressValue + bump);
    bar.style.width = `${Math.round(__progressValue)}%`;
    percentEl.textContent = `${Math.round(__progressValue)}%`;
  }, 260);
}

function setProgress(pct = 0, stage = '') {
  const bar = $('progressBar');
  const stageEl = $('progressStage');
  const percentEl = $('progressPercent');
  if (!bar || !stageEl || !percentEl) return;
  __progressValue = Math.max(0, Math.min(100, pct));
  bar.style.width = `${__progressValue}%`;
  percentEl.textContent = `${Math.round(__progressValue)}%`;
  if (stage) stageEl.textContent = stage;
}

function completeProgress(finalStage = 'Finalizing') {
  const wrap = $('progressWrap');
  const bar = $('progressBar');
  const stageEl = $('progressStage');
  const percentEl = $('progressPercent');

  if (!wrap || !bar || !stageEl || !percentEl) return;
  if (__progressTick) { clearInterval(__progressTick); __progressTick = null; }

  stageEl.textContent = finalStage;
  setTimeout(() => {
    __progressValue = 100;
    bar.style.width = '100%';
    percentEl.textContent = '100%';
    setTimeout(() => {
      bar.classList.remove('active');
      wrap.classList.add('progress-hidden');
      setTimeout(() => {
        wrap.classList.add('hidden');
        wrap.classList.remove('progress-hidden');
        bar.style.width = '0%';
        percentEl.textContent = '0%';
        $('progressStage') && ($('progressStage').textContent = 'Waiting');
        __progressValue = 0;
      }, 300);
    }, 420);
  }, 180);
}

/* ------------------------- scanning flow ------------------------- */
async function runScan() {
  const chain = $('chain').value;
  const address = $('address').value.trim();
  if (!address) { alert('Please provide a contract address'); return; }

  $('status').textContent = 'Scanning…';
  $('issues').innerHTML = '';
  $('raw').textContent = '{}';
  $('stat-issues').textContent = '—';
  $('stat-time').textContent = '—';
  $('selectedIssueInline').classList.add('hidden');
  $('selectedIssueInline').innerHTML = '';
  $('severityFiltersTop').innerHTML = '<span class="text-xs text-slate-400 mr-2">Severity</span>';
  $('topFunctions').innerHTML = '<span class="text-slate-400">No data</span>';
  const statCodesWrap = document.getElementById('stat-codes'); if (statCodesWrap) statCodesWrap.innerHTML = '<span class="text-slate-400">No codes</span>';

  // start progress
  startProgress('Scanning Contract');

  const payload = { chain, address };
  const start = Date.now();

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    // bump during network -> parse
    setProgress(72, 'Parsing response');

    const json = await res.json().catch(() => ({}));
    if (!res.ok) {
      completeProgress('Error');
      $('status').textContent = `Error: ${json.error || res.statusText || 'scan failed'}`;
      return;
    }

    const elapsed = Date.now() - start;

    // finalize progress
    completeProgress('Finishing');

    // tolerant parsing of issues
    let issues = [];
    if (Array.isArray(json.issues_found)) issues = json.issues_found;
    else if (Array.isArray(json.issues)) issues = json.issues;
    else if (Array.isArray(json.results)) issues = json.results;
    else {
      const all = [];
      ['info_IV','info_AC','info_ACM','info_MCO','detector','access','mint','override'].forEach(k => {
        if (Array.isArray(json[k])) all.push(...json[k]);
        else if (json[k] && Array.isArray(json[k].issues_found)) all.push(...json[k].issues_found);
      });
      if (all.length) issues = all;
    }

    window.__lastIssues = issues || [];
    renderIssues(window.__lastIssues);
    $('stat-issues').textContent = window.__lastIssues.length || 0;
    renderCodeCountsIntoStats(window.__lastIssues);
    // Show scan time in ms or seconds intelligently
const durationMs = (json.meta && json.meta.duration_ms) ? json.meta.duration_ms : elapsed;
const durationText = durationMs >= 1000
  ? `${(durationMs / 1000).toFixed(2)} s`
  : `${Math.round(durationMs)} ms`;
$('stat-time').textContent = durationText;

    renderSeverityFiltersTop(window.__lastIssues);
    renderTopFunctionsInline(window.__lastIssues);

    // filter select fallback
    const filterSel = $('filter');
    const ids = [...new Set(window.__lastIssues.map(i => (i.ID || i.id)).filter(Boolean))].sort();
    const sevs = [...new Set(window.__lastIssues.map(i => (i.Severity || i.severity)).filter(Boolean))];
    const opts = [{ value: 'all', label: 'All' }];
    ids.forEach(id => opts.push({ value: id, label: id }));
    sevs.forEach(s => opts.push({ value: `sev:${s}`, label: `Severity: ${s}` }));
    if (opts.length > 1) {
      filterSel.innerHTML = opts.map(o => `<option value="${escapeHtml(o.value)}">${escapeHtml(o.label)}</option>`).join('');
      filterSel.classList.remove('hidden');
      filterSel.onchange = () => {
        const val = filterSel.value;
        if (!val || val === 'all') return renderIssues(window.__lastIssues || []);
        if (val.startsWith('sev:')) {
          const s = val.slice(4).toUpperCase();
          const filtered = (window.__lastIssues || []).filter(i => ((i.Severity || i.severity || '').toString().toUpperCase() === s));
          renderIssues(filtered);
          return;
        }
        const byId = (window.__lastIssues || []).filter(i => (i.ID || i.id) === val);
        renderIssues(byId);
      };
    } else {
      filterSel.classList.add('hidden');
    }

    $('raw').textContent = JSON.stringify(json, null, 2);
    $('status').textContent = json.summary || 'Scan complete';
  } catch (e) {
    if (__progressTick) { clearInterval(__progressTick); __progressTick = null; }
    $('progressWrap') && $('progressWrap').classList.add('hidden');
    $('status').textContent = 'Unexpected error: ' + (e.message || e);
    console.error(e);
  }
}

/* ------------------------- boot / init ------------------------- */
document.addEventListener('DOMContentLoaded', () => {
  $('run').addEventListener('click', runScan);
  $('clear').addEventListener('click', () => {
    $('address').value = '';
    $('issues').innerHTML = 'Run a scan to see issues — we\'ll make them pop ✨';
    $('raw').textContent = '{}';
    $('status').textContent = 'No scan yet';
    $('stat-issues').textContent = '—';
    const sc = document.getElementById('stat-codes'); if (sc) sc.innerHTML = '<span class="text-slate-400">No codes</span>';
    $('stat-time').textContent = '—';
    $('selectedIssueInline').classList.add('hidden');
    $('selectedIssueInline').innerHTML = '';
    $('severityFiltersTop').innerHTML = '<span class="text-xs text-slate-400 mr-2">Severity</span>';
    $('topFunctions').innerHTML = '<span class="text-slate-400">No data</span>';
    const prev = document.getElementById('__counters'); if (prev) prev.remove();
    const filterSel = $('filter'); if (filterSel) filterSel.classList.add('hidden');
    window.__lastIssues = [];
  });
  $('address').addEventListener('keydown', (e) => { if (e.key === 'Enter') runScan(); });
  setupGlobalDismiss();
});
