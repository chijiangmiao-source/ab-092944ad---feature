/* 机载维护镜像 · 链接闭合审计前端 */

const MAX_ROWS = 12;
const rowsEl = document.getElementById('rows');
const verdictEl = document.getElementById('verdict');
const errEl = document.getElementById('requestError');
const hintEl = document.getElementById('loadHint');
const submitBtn = document.getElementById('submitBtn');
const auditIdEl = document.getElementById('auditId');

let seq = 0;
let currentVerdict = null;        // 最近展示的冻结结论
let traceFocus = null;            // 符号轨迹示例的三个焦点符号

function addRow({ name = '', group = '', data = '' } = {}) {
  if (rowsEl.children.length >= MAX_ROWS) return;
  seq += 1;
  const pos = rowsEl.children.length + 1;
  const row = document.createElement('div');
  row.className = 'row';
  row.innerHTML = `
    <div class="pos">#${pos}</div>
    <div class="flds">
      <input type="text" class="r-name" placeholder="对象或归档文件名（如 main.o / libx.a）"
             value="${escapeAttr(name)}" autocomplete="off" spellcheck="false" />
      <div class="data-row">
        <textarea class="r-data" placeholder="粘贴 Base64（ELF64 ET_REL 或 GNU ar），或用右侧按钮选择文件"
                  spellcheck="false">${escapeAttr(data)}</textarea>
        <label class="file-btn" title="从本地文件读取并编码为 Base64">📄
          <input type="file" class="r-file" hidden />
        </label>
      </div>
    </div>
    <div class="flds2">
      <input type="text" class="r-group" placeholder="组标签"
             value="${escapeAttr(group)}" autocomplete="off" spellcheck="false"
             title="相同组标签且连续的输入按 --start-group 语义反复扫描" />
    </div>
    <button class="del" type="button" title="删除此行">✕</button>`;
  row.querySelector('.del').addEventListener('click', () => {
    row.remove();
    renumber();
  });
  row.querySelector('.r-file').addEventListener('change', (ev) => {
    const file = ev.target.files?.[0];
    if (!file) return;
    const nameInput = row.querySelector('.r-name');
    if (!nameInput.value.trim()) nameInput.value = file.name;
    const reader = new FileReader();
    reader.onload = () => {
      const b64Text = String(reader.result).split(',')[1] ?? '';
      row.querySelector('.r-data').value = b64Text;
    };
    reader.readAsDataURL(file);
  });
  rowsEl.appendChild(row);
  renumber();
}

function renumber() {
  [...rowsEl.children].forEach((r, i) => {
    r.querySelector('.pos').textContent = `#${i + 1}`;
  });
}

function escapeAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function collect() {
  const inputs = [...rowsEl.children].map((r) => ({
    name: r.querySelector('.r-name').value.trim(),
    group: (r.querySelector('.r-group').value.trim() || null),
    data_b64: r.querySelector('.r-data').value.replace(/\s+/g, ''),
  }));
  return {
    audit_id: auditIdEl.value.trim(),
    audit_type: 'link_closure',
    inputs,
  };
}

function showRequestError(msg) {
  errEl.hidden = false;
  errEl.textContent = msg;
}
function clearRequestError() {
  errEl.hidden = true;
  errEl.textContent = '';
}

function setBusy(on, hint = '') {
  submitBtn.disabled = on;
  hintEl.textContent = hint;
}

// --------------------------------------------------------------------------- //
async function submitAudit() {
  clearRequestError();
  verdictEl.innerHTML = '<div class="empty">裁决计算中…</div>';
  const payload = collect();
  let basicErr = null;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(payload.audit_id)) {
    basicErr = '审计标识不合法：须为 1-64 位字母数字及 ._-，以字母数字开头。';
  } else if (payload.inputs.length === 0) {
    basicErr = '请至少填写一个输入。';
  } else if (payload.inputs.some((i) => !i.name || !i.data_b64)) {
    basicErr = '每行都需要文件名与 Base64 数据。';
  }
  if (basicErr) {
    showRequestError(basicErr);
    verdictEl.innerHTML = '<div class="empty">尚未提交</div>';
    return;
  }
  setBusy(true, 'POST /api/audits …');
  try {
    const res = await fetch('/api/audits', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (res.status >= 400 && body.status === undefined) {
      showRequestError(`${body.error?.code ?? 'ERROR'}: ${body.error?.message ?? res.statusText}`);
      verdictEl.innerHTML = '<div class="empty">请求被拒绝，未产生冻结结论</div>';
      return;
    }
    renderVerdict(body, { frozen: res.status === 409 });
  } catch (e) {
    showRequestError(`网络错误：${e.message}`);
    verdictEl.innerHTML = '<div class="empty">后端不可达</div>';
  } finally {
    setBusy(false, '');
  }
}

async function reopenAudit() {
  clearRequestError();
  const id = auditIdEl.value.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id)) {
    showRequestError('请先填写合法的稳定审计标识。');
    return;
  }
  setBusy(true, `GET /api/audits/${id} …`);
  verdictEl.innerHTML = '<div class="empty">读取冻结结论…</div>';
  try {
    const res = await fetch(`/api/audits/${encodeURIComponent(id)}`);
    const body = await res.json();
    if (res.status === 404) {
      currentVerdict = null;
      verdictEl.innerHTML = `<div class="empty">${escapeHtml(body.error?.message ?? '无冻结结论')}</div>`;
      return;
    }
    renderVerdict(body, { frozen: true, reopened: true });
  } catch (e) {
    showRequestError(`网络错误：${e.message}`);
  } finally {
    setBusy(false, '');
  }
}

async function fillTraceDemo() {
  clearRequestError();
  setBusy(true, 'GET /api/demo/symbol-trace …');
  try {
    const res = await fetch('/api/demo/symbol-trace');
    const demo = await res.json();
    auditIdEl.value = demo.audit_id;
    rowsEl.innerHTML = '';
    demo.inputs.forEach((i) => addRow({ name: i.name, group: i.group ?? '', data: i.data_b64 }));
    traceFocus = demo.focus_symbols ?? null;
    verdictEl.innerHTML = `<div class="empty">已填充${demo.inputs.length}个真实合成输入（${escapeHtml(demo.explanation)}）。点击「提交审计」，随后自动通过只读接口追查三个焦点符号。</div>`;
  } catch (e) {
    showRequestError(`示例加载失败：${e.message}`);
  } finally {
    setBusy(false, '');
  }
}

async function fillDemo() {
  clearRequestError();
  setBusy(true, 'GET /api/demo/cycle …');
  try {
    const res = await fetch('/api/demo/cycle');
    const demo = await res.json();
    auditIdEl.value = demo.audit_id;
    rowsEl.innerHTML = '';
    demo.inputs.forEach((i) => addRow({ name: i.name, group: i.group ?? '', data: i.data_b64 }));
    traceFocus = null;
    verdictEl.innerHTML = `<div class="empty">已填充${demo.inputs.length}个真实合成输入（${escapeHtml(demo.explanation)}）。点击「提交审计」查看裁决。</div>`;
  } catch (e) {
    showRequestError(`示例加载失败：${e.message}`);
  } finally {
    setBusy(false);
  }
}

// --------------------------------------------------------------------------- //
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function tag(text, cls = '') {
  return `<span class="tag ${cls}">${escapeHtml(text)}</span>`;
}

function renderVerdict(v, { frozen = false, reopened = false } = {}) {
  currentVerdict = v;
  const accepted = v.status === 'accepted';
  const banner = accepted
    ? `<div class="banner accepted"><span class="dot">✔</span> 链接闭包通过 · 审计标识 ${escapeHtml(v.audit_id)}</div>`
    : `<div class="banner rejected"><span class="dot">✖</span> 审计拒绝 · ${escapeHtml(v.error?.code ?? '')} · 审计标识 ${escapeHtml(v.audit_id)}</div>`;

  let html = banner;
  if (frozen) {
    html += `<div class="frozen-note">❄ ${reopened ? '重开的' : '返回的'}是按稳定标识冻结的既有结论（HTTP ${reopened ? '200' : '409'}），不会被本次提交覆盖。</div>`;
  }

  html += `<div class="meta-grid">
    <div class="meta-item"><div class="k">状态</div><div class="v">${escapeHtml(v.status)}</div></div>
    <div class="meta-item"><div class="k">输入数</div><div class="v">${(v.inputs ?? []).length}</div></div>
    <div class="meta-item"><div class="k">抽取成员</div><div class="v">${(v.extraction_order ?? []).length}</div></div>
    <div class="meta-item"><div class="k">扫描轮次</div><div class="v">${(v.rounds ?? []).length}</div></div>
  </div>`;

  if (!accepted && v.error) {
    html += `<h3>首次触发位置</h3>
      <div class="loc">${escapeHtml(v.error.location)}</div>
      <div style="font-size:.82rem;margin-top:4px">${escapeHtml(v.error.message)}</div>`;
    const ev = v.error.evidence ?? {};
    if (ev.undefined) {
      html += `<h3>最终未定义集合</h3><div class="undef-set">${ev.undefined.map(escapeHtml).join(', ') || '（空）'}</div>`;
    }
    if (ev.first_definition) {
      html += `<h3>强定义冲突证据</h3>
        <table><tr><th>先定义</th><td class="mono">${escapeHtml(ev.first_definition)}</td></tr>
        <tr><th>冲突定义</th><td class="mono">${escapeHtml(ev.conflicting_definition ?? '')}</td></tr></table>`;
    }
  }

  html += renderInputs(v.inputs ?? []);
  html += renderExtraction(v.extraction_order ?? []);
  html += renderRounds(v.rounds ?? []);
  html += renderDefinitions(v.definitions ?? {});
  if ((v.weak_unresolved ?? []).length) {
    html += `<h3>弱未定义（不判错）</h3><div class="undef-set">${v.weak_unresolved.map(escapeHtml).join(', ')}</div>`;
  }
  html += renderTraceSection(v);
  verdictEl.innerHTML = html;
  bindTraceSection(v);
}

function renderInputs(inputs) {
  if (!inputs.length) return '';
  const rows = inputs.map((i) => `
    <tr>
      <td class="mono">#${i.position}</td>
      <td class="mono">${escapeHtml(i.name)}</td>
      <td>${i.kind === 'ar' ? tag('GNU ar', 'ar') : tag('ELF REL', 'obj')}</td>
      <td class="mono">${i.group ? tag('组 ' + i.group) : '—'}</td>
      <td class="mono">${i.bytes} B${i.members ? ` · ${i.members.length} 成员 · 索引 ${i.index_symbols} 符号` : ''}</td>
    </tr>`).join('');
  return `<h3>输入（命令行顺序）</h3><div class="scroll"><table>
    <tr><th>位置</th><th>名称</th><th>类型</th><th>成组</th><th>规模</th></tr>${rows}
  </table></div>`;
}

function renderExtraction(orders) {
  if (!orders.length) return '<h3>归档成员抽取顺序</h3><div class="empty">无归档成员被抽取</div>';
  const rows = orders.map((e) => `
    <tr>
      <td class="mono">${e.seq}</td>
      <td class="mono">#${e.input_position} ${escapeHtml(e.archive)}</td>
      <td class="mono">${escapeHtml(e.member)}</td>
      <td class="mono">${(e.matched_index_symbols ?? []).map(escapeHtml).join(', ')}</td>
      <td class="mono pill">${e.context ?? ''}${e.pass_or_round ? '#' + e.pass_or_round : ''}</td>
      <td class="undef-set">{${(e.undefined_before ?? []).join(', ')}}</td>
      <td class="undef-set">{${(e.undefined_after ?? []).join(', ')}}</td>
    </tr>`).join('');
  return `<h3>归档成员抽取顺序（含匹配索引符号与每轮未定义集合）</h3>
  <div class="scroll"><table>
    <tr><th>#</th><th>归档</th><th>成员</th><th>命中索引符号</th><th>上下文/轮次</th><th>抽取前未定义</th><th>抽取后未定义</th></tr>
    ${rows}
  </table></div>`;
}

function renderRounds(rounds) {
  if (!rounds.length) return '';
  const rows = rounds.map((r) => {
    const scope = r.scope === 'group'
      ? `组 ${r.group} · 第 ${r.round} 轮`
      : `归档 ${r.archive} · 第 ${r.pass} 趟`;
    const extracted = r.scope === 'group'
      ? (r.scans ?? []).map((s) => `${s.name}:[${(s.extracted ?? []).join(', ')}]`).join(' ｜ ')
      : (r.extracted ?? []).join(', ');
    return `<tr>
      <td class="mono">${scope}</td>
      <td class="mono">${escapeHtml(extracted || '—')}</td>
      <td>${r.changed ? tag('有新增', 'err') : tag('收敛', 'ok')}</td>
      <td class="undef-set">{${(r.undefined_before ?? []).join(', ')}}</td>
      <td class="undef-set">{${(r.undefined_after ?? []).join(', ')}}</td>
    </tr>`;
  }).join('');
  return `<details open><summary>逐趟/逐轮扫描证据（${rounds.length}）</summary>
  <div class="scroll"><table>
    <tr><th>范围</th><th>本轮抽取</th><th>未定义集合变化</th><th>轮前</th><th>轮后</th></tr>
    ${rows}
  </table></div></details>`;
}

function renderDefinitions(defs) {
  const names = Object.keys(defs);
  if (!names.length) return '';
  const rows = names.map((n) => {
    const d = defs[n];
    const cls = d.binding === 'strong' ? 'strong' : d.binding === 'weak' ? 'weak' : 'common';
    return `<tr><td class="mono">${escapeHtml(n)}</td>
      <td>${tag(d.binding, cls)}</td>
      <td class="mono" style="font-size:.7rem">${escapeHtml(d.source)}</td></tr>`;
  }).join('');
  return `<details><summary>外部符号裁决表（${names.length}）</summary>
  <div class="scroll"><table>
    <tr><th>符号</th><th>裁决绑定</th><th>满足位置</th></tr>${rows}
  </table></div></details>`;
}

// --------------------------------------------------------------------------- //
// ④ 冻结结论逐符号轨迹（只读真实接口，不重放裁决）
// --------------------------------------------------------------------------- //
const TRACE_EVENT_CLS = {
  strong_reference: 'weak',          // 引用：中性蓝
  weak_reference: 'weak',
  weak_definition: 'weak',
  strong_definition: 'strong',
  common_definition: 'common',
  archive_index_hit: 'ar',
  member_extracted: 'ar',
  final_undefined: 'err',
};

function renderTraceSection(v) {
  const embedded = v.symbol_traces;
  if (embedded === undefined) {
    const reason = v.error
      ? `该结论在字节解析/请求校验阶段即被拒绝（${v.error.code}），链接裁决未开始，没有可重放的符号轨迹。`
      : '该冻结结论生成于符号轨迹功能上线前，不含逐符号轨迹数据。';
    return `<h3>④ 外部符号轨迹追查</h3>
      <div class="empty">${reason}</div>`;
  }
  const focus = (traceFocus && Object.values(traceFocus).every((s) => embedded[s]))
    ? traceFocus : null;
  const focusChips = focus
    ? [...new Set(Object.values(focus))]
        .map((s) => `<button type="button" class="btn small trace-focus-chip" data-symbol="${escapeAttr(s)}">${escapeHtml(s)}</button>`)
        .join('')
    : '';
  return `<h3>④ 外部符号轨迹追查（只读接口 · 按命令行处理序）</h3>
    <div class="trace-bar">
      <select id="traceSelect" class="trace-select" disabled>
        <option>加载已收录符号…</option>
      </select>
      <button id="traceQueryBtn" class="btn small" type="button" disabled>追查选中符号</button>
      <input id="traceAny" class="trace-any" type="text" maxlength="128"
             placeholder="也可输入任意符号名验证未收录反馈" autocomplete="off" spellcheck="false" />
      <button id="traceAnyBtn" class="btn small ghost" type="button">按名追查</button>
      <span class="trace-hint">${focusChips ? '焦点符号：' : ''}${focusChips}</span>
    </div>
    <div id="traceError" class="trace-feedback" hidden></div>
    ${focus ? '<div id="traceFocusPanels" class="trace-focus-wrap"></div>' : ''}
    <div id="tracePanel"></div>`;
}

function bindTraceSection(v) {
  if (v.symbol_traces === undefined) return;
  const auditId = v.audit_id;
  const selectEl = document.getElementById('traceSelect');
  const queryBtn = document.getElementById('traceQueryBtn');
  const anyBtn = document.getElementById('traceAnyBtn');
  const anyInput = document.getElementById('traceAny');

  fetch(`/api/audits/${encodeURIComponent(auditId)}/symbols`)
    .then((r) => r.json())
    .then((body) => {
      selectEl.innerHTML = '<option value="">— 选择已出现的符号 —</option>'
        + body.symbols.map((s) =>
          `<option value="${escapeAttr(s.symbol)}">${escapeHtml(s.symbol)}（${escapeHtml(s.final_state)}）</option>`).join('');
      selectEl.disabled = false;
      queryBtn.disabled = false;
    })
    .catch((e) => {
      selectEl.innerHTML = '<option>符号列表加载失败</option>';
      showTraceError(`符号列表接口不可达：${e.message}`);
    });

  queryBtn.addEventListener('click', () => {
    const sym = selectEl.value;
    if (sym) queryAndRender(auditId, sym, { target: 'tracePanel' });
  });
  selectEl.addEventListener('change', () => {
    if (selectEl.value) queryAndRender(auditId, selectEl.value, { target: 'tracePanel' });
  });
  anyBtn.addEventListener('click', () => {
    const sym = anyInput.value.trim();
    if (!sym) return;
    queryAndRender(auditId, sym, { target: 'tracePanel' });
  });
  anyInput.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') anyBtn.click();
  });
  document.querySelectorAll('.trace-focus-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const sym = chip.dataset.symbol;
      queryAndRender(auditId, sym, { target: 'tracePanel', highlight: true });
    });
  });

  // 轨迹示例：仅当焦点符号确已收录于该冻结结论时，才自动通过真实接口拉取三类归因结果。
  if (traceFocus) {
    const traces = v.symbol_traces ?? {};
    const allWanted = Object.values(traceFocus);
    if (allWanted.every((s) => traces[s])) {
      const wanted = [
        [traceFocus.cross_member, '归档跨成员满足'],
        [traceFocus.weak_to_strong, '弱转强覆盖'],
        [traceFocus.undefined, '最终未定义归因'],
      ];
      const wrap = document.getElementById('traceFocusPanels');
      wrap.innerHTML = wanted.map(([sym, label]) =>
        `<div class="trace-focus-slot" data-symbol="${escapeAttr(sym)}">
           <div class="trace-slot-head">${escapeHtml(label)} · <span class="mono">${escapeHtml(sym)}</span></div>
           <div class="empty">轨迹加载中…</div>
         </div>`).join('');
      wanted.forEach(([sym]) => queryAndRender(auditId, sym, { target: 'focusSlot', slotSymbol: sym }));
    } else {
      const wrap = document.getElementById('traceFocusPanels');
      if (wrap) wrap.remove();
    }
  }
}

function showTraceError(msg) {
  const el = document.getElementById('traceError');
  if (!el) return;
  el.hidden = false;
  el.textContent = msg;
}

async function queryAndRender(auditId, symbol, { target = 'tracePanel', slotSymbol = null, highlight = false } = {}) {
  const errEl = document.getElementById('traceError');
  if (target === 'tracePanel' && errEl) { errEl.hidden = true; errEl.textContent = ''; }
  let panel;
  if (target === 'focusSlot') {
    panel = document.querySelector(`.trace-focus-slot[data-symbol="${CSS.escape(slotSymbol)}"]`);
  } else {
    panel = document.getElementById('tracePanel');
  }
  if (!panel) return;
  try {
    const res = await fetch(`/api/audits/${encodeURIComponent(auditId)}/symbols/${encodeURIComponent(symbol)}`);
    const body = await res.json();
    if (!res.ok) {
      panel.innerHTML = renderTraceNotRecorded(body, res.status);
      return;
    }
    panel.innerHTML = renderTrace(body, { embedded: target === 'focusSlot', highlight });
  } catch (e) {
    panel.innerHTML = `<div class="empty">轨迹接口不可达：${escapeHtml(e.message)}</div>`;
  }
}

function renderTraceNotRecorded(body, status) {
  const err = body.error ?? {};
  const avail = err.available_symbols ?? [];
  return `<div class="trace-missing">
    <div class="trace-missing-head">⚠ ${escapeHtml(err.code ?? 'ERROR')}（HTTP ${status}）· 可操作反馈</div>
    <div class="trace-missing-msg">${escapeHtml(err.message ?? '查询失败')}</div>
    ${avail.length ? `<div class="trace-missing-alt">该冻结结论已收录的符号：${avail.map((s) =>
      `<button type="button" class="btn small trace-jump" data-symbol="${escapeAttr(s)}">${escapeHtml(s)}</button>`).join(' ')}</div>` : ''}
  </div>`;
}

function renderTrace(body, { embedded = false, highlight = false } = {}) {
  const t = body.trace;
  const labels = body.event_labels ?? {};
  const adopted = t.adopted_definition;
  const stateCls = ({ strong: 'strong', weak: 'weak', common: 'common', undefined: 'err' })[t.final_state] ?? '';
  const head = `<div class="trace-head${highlight ? ' hl' : ''}">
    <span class="mono">${escapeHtml(t.symbol)}</span>
    ${tag(t.final_state, stateCls)}
    ${adopted
      ? `<span class="trace-adopt">最终采用：${escapeHtml(adopted.binding)} @ ${escapeHtml(adopted.source)}</span>`
      : '<span class="trace-adopt weak">无采用定义</span>'}
  </div>`;

  const rows = t.events.map((e) => {
    const cls = TRACE_EVENT_CLS[e.type] ?? '';
    const detailBits = [];
    if (e.symtab_index !== undefined && e.symtab_index !== null) {
      detailBits.push(`.symtab[${e.symtab_index}]`);
    }
    if (e.context) detailBits.push(`${e.context}${e.pass_or_round ? '#' + e.pass_or_round : ''}`);
    if (e.extraction_seq) detailBits.push(`抽取序#${e.extraction_seq}`);
    if (e.binding_before !== undefined || e.binding_after !== undefined) {
      detailBits.push(`绑定 ${e.binding_before ?? '∅'} → ${e.binding_after ?? '∅'}`);
    }
    if (e.undefined_added) detailBits.push('加入强未定义集合');
    if (e.undefined_removed) detailBits.push('移出未定义集合');
    if (e.archive && e.member) detailBits.push(`${e.archive}!${e.member}`);
    const after = e.strong_undefined_after ?? e.undefined_after ?? null;
    return `<tr class="${e.terminal ? 'term-row' : ''}">
      <td class="mono">${e.seq}</td>
      <td>${tag(labels[e.type] ?? e.type, cls)}</td>
      <td class="mono trace-loc">${escapeHtml(e.location)}</td>
      <td>${escapeHtml(e.effect)}</td>
      <td class="mono trace-detail">${detailBits.map(escapeHtml).join(' · ')}</td>
      <td class="undef-set">${after === null ? '—' : (after.length ? `{${after.join(', ')}}` : '{∅}')}</td>
    </tr>`;
  }).join('');

  const terminalBox = t.terminal
    ? `<div class="trace-terminal">⛔ 轨迹止于首个拒绝证据：${escapeHtml(t.terminal.code)}
        @ <span class="mono">${escapeHtml(t.terminal.location)}</span>${
          t.terminal.note ? `<div class="trace-term-note">${escapeHtml(t.terminal.note)}</div>` : ''}</div>`
    : '';

  return `${head}
  <div class="scroll trace-scroll"><table>
    <tr><th>处理序</th><th>事件</th><th>输入位置</th><th>对未定义集合 / 绑定的影响</th><th>细节</th><th>事后强未定义集合</th></tr>
    ${rows}
  </table></div>
  ${terminalBox}`;
}

// --------------------------------------------------------------------------- //
document.getElementById('submitBtn').addEventListener('click', submitAudit);
document.getElementById('reopenBtn').addEventListener('click', reopenAudit);
document.getElementById('addRow').addEventListener('click', () => addRow());
document.getElementById('addDemo').addEventListener('click', fillDemo);
document.getElementById('addTraceDemo').addEventListener('click', fillTraceDemo);

// 未收录反馈中的符号按钮：委托绑定，直接追查该已收录符号。
verdictEl.addEventListener('click', (ev) => {
  const jump = ev.target.closest('.trace-jump');
  if (!jump || !currentVerdict) return;
  queryAndRender(currentVerdict.audit_id, jump.dataset.symbol, { target: 'tracePanel' });
});

addRow();
verdictEl.innerHTML = '<div class="empty">填写标识与输入，或点击「填充循环依赖示例」</div>';
