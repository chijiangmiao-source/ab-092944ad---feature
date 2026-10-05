/* 机载维护镜像 · 链接闭合审计前端 */

const MAX_ROWS = 12;
const rowsEl = document.getElementById('rows');
const verdictEl = document.getElementById('verdict');
const errEl = document.getElementById('requestError');
const hintEl = document.getElementById('loadHint');
const submitBtn = document.getElementById('submitBtn');
const auditIdEl = document.getElementById('auditId');

let seq = 0;

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
    setBusy(false);
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
      verdictEl.innerHTML = `<div class="empty">${escapeHtml(body.error?.message ?? '无冻结结论')}</div>`;
      return;
    }
    renderVerdict(body, { frozen: true, reopened: true });
  } catch (e) {
    showRequestError(`网络错误：${e.message}`);
  } finally {
    setBusy(false);
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
  html += renderTracePanelSkeleton(v.audit_id);
  verdictEl.innerHTML = html;
  initTracePanel(v.audit_id);
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
// ④ 符号归因追查（只读真实接口，不重放、不改写冻结结论）
// --------------------------------------------------------------------------- //
let traceBusy = false;

function renderTracePanelSkeleton(auditId) {
  return `
  <div class="trace-panel" id="tracePanel" data-audit="${escapeAttr(auditId)}">
    <h3>④ 外部符号归因追查（只读）</h3>
    <div class="trace-hint">选择冻结结论中已出现的符号，按<strong>命令行处理顺序</strong>
      追溯其引用、弱/强定义、归档索引命中与实际抽取成员；每项含输入位置及对未定义集合/绑定的影响。
      追查仅读取冻结证据，不改变结论、抽取顺序或冻结重放。</div>
    <div class="trace-controls">
      <select id="traceSelect" class="trace-select">
        <option value="">— 加载已收录符号中 —</option>
      </select>
      <input type="text" id="traceCustom" class="trace-custom"
             placeholder="或输入任意符号名尝试追查（未收录会给出反馈）"
             autocomplete="off" spellcheck="false" />
      <button id="traceQueryBtn" class="btn small" type="button">追查</button>
    </div>
    <div id="traceResult" class="trace-result">
      <div class="empty">请选择一个已收录符号开始追查</div>
    </div>
  </div>`;
}

const FINAL_STATE_BADGE = {
  bound_strong: ['最终采用强定义', 'strong'],
  bound_weak: ['最终仅弱定义（占位）', 'weak'],
  bound_common: ['最终采用 COMMON 暂定定义', 'common'],
  final_undefined: ['最终未定义 · 裁决拒绝', 'err'],
  duplicate_strong_rejected: ['重复强定义 · 裁决拒绝', 'err'],
  weak_unresolved: ['弱未定义残留（不判错）', 'weak'],
  no_effect_binding: ['未形成绑定', ''],
};

function initTracePanel(auditId) {
  const select = document.getElementById('traceSelect');
  const custom = document.getElementById('traceCustom');
  const btn = document.getElementById('traceQueryBtn');
  const result = document.getElementById('traceResult');
  if (!select) return;

  fetch(`/api/audits/${encodeURIComponent(auditId)}/symbols`)
    .then((r) => r.json())
    .then((listing) => {
      if (!listing.symbols) throw new Error('符号清单响应异常');
      select.innerHTML = '<option value="">— 请选择已收录符号 —</option>';
      const groups = new Map();
      for (const s of listing.symbols) {
        const [label] = FINAL_STATE_BADGE[s.final_state] || [s.final_state];
        if (!groups.has(label)) groups.set(label, []);
        groups.get(label).push(s);
      }
      for (const [label, items] of groups) {
        const og = document.createElement('optgroup');
        og.label = `${label}（${items.length}）`;
        items.forEach((s) => {
          const o = document.createElement('option');
          o.value = s.symbol;
          o.textContent = `${s.symbol} · ${s.event_count} 个事件`;
          og.appendChild(o);
        });
        select.appendChild(og);
      }
      result.innerHTML = `<div class="empty">已收录 ${listing.count} 个符号，请选择或输入符号名后追查</div>`;
    })
    .catch((e) => {
      select.innerHTML = '<option value="">— 符号清单不可用 —</option>';
      result.innerHTML = `<div class="empty">符号清单加载失败：${escapeHtml(e.message)}</div>`;
    });

  select.addEventListener('change', () => {
    if (select.value) {
      custom.value = '';
      queryTrace(auditId, select.value);
    }
  });
  btn.addEventListener('click', () => {
    const name = custom.value.trim();
    if (!name) {
      if (select.value) queryTrace(auditId, select.value);
      return;
    }
    queryTrace(auditId, name);
  });
  custom.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') btn.click();
  });
}

async function queryTrace(auditId, name) {
  const result = document.getElementById('traceResult');
  if (traceBusy) return;
  traceBusy = true;
  result.innerHTML = `<div class="empty">GET /api/audits/${escapeHtml(auditId)}/symbols/${escapeHtml(name)} …</div>`;
  try {
    const res = await fetch(
      `/api/audits/${encodeURIComponent(auditId)}/symbols/${encodeURIComponent(name)}`
    );
    const body = await res.json();
    if (res.status === 404 && body.found === false) {
      renderNotRecorded(body);
    } else if (res.status >= 400) {
      result.innerHTML = `<div class="empty">${escapeHtml(body.error?.message ?? '追查失败')}</div>`;
    } else {
      renderTrace(body);
    }
  } catch (e) {
    result.innerHTML = `<div class="empty">网络错误：${escapeHtml(e.message)}</div>`;
  } finally {
    traceBusy = false;
  }
}

function renderNotRecorded(body) {
  const result = document.getElementById('traceResult');
  const err = body.error ?? {};
  const ev = err.evidence ?? {};
  const action = body.action ?? {};
  const chips = (names) => names.map((n) =>
    `<button type="button" class="chip" data-symbol="${escapeAttr(n)}">${escapeHtml(n)}</button>`
  ).join('') || '<span class="muted-s">（无）</span>';
  result.innerHTML = `
    <div class="trace-notfound">
      <div class="nf-head">⊘ 未收录符号：<span class="mono">${escapeHtml(body.symbol)}</span></div>
      <div class="nf-msg">${escapeHtml(err.message)}</div>
      ${(ev.closest_matches ?? []).length
        ? `<div class="nf-row"><span class="nf-k">名称相近：</span>${chips(ev.closest_matches)}</div>`
        : '<div class="nf-row"><span class="nf-k">名称相近：</span><span class="muted-s">无匹配</span></div>'}
      <div class="nf-row"><span class="nf-k">可操作建议：</span>
        <ul class="nf-steps">${(action.steps ?? []).map((s) => `<li>${escapeHtml(s)}</li>`).join('')}</ul></div>
      <details><summary>该冻结结论收录的全部 ${ev.recorded_symbol_count ?? 0} 个符号</summary>
        <div class="nf-chips">${chips(action.recorded_symbols ?? [])}</div></details>
    </div>`;
  result.querySelectorAll('.chip').forEach((c) => {
    c.addEventListener('click', () => {
      const sel = document.getElementById('traceSelect');
      if ([...sel.options].some((o) => o.value === c.dataset.symbol)) {
        sel.value = c.dataset.symbol;
      } else {
        document.getElementById('traceCustom').value = c.dataset.symbol;
      }
      queryTrace(body.audit_id, c.dataset.symbol);
    });
  });
}

const TYPE_LABEL = {
  strong_reference: '强引用',
  weak_reference: '弱引用',
  common_reference: 'COMMON 引用',
  weak_definition: '弱定义',
  strong_definition: '强定义',
  common_definition: 'COMMON 定义',
  duplicate_strong_definition: '重复强定义',
  archive_index_hit: '归档索引命中',
  archive_index_skip: '索引命中但成员已抽取',
  archive_index_miss: '归档索引不收录',
  final_undefined_rejection: '最终未定义拒绝',
};

function renderTrace(t) {
  const result = document.getElementById('traceResult');
  const [stateLabel, stateCls] = FINAL_STATE_BADGE[t.final.state] ?? [t.final.state, ''];
  const c = t.counts ?? {};
  let html = `
    <div class="trace-head">
      <div class="trace-sym mono">${escapeHtml(t.symbol)}</div>
      ${tag(stateLabel, stateCls)}
      <span class="readonly-pill">❄ 只读 · 冻结证据</span>
    </div>`;
  if (t.final.bound_location) {
    html += `<div class="trace-bound">最终绑定位置：<span class="mono">${escapeHtml(t.final.bound_location)}</span></div>`;
  }
  html += `<div class="trace-counts">
    <span>强引用 ${c.strong_references ?? 0}</span>
    <span>弱引用 ${c.weak_references ?? 0}</span>
    <span>弱定义 ${c.weak_definitions ?? 0}</span>
    <span>强定义 ${c.strong_definitions ?? 0}</span>
    <span>索引命中 ${c.archive_index_hits ?? 0}</span>
    <span>实际抽取成员 ${c.archive_members_extracted ?? 0}</span>
  </div>`;
  html += renderTraceExtractions(t.archive_extractions ?? []);
  html += '<div class="trace-timeline">';
  for (const e of t.timeline) {
    html += renderTraceEvent(e);
  }
  html += '</div>';
  result.innerHTML = html;
}

function renderTraceExtractions(list) {
  if (!list.length) return '';
  const rows = list.map((x) => `
    <tr>
      <td class="mono">#${x.seq}</td>
      <td class="mono">输入#${x.input_position} ${escapeHtml(x.archive)}!${escapeHtml(x.member)}</td>
      <td>${x.relation === 'index_hit_for_symbol'
        ? tag('该符号索引命中', 'ok')
        : tag('成员内定义该符号', 'weak')}</td>
      <td class="mono">${escapeHtml((x.matched_index_symbols ?? []).join(', ') || '—')}</td>
      <td class="undef-set">{${(x.undefined_before ?? []).join(', ')}}</td>
      <td class="undef-set">{${(x.undefined_after ?? []).join(', ')}}</td>
    </tr>`).join('');
  return `<div class="trace-sub">实际抽取成员（与冻结 extraction_order 交叉引用）</div>
  <div class="scroll"><table>
    <tr><th>序号</th><th>成员</th><th>关联</th><th>命中索引符号</th><th>抽取前未定义</th><th>抽取后未定义</th></tr>
    ${rows}
  </table></div>`;
}

function renderTraceEvent(e) {
  const cat = TYPE_LABEL[e.type] ?? e.type;
  let cls = 'ev-other';
  if (e.type.endsWith('_reference') || e.type === 'common_reference') cls = 'ev-ref';
  if (e.type.includes('definition') && !e.type.includes('duplicate')) cls = 'ev-def';
  if (e.type.startsWith('archive_index')) cls = 'ev-idx';
  if (e.is_terminal) cls = 'ev-reject';
  const badges = [];
  if (e.is_terminal) badges.push('<span class="mini-badge reject-b">拒绝终点 · 后续事件不存在</span>');
  if (e.is_final_binding) badges.push('<span class="mini-badge final-b">最终采用者</span>');
  if (e.is_superseded) badges.push('<span class="mini-badge sup-b">已被强定义覆盖（保留留档）</span>');
  const undef = (e.undefined_before !== null && e.undefined_before !== undefined)
    ? `<div class="ev-undef">未定义集合 <span class="undef-set">{${(e.undefined_before ?? []).join(', ')}}</span>
         → <span class="undef-set">{${(e.undefined_after ?? []).join(', ')}}</span></div>`
    : '';
  let detail = '';
  if (e.type === 'strong_definition' && e.effect === 'strong_overrides_weak') {
    detail = `<div class="ev-detail">被覆盖的弱定义：<span class="mono">${escapeHtml(e.detail.replaced_location)}</span>（事件 #${e.detail.replaces_event_no}）</div>`;
  }
  if (e.is_superseded && e.detail.adopted_by_location) {
    detail += `<div class="ev-detail">最终采用：<span class="mono">${escapeHtml(e.detail.adopted_by_location)}</span>（事件 #${e.detail.adopted_by_event_no}）</div>`;
  }
  if (e.type === 'duplicate_strong_definition') {
    detail = `<div class="ev-detail">首个强定义：<span class="mono">${escapeHtml(e.detail.first_definition)}</span><br/>
      冲突强定义：<span class="mono">${escapeHtml(e.detail.conflicting_definition)}</span></div>`;
  }
  if (e.type === 'final_undefined_rejection') {
    detail = `<div class="ev-detail">首次引用：<span class="mono">${escapeHtml(e.detail.first_reference)}</span><br/>
      最终未定义集合：<span class="undef-set">{${(e.detail.undefined ?? []).join(', ')}}</span></div>`;
  }
  if (e.extraction_seq) {
    detail += `<div class="ev-detail">触发成员抽取序号：#${e.extraction_seq}</div>`;
  }
  return `
  <div class="trace-event ${cls}${e.is_terminal ? ' terminal' : ''}">
    <div class="ev-top">
      <span class="ev-no mono">#${e.event_no}</span>
      ${tag(cat, '')}
      <span class="ev-context mono">${escapeHtml(
        e.type === 'final_undefined_rejection'
          ? '命令行处理完毕 · 裁决终结'
          : [e.input_position ? `输入#${e.input_position} ${e.input_name ?? ''}` : '',
             e.member ? `!${e.member}` : ''].join('')
      )}</span>
      ${badges.join('')}
    </div>
    <div class="ev-loc mono">${escapeHtml(e.location)}</div>
    <div class="ev-text">${escapeHtml(e.effect_text)}</div>
    ${undef}${detail}
  </div>`;
}

async function fillTraceDemo() {
  clearRequestError();
  setBusy(true, 'GET /api/demo/trace …');
  try {
    const res = await fetch('/api/demo/trace');
    const demo = await res.json();
    auditIdEl.value = demo.audit_id;
    rowsEl.innerHTML = '';
    demo.inputs.forEach((i) => addRow({ name: i.name, group: i.group ?? '', data: i.data_b64 }));
    verdictEl.innerHTML = `<div class="empty">已填充${demo.inputs.length}个真实合成输入（${escapeHtml(demo.explanation)}）。点击「提交审计」，再在结论下方用符号面板追查 need / pull / backsym / missing。</div>`;
  } catch (e) {
    showRequestError(`示例加载失败：${e.message}`);
  } finally {
    setBusy(false);
  }
}

// --------------------------------------------------------------------------- //
document.getElementById('submitBtn').addEventListener('click', submitAudit);
document.getElementById('reopenBtn').addEventListener('click', reopenAudit);
document.getElementById('addRow').addEventListener('click', () => addRow());
document.getElementById('addDemo').addEventListener('click', fillDemo);
document.getElementById('addTraceDemo').addEventListener('click', fillTraceDemo);

addRow();
verdictEl.innerHTML = '<div class="empty">填写标识与输入，或点击「填充循环依赖示例」</div>';
