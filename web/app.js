'use strict';

const $ = (id) => document.getElementById(id);

/* ---------- 共通 ---------- */
let toastTimer;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 1800);
}

async function copyText(text, msg) {
  try {
    await navigator.clipboard.writeText(text);
    toast(msg);
  } catch {
    toast('コピーできませんでした');
  }
}

// 偏りのない乱数（0 <= n < max）
function randInt(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % max;
}

/* ---------- タブ ---------- */
const TITLES = { gen: 'パスワード生成', pii: '個人情報チェック', vault: '暗号化メモ' };
document.querySelectorAll('.tabs button').forEach((btn) => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll('.tabs button').forEach((b) => b.classList.toggle('active', b === btn));
    Object.keys(TITLES).forEach((k) => { $('view-' + k).hidden = tab !== k; });
    $('title').textContent = TITLES[tab];
    if (tab === 'vault') showVaultEntry();
    window.scrollTo(0, 0);
  });
});

/* ---------- パスワード生成 ---------- */
const SETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
};
const AMBIGUOUS = /[0O1lI|]/g;

function generate() {
  const len = Number($('len').value);
  const noAmb = $('noamb').checked;
  const sets = Object.keys(SETS)
    .filter((k) => $(k).checked)
    .map((k) => (noAmb ? SETS[k].replace(AMBIGUOUS, '') : SETS[k]));

  if (sets.length === 0) {
    $('pw').textContent = '';
    $('entropy').textContent = '文字の種類を1つ以上選んでください';
    $('bar').style.width = '0';
    $('copy').disabled = true;
    return;
  }

  const pool = sets.join('');
  // 選んだ種類を最低1文字ずつ入れ、残りは全体から選ぶ
  const chars = sets.map((s) => s[randInt(s.length)]);
  while (chars.length < len) chars.push(pool[randInt(pool.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  const bits = Math.round(len * Math.log2(pool.length));
  let label, color;
  if (bits < 50) { label = '弱い'; color = 'var(--danger)'; }
  else if (bits < 80) { label = '普通'; color = '#f59e0b'; }
  else { label = '強い'; color = '#16a34a'; }

  $('pw').textContent = chars.join('');
  $('entropy').textContent = `強度: ${label}（約 ${bits} ビット）`;
  $('bar').style.width = Math.min(100, (bits / 128) * 100) + '%';
  $('bar').style.background = color;
  $('copy').disabled = false;
}

$('len').addEventListener('input', () => { $('lenval').textContent = $('len').value; generate(); });
['upper', 'lower', 'digits', 'symbols', 'noamb'].forEach((id) => $(id).addEventListener('change', generate));
$('regen').addEventListener('click', generate);
$('copy').addEventListener('click', () => copyText($('pw').textContent, 'コピーしました'));
generate();

/* ---------- 個人情報チェック ---------- */
let piiTimer;
function runPii() {
  const text = $('pii-in').value;
  if (!text.trim()) { $('pii-result').hidden = true; return; }

  const found = PII.find(text);
  $('pii-result').hidden = false;
  $('pii-out-card').hidden = found.length === 0;

  if (found.length === 0) {
    $('pii-summary').textContent = '✅ 個人情報は見つかりませんでした';
    $('pii-list').replaceChildren();
    return;
  }

  $('pii-summary').textContent = `⚠️ ${found.length}件 見つかりました`;
  // 一覧にも生の値は出さず、隠した形で表示する
  const ul = $('pii-list');
  ul.replaceChildren();
  found.forEach((m) => {
    const li = document.createElement('li');
    const k = document.createElement('span');
    k.className = 'kind';
    k.textContent = m.kind;
    const v = document.createElement('span');
    v.className = 'val';
    v.textContent = PII.maskValue(text.slice(m.start, m.end), m.kind);
    li.append(k, v);
    ul.append(li);
  });
  $('pii-out').textContent = PII.mask(text);
}
$('pii-in').addEventListener('input', () => { clearTimeout(piiTimer); piiTimer = setTimeout(runPii, 200); });
$('pii-clear').addEventListener('click', () => { $('pii-in').value = ''; runPii(); });
$('pii-copy').addEventListener('click', () => copyText($('pii-out').textContent, 'コピーしました'));

/* ---------- 暗号化メモ ---------- */
// 保存形式: localStorage に { v, iter, salt, iv, ct }（すべて暗号化済み）
// 鍵: マスターパスワード → PBKDF2-SHA256 → AES-GCM 256bit
const STORE_KEY = 'secure-notes-vault-v1';
const ITERATIONS = 600000;
const AUTO_LOCK_MS = 5 * 60 * 1000;   // 操作がなければ5分でロック
const BG_LOCK_MS = 30 * 1000;         // 30秒以上バックグラウンドならロック

const enc = new TextEncoder();
const dec = new TextDecoder();

const b64 = (bytes) => {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
};
const unb64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));

async function deriveKey(password, salt, iter) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

const vault = { key: null, salt: null, iter: ITERATIONS, notes: [], currentId: null };

function readStored() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function isValidStored(o) {
  return o && o.v === 1 && Number.isInteger(o.iter) && o.iter >= 100000 &&
    typeof o.salt === 'string' && typeof o.iv === 'string' && typeof o.ct === 'string';
}

async function writeVault() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = enc.encode(JSON.stringify({ notes: vault.notes }));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vault.key, data);
  localStorage.setItem(STORE_KEY, JSON.stringify({
    v: 1, iter: vault.iter, salt: b64(vault.salt), iv: b64(iv), ct: b64(ct),
  }));
}

// 保存は順番に実行して競合を防ぐ
let saveChain = Promise.resolve();
let saveTimer = null;
function saveNow() {
  clearTimeout(saveTimer);
  saveTimer = null;
  if (!vault.key) return saveChain;
  saveChain = saveChain.then(writeVault).then(
    () => { $('save-state').textContent = '保存しました（暗号化済み）'; },
    () => { $('save-state').textContent = '保存に失敗しました'; },
  );
  return saveChain;
}
function scheduleSave() {
  $('save-state').textContent = '編集中…';
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveNow, 600);
}
function flushSave() {
  return saveTimer ? saveNow() : saveChain;
}

const PANELS = ['setup', 'unlock', 'list', 'editor', 'import'];
function showPanel(name) {
  PANELS.forEach((p) => { $(p).hidden = p !== name; });
}

function showVaultEntry() {
  if (vault.key) {
    if (vault.currentId) showPanel('editor');
    else renderList();
  } else if (readStored()) {
    showPanel('unlock');
  } else {
    showPanel('setup');
  }
}

function fmtDate(ts) {
  return new Date(ts).toLocaleString('ja-JP', { year: 'numeric', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function renderList() {
  const ul = $('notes');
  ul.replaceChildren();
  [...vault.notes].sort((a, b) => b.updated - a.updated).forEach((n) => {
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.type = 'button';
    const t = document.createElement('span');
    t.className = 't';
    t.textContent = n.title || n.body.split('\n')[0] || '（無題）';
    const d = document.createElement('span');
    d.className = 'd';
    d.textContent = fmtDate(n.updated);
    btn.append(t, d);
    btn.addEventListener('click', () => openNote(n.id));
    li.append(btn);
    ul.append(li);
  });
  $('empty').hidden = vault.notes.length > 0;
  $('reset-confirm').hidden = true;
  showPanel('list');
}

function currentNote() {
  return vault.notes.find((n) => n.id === vault.currentId);
}

function openNote(id) {
  vault.currentId = id;
  const n = currentNote();
  $('note-title').value = n.title;
  $('note-body').value = n.body;
  $('save-state').textContent = '';
  $('del-confirm').hidden = true;
  showPanel('editor');
}

async function closeEditor() {
  const n = currentNote();
  vault.currentId = null;
  // 空のメモは残さない
  if (n && !n.title.trim() && !n.body.trim()) {
    vault.notes = vault.notes.filter((x) => x !== n);
    saveNow();
  }
  await flushSave();
  $('note-title').value = '';
  $('note-body').value = '';
}

async function lock() {
  if (!vault.key) return;
  await flushSave();
  vault.key = null;
  vault.salt = null;
  vault.notes = [];
  vault.currentId = null;
  $('note-title').value = '';
  $('note-body').value = '';
  $('notes').replaceChildren();
  $('unlock-pw').value = '';
  $('unlock-err').textContent = '';
  if (!$('view-vault').hidden) showPanel('unlock');
  if (updatePending) location.reload();
}
let updatePending = false;

function busy(form, on, label) {
  const btn = form.querySelector('button[type=submit]');
  if (on) { btn.dataset.label = btn.textContent; btn.textContent = label; }
  else if (btn.dataset.label) btn.textContent = btn.dataset.label;
  btn.disabled = on;
}

// 初回作成
$('setup').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('setup-pw').value;
  const err = $('setup-err');
  if (pw.length < 10) { err.textContent = '10文字以上にしてください'; return; }
  if (pw !== $('setup-pw2').value) { err.textContent = '2回の入力が一致しません'; return; }
  err.textContent = '';
  busy(e.target, true, '作成中…');
  try {
    vault.salt = crypto.getRandomValues(new Uint8Array(16));
    vault.iter = ITERATIONS;
    vault.key = await deriveKey(pw, vault.salt, vault.iter);
    vault.notes = [];
    await saveNow();
    navigator.storage?.persist?.();
    $('setup-pw').value = '';
    $('setup-pw2').value = '';
    resetIdle();
    renderList();
  } catch {
    err.textContent = '作成に失敗しました';
  } finally {
    busy(e.target, false);
  }
});

// ロック解除
$('unlock').addEventListener('submit', async (e) => {
  e.preventDefault();
  const stored = readStored();
  const err = $('unlock-err');
  if (!isValidStored(stored)) { err.textContent = '保存データが壊れています'; return; }
  busy(e.target, true, '確認中…');
  try {
    const salt = unb64(stored.salt);
    const key = await deriveKey($('unlock-pw').value, salt, stored.iter);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(stored.iv) }, key, unb64(stored.ct));
    const data = JSON.parse(dec.decode(plain));
    vault.key = key;
    vault.salt = salt;
    vault.iter = stored.iter;
    vault.notes = Array.isArray(data.notes) ? data.notes : [];
    $('unlock-pw').value = '';
    err.textContent = '';
    resetIdle();
    renderList();
  } catch {
    err.textContent = 'パスワードが違います';
    $('unlock-pw').select();
  } finally {
    busy(e.target, false);
  }
});

$('new-note').addEventListener('click', () => {
  const id = crypto.randomUUID ? crypto.randomUUID() : b64(crypto.getRandomValues(new Uint8Array(12)));
  vault.notes.push({ id, title: '', body: '', updated: Date.now() });
  openNote(id);
  $('note-title').focus();
});

function onEdit() {
  const n = currentNote();
  if (!n) return;
  n.title = $('note-title').value;
  n.body = $('note-body').value;
  n.updated = Date.now();
  scheduleSave();
}
$('note-title').addEventListener('input', onEdit);
$('note-body').addEventListener('input', onEdit);

$('back').addEventListener('click', async () => { await closeEditor(); renderList(); });
$('del-note').addEventListener('click', () => { $('del-confirm').hidden = false; });
$('del-cancel').addEventListener('click', () => { $('del-confirm').hidden = true; });
$('del-do').addEventListener('click', async () => {
  vault.notes = vault.notes.filter((n) => n.id !== vault.currentId);
  vault.currentId = null;
  clearTimeout(saveTimer);
  saveTimer = null;
  await saveNow();
  toast('削除しました');
  renderList();
});

$('lock').addEventListener('click', lock);

// バックアップ（暗号化済みの文字列をそのままコピー）
$('export').addEventListener('click', () => {
  const raw = localStorage.getItem(STORE_KEY);
  if (raw) copyText(raw, 'バックアップをコピーしました');
});

$('reset-start').addEventListener('click', () => { $('reset-confirm').hidden = false; });
$('reset-cancel').addEventListener('click', () => { $('reset-confirm').hidden = true; });
$('reset-do').addEventListener('click', async () => {
  await flushSave();
  localStorage.removeItem(STORE_KEY);
  vault.key = null;
  vault.salt = null;
  vault.notes = [];
  vault.currentId = null;
  toast('すべて削除しました');
  showPanel('setup');
});

// 復元
$('show-import').addEventListener('click', () => {
  $('import-text').value = '';
  $('import-err').textContent = '';
  showPanel('import');
});
$('import-cancel').addEventListener('click', () => showPanel('setup'));
$('import').addEventListener('submit', (e) => {
  e.preventDefault();
  let o;
  try { o = JSON.parse($('import-text').value.trim()); } catch { o = null; }
  if (!isValidStored(o)) { $('import-err').textContent = 'バックアップの形式が正しくありません'; return; }
  localStorage.setItem(STORE_KEY, JSON.stringify({ v: 1, iter: o.iter, salt: o.salt, iv: o.iv, ct: o.ct }));
  $('import-text').value = '';
  toast('復元しました');
  showPanel('unlock');
});

// 自動ロック
let idleTimer;
function resetIdle() {
  clearTimeout(idleTimer);
  if (vault.key) idleTimer = setTimeout(lock, AUTO_LOCK_MS);
}
['pointerdown', 'keydown', 'input'].forEach((ev) => document.addEventListener(ev, resetIdle, { passive: true }));

let hiddenAt = 0;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    hiddenAt = Date.now();
    flushSave();
  } else if (vault.key && Date.now() - hiddenAt > BG_LOCK_MS) {
    lock();
  }
});
window.addEventListener('pagehide', () => { flushSave(); });

/* ---------- オフライン対応 ---------- */
if ('serviceWorker' in navigator && location.protocol === 'https:') {
  navigator.serviceWorker.register('sw.js').then((reg) => {
    // ホーム画面のアプリは閉じずに再開されることが多いので、戻ってきたときにも更新を確認する
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) reg.update().catch(() => {});
    });
  });

  // 新しい版が有効になったら読み込み直す（メモを開いている間は邪魔しない）
  const hadController = !!navigator.serviceWorker.controller;
  let reloading = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (!hadController || reloading) return;
    if (vault.key) {
      updatePending = true;
      toast('新しい版があります。ロックすると反映されます');
      return;
    }
    reloading = true;
    location.reload();
  });
}
