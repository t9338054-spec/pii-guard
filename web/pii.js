'use strict';
// 個人情報・秘密情報の検出とマスク。
// pii-guard（pii_guard.py / Detector.swift）と同じルールを JavaScript に移植したもの。
// 追加: 全角の英数字・記号（０９０－１２３４ など）も半角と同じように検出する。
(function (root) {
  const PREF =
    '(?:北海道|東京都|(?:京都|大阪)府|' +
    '(?:青森|岩手|宮城|秋田|山形|福島|茨城|栃木|群馬|埼玉|千葉|神奈川|新潟|富山|石川|福井|山梨|長野|岐阜|静岡|愛知|' +
    '三重|滋賀|兵庫|奈良|和歌山|鳥取|島根|岡山|広島|山口|徳島|香川|愛媛|高知|福岡|佐賀|長崎|熊本|大分|宮崎|鹿児島|沖縄)県)';

  const digits = (s) => s.replace(/\D/g, '');

  function luhnOK(d) {
    let total = 0;
    let alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let v = Number(d[i]);
      if (alt) { v *= 2; if (v > 9) v -= 9; }
      total += v;
      alt = !alt;
    }
    return total % 10 === 0;
  }

  // マイナンバー（12桁）の検査用数字
  function myNumberOK(d) {
    if (d.length !== 12) return false;
    const n = [...d].map(Number);
    let s = 0;
    for (let p = 1; p <= 11; p++) s += n[11 - p] * (p <= 6 ? p + 1 : p - 5);
    const r = s % 11;
    return (r <= 1 ? 0 : 11 - r) === n[11];
  }

  const RULES = [
    ['メールアドレス', /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g],
    ['電話番号', /(?<!\d)0\d{1,4}[-ー ]\d{1,4}[-ー ]\d{3,4}(?!\d)|(?<!\d)0[789]0\d{8}(?!\d)/g],
    ['クレジットカード', /(?<!\d)(?:\d[ -]?){13,16}(?!\d)/g,
      (v) => { const d = digits(v); return d.length >= 13 && d.length <= 16 && luhnOK(d); }],
    ['マイナンバー', /(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)/g, (v) => myNumberOK(digits(v))],
    ['郵便番号', /(?<![\d-])\d{3}-\d{4}(?![\d-])/g],
    ['IPアドレス', /(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)/g],
    ['AWSキー', /AKIA[0-9A-Z]{16}/g],
    ['秘密情報(キー/トークン)', /(?:api[_-]?key|secret|token|passw(?:or)?d|パスワード)\s*[:=：]\s*['"]?[^\s'"]{6,}/gi],
    ['秘密鍵', /-----BEGIN [A-Z ]*PRIVATE KEY-----/g],
    ['住所', new RegExp(PREF + '[^\\s,、。「」]{2,30}?\\d{1,4}(?:[-ー丁目番地号]\\d{0,4}){0,3}[^\\s,、。]{0,12}', 'g')],
    ['氏名', new RegExp(
      '(?:氏名|名前|お名前|契約者|代表者|担当者)\\s*[:：]\\s*[一-龥ぁ-んァ-ヶ]{1,5}[ 　]?[一-龥ぁ-んァ-ヶ]{1,5}' +
      '|(?<![一-龥ぁ-んァ-ヶ])[一-龥]{1,4}[ 　]?[一-龥]{1,3}(?=様|殿|さん(?![ぁ-ん]))', 'g')],
  ];

  // 全角の英数字・記号（！〜～）を半角に。1文字→1文字なので位置はずれない
  const toHalfWidth = (s) =>
    s.replace(/[！-～]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xFEE0));

  /** 重複を除いた検出結果 [{start, end, kind}]（位置順。同じ開始位置なら長い一致を優先） */
  function find(text) {
    const norm = toHalfWidth(text);
    const hits = [];
    for (const [kind, rx, check] of RULES) {
      rx.lastIndex = 0;
      for (const m of norm.matchAll(rx)) {
        if (check && !check(m[0])) continue;
        hits.push({ start: m.index, end: m.index + m[0].length, kind });
      }
    }
    hits.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
    const result = [];
    let lastEnd = -1;
    for (const h of hits) {
      if (h.start >= lastEnd) { result.push(h); lastEnd = h.end; }
    }
    return result;
  }

  function maskValue(value, kind) {
    const v = toHalfWidth(value);
    if (kind === 'メールアドレス') {
      const at = v.indexOf('@');
      return v.slice(0, 1) + '***@' + v.slice(at + 1);
    }
    if (kind === 'クレジットカード' || kind === 'マイナンバー' || kind === '電話番号') {
      const d = digits(v);
      return '*'.repeat(Math.max(0, d.length - 4)) + d.slice(-4);
    }
    return '[' + kind + ':MASKED]';
  }

  function mask(text) {
    let out = '';
    let pos = 0;
    for (const m of find(text)) {
      out += text.slice(pos, m.start) + maskValue(text.slice(m.start, m.end), m.kind);
      pos = m.end;
    }
    return out + text.slice(pos);
  }

  const api = { find, mask, maskValue, luhnOK, myNumberOK };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.PII = api;
})(this);
