// pii-guard のテスト（tests/test_pii_guard.py / PIIGuardCoreTests.swift）と同じ内容
// 実行: node --test tests/pii.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const PII = require('../web/pii.js');

const kinds = (t) => PII.find(t).map((m) => m.kind);

test('メールアドレスとマスク', () => {
  assert.deepEqual(kinds('連絡: taro@example.com'), ['メールアドレス']);
  assert.equal(PII.mask('taro@example.com'), 't***@example.com');
});

test('電話番号を郵便番号と取り違えない', () => {
  assert.deepEqual(kinds('tel 090-1234-5678'), ['電話番号']);
  assert.equal(PII.mask('tel 090-1234-5678'), 'tel *******5678');
});

test('クレジットカード（Luhn）', () => {
  assert.deepEqual(kinds('card 4111 1111 1111 1111'), ['クレジットカード']);
  assert.ok(!kinds('card 4111 1111 1111 1112').includes('クレジットカード'));
});

test('マイナンバーの検査用数字', () => {
  const base = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1];
  let s = 0;
  for (let p = 1; p <= 11; p++) s += base[11 - p] * (p <= 6 ? p + 1 : p - 5);
  const check = s % 11 <= 1 ? 0 : 11 - (s % 11);
  assert.ok(PII.myNumberOK(base.join('') + check));
  assert.ok(!PII.myNumberOK(base.join('') + ((check + 1) % 10)));
  assert.deepEqual(kinds('番号 ' + base.join('') + check), ['マイナンバー']);
});

test('郵便番号・住所・氏名', () => {
  assert.ok(kinds('〒100-0001').includes('郵便番号'));
  assert.ok(kinds('東京都千代田区1-1-1').includes('住所'));
  assert.ok(kinds('氏名: 山田 太郎').includes('氏名'));
  assert.ok(kinds('山田太郎様へ').includes('氏名'));
});

test('秘密情報', () => {
  assert.ok(kinds('password: Secret12345').includes('秘密情報(キー/トークン)'));
  assert.ok(kinds('PASSWORD=Secret12345').includes('秘密情報(キー/トークン)'));
  assert.ok(kinds('AKIAABCDEFGHIJKLMNOP').includes('AWSキー'));
  assert.ok(kinds('-----BEGIN RSA PRIVATE KEY-----').includes('秘密鍵'));
});

test('普通の文章では検出しない', () => {
  assert.deepEqual(kinds('今日はいい天気です。会議は15時からです。'), []);
});

test('全角の数字・記号も検出する（追加機能）', () => {
  assert.deepEqual(kinds('電話 ０９０－１２３４－５６７８'), ['電話番号']);
  assert.equal(PII.mask('電話 ０９０－１２３４－５６７８'), '電話 *******5678');
  assert.deepEqual(kinds('ｔａｒｏ＠ｅｘａｍｐｌｅ．ｃｏｍ'), ['メールアドレス']);
});
