#!/usr/bin/env python3
"""pii_guard: 個人情報の検出・マスキング・ファイル暗号化ツール

使い方:
  python pii_guard.py scan   <ファイル/フォルダ>            個人情報・秘密情報を検出
  python pii_guard.py mask   <入力> [-o 出力]              検出箇所をマスクして出力
  python pii_guard.py scan --staged                        gitのステージ内容を検査 (検出で終了コード1)
  python pii_guard.py encrypt <ファイル/フォルダ> [--delete-original]
  python pii_guard.py decrypt <ファイル.enc/フォルダ> [--delete-encrypted]
  python pii_guard.py hook install|uninstall               git pre-commit フック設定

依存: pip install cryptography
"""
import argparse
import base64
import getpass
import os
import re
import sys
from pathlib import Path

# ---------- 検出ルール ----------

def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _my_check(n):
    # n は上位桁から並んだ12桁。末尾が検査用数字
    s = 0
    for p in range(1, 12):  # p: 下位から数えた位置(検査用数字を除く)
        q = p + 1 if p <= 6 else p - 5
        s += n[11 - p] * q
    r = s % 11
    return (0 if r <= 1 else 11 - r) == n[11]


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


PREF = ("(?:北海道|東京都|(?:京都|大阪)府|"
        "(?:青森|岩手|宮城|秋田|山形|福島|茨城|栃木|群馬|埼玉|千葉|神奈川|新潟|富山|石川|福井|山梨|長野|岐阜|静岡|愛知|"
        "三重|滋賀|兵庫|奈良|和歌山|鳥取|島根|岡山|広島|山口|徳島|香川|愛媛|高知|福岡|佐賀|長崎|熊本|大分|宮崎|鹿児島|沖縄)県)")

RULES = [
    # (名前, 正規表現, 追加検証)
    ("メールアドレス", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), None),
    ("電話番号", re.compile(r"(?<!\d)0\d{1,4}[-ー ]\d{1,4}[-ー ]\d{3,4}(?!\d)|(?<!\d)0[789]0\d{8}(?!\d)"), None),
    ("クレジットカード", re.compile(r"(?<!\d)(?:\d[ -]?){13,16}(?!\d)"), lambda m: luhn_ok(_digits(m)) and 13 <= len(_digits(m)) <= 16),
    ("マイナンバー", re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)"), lambda m: _my_check([int(c) for c in _digits(m)])),
    ("郵便番号", re.compile(r"(?<![\d-])\d{3}-\d{4}(?![\d-])"), None),
    ("IPアドレス", re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)"), None),
    ("AWSキー", re.compile(r"AKIA[0-9A-Z]{16}"), None),
    ("秘密情報(キー/トークン)", re.compile(r"(?i)(?:api[_-]?key|secret|token|passw(?:or)?d|パスワード)\s*[:=：]\s*['\"]?[^\s'\"]{6,}"), None),
    ("秘密鍵", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), None),
    ("住所", re.compile(PREF + r"[^\s,、。「」]{2,30}?\d{1,4}(?:[-ー丁目番地号]\d{0,4}){0,3}[^\s,、。]{0,12}"), None),
    # 氏名: 「氏名:」等のラベルの直後、または「様」「さん」「殿」の直前(ヒューリスティック)
    ("氏名", re.compile(r"(?:氏名|名前|お名前|契約者|代表者|担当者)\s*[:：]\s*[一-龥ぁ-んァ-ヶ]{1,5}[ 　]?[一-龥ぁ-んァ-ヶ]{1,5}"
                         r"|(?<![一-龥ぁ-んァ-ヶ])[一-龥]{1,4}[ 　]?[一-龥]{1,3}(?=様|殿|さん(?![ぁ-ん]))"), None),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
MAX_SIZE = 5 * 1024 * 1024


def find_pii(text: str):
    """(開始, 終了, 種別) のリスト(重複除去済み)"""
    hits = []
    for name, rx, check in RULES:
        for m in rx.finditer(text):
            if check is None or check(m.group()):
                hits.append((m.start(), m.end(), name))
    hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))  # 同位置なら長い一致を優先
    result, last_end = [], -1
    for s, e, n in hits:
        if s >= last_end:
            result.append((s, e, n))
            last_end = e
    return result


def mask_value(value: str, kind: str) -> str:
    if kind == "メールアドレス":
        local, _, domain = value.partition("@")
        return local[:1] + "***@" + domain
    if kind in ("クレジットカード", "マイナンバー", "電話番号"):
        d = _digits(value)
        return "*" * (len(d) - 4) + d[-4:]
    return "[" + kind + ":MASKED]"


def mask_text(text: str) -> str:
    out, pos = [], 0
    for s, e, kind in find_pii(text):
        out.append(text[pos:s])
        out.append(mask_value(text[s:e], kind))
        pos = e
    out.append(text[pos:])
    return "".join(out)


def iter_files(target: Path):
    if target.is_file():
        yield target
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            p = Path(root) / f
            if p.suffix == ".enc":
                continue
            yield p


def read_text(path: Path):
    try:
        if path.stat().st_size > MAX_SIZE:
            return None
        data = path.read_bytes()
        if b"\0" in data[:2048]:
            return None
        for enc in ("utf-8", "cp932"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
    except OSError:
        pass
    return None


# ---------- コマンド ----------

import subprocess

HOOK_MARK = "# pii_guard hook"


def staged_files():
    """git のステージ内容 (パス, テキスト) を返す。作業ツリーではなくindexの内容を検査する"""
    names = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
                           capture_output=True).stdout.split(b"\0")
    for n in filter(None, names):
        path = n.decode("utf-8", "replace")
        blob = subprocess.run(["git", "show", ":" + path], capture_output=True).stdout
        if b"\0" in blob[:2048] or len(blob) > MAX_SIZE:
            continue
        for enc in ("utf-8", "cp932"):
            try:
                yield path, blob.decode(enc)
                break
            except UnicodeDecodeError:
                continue


def cmd_scan(args) -> int:
    total = 0
    if args.staged:
        sources = staged_files()
    else:
        sources = ((str(p), read_text(p)) for p in iter_files(Path(args.target)))
    for name, text in sources:
        if text is None:
            continue
        for s, e, kind in find_pii(text):
            line = text.count("\n", 0, s) + 1
            print(f"{name}:{line}: {kind}: {mask_value(text[s:e], kind)}")  # 生の値は表示しない
            total += 1
    print(f"\n検出数: {total}")
    if total and args.staged:
        print("コミットを中止しました。内容を修正するか、意図的な場合は git commit --no-verify を使ってください。")
    return 1 if total else 0


def cmd_hook(args) -> int:
    root = subprocess.run(["git", "rev-parse", "--git-path", "hooks"], capture_output=True, text=True)
    if root.returncode:
        sys.exit("git リポジトリ内で実行してください")
    hook = Path(root.stdout.strip()) / "pre-commit"
    if args.action == "uninstall":
        if hook.exists() and HOOK_MARK in hook.read_text(encoding="utf-8", errors="ignore"):
            hook.unlink()
            print("フックを削除しました")
        return 0
    if hook.exists() and HOOK_MARK not in hook.read_text(encoding="utf-8", errors="ignore"):
        sys.exit(f"既存の pre-commit フックがあるため上書きしません: {hook}")
    script = Path(__file__).resolve().as_posix()
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(f'#!/bin/sh\n{HOOK_MARK}\nexec python "{script}" scan --staged\n', encoding="utf-8")
    hook.chmod(0o755)
    print(f"pre-commit フックを設定しました: {hook}")
    return 0


def cmd_mask(args) -> int:
    src = Path(args.target)
    if src.is_dir():
        print("mask はファイル単位で指定してください", file=sys.stderr)
        return 2
    text = read_text(src)
    if text is None:
        print("テキストとして読めません", file=sys.stderr)
        return 2
    out = Path(args.output) if args.output else src.with_name(src.stem + ".masked" + src.suffix)
    out.write_text(mask_text(text), encoding="utf-8")
    print(f"マスク済みファイル: {out}")
    return 0


def _kdf(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def get_password(confirm: bool) -> str:
    pw = os.environ.get("PII_GUARD_PASSWORD") or getpass.getpass("パスワード: ")
    if confirm and not os.environ.get("PII_GUARD_PASSWORD"):
        if pw != getpass.getpass("パスワード(確認): "):
            sys.exit("パスワードが一致しません")
    if confirm and len(pw) < 8:
        sys.exit("パスワードは8文字以上にしてください")
    return pw


def encrypt_file(src: Path, pw: str, delete_original: bool = False) -> Path:
    from cryptography.fernet import Fernet
    salt = os.urandom(16)
    token = Fernet(_kdf(pw, salt)).encrypt(src.read_bytes())
    out = src.with_name(src.name + ".enc")
    out.write_bytes(b"PIIG1" + salt + token)
    if delete_original:
        src.unlink()
    return out


def decrypt_file(src: Path, pw: str, delete_encrypted: bool = False) -> Path:
    from cryptography.fernet import Fernet, InvalidToken
    blob = src.read_bytes()
    if not blob.startswith(b"PIIG1"):
        raise ValueError("pii_guard の暗号化ファイルではありません")
    salt, token = blob[5:21], blob[21:]
    try:
        data = Fernet(_kdf(pw, salt)).decrypt(token)
    except InvalidToken:
        raise ValueError("復号失敗: パスワードが違うか、ファイルが改ざんされています")
    out = src.with_suffix("") if src.suffix == ".enc" else src.with_name(src.name + ".dec")
    if out.exists():
        out = out.with_name(out.stem + ".decrypted" + out.suffix)
    out.write_bytes(data)
    if delete_encrypted:
        src.unlink()
    return out


def cmd_encrypt(args) -> int:
    target = Path(args.target)
    pw = get_password(confirm=True)
    files = [p for p in iter_files(target) if p.suffix != ".enc"] if target.is_dir() else [target]
    for p in files:
        out = encrypt_file(p, pw, args.delete_original)
        print(f"暗号化: {p} -> {out.name}")
    if not args.delete_original:
        print("元ファイルは残っています。不要なら --delete-original を付けるか、安全に削除してください")
    return 0


def cmd_decrypt(args) -> int:
    target = Path(args.target)
    pw = get_password(confirm=False)
    files = list(target.rglob("*.enc")) if target.is_dir() else [target]
    rc = 0
    for p in files:
        try:
            print(f"復号: {p} -> {decrypt_file(p, pw, args.delete_encrypted).name}")
        except ValueError as e:
            print(f"{p}: {e}", file=sys.stderr)
            rc = 1
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="個人情報の検出・マスク・暗号化")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="検出 (--staged でgitステージ内容)")
    sp.add_argument("target", nargs="?", default=".")
    sp.add_argument("--staged", action="store_true")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("mask")
    sp.add_argument("target")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_mask)

    sp = sub.add_parser("encrypt", help="ファイル/フォルダを暗号化")
    sp.add_argument("target")
    sp.add_argument("--delete-original", action="store_true")
    sp.set_defaults(func=cmd_encrypt)

    sp = sub.add_parser("decrypt", help="ファイル/フォルダを復号")
    sp.add_argument("target")
    sp.add_argument("--delete-encrypted", action="store_true")
    sp.set_defaults(func=cmd_decrypt)

    sp = sub.add_parser("hook", help="git pre-commit フックの設定/解除")
    sp.add_argument("action", choices=["install", "uninstall"])
    sp.set_defaults(func=cmd_hook)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
