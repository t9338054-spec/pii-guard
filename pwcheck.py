#!/usr/bin/env python3
"""pwcheck: パスワード診断ツール(強度判定 + 漏洩済みか確認)

使い方:
  python pwcheck.py            # パスワードを非表示で入力
  python pwcheck.py --offline  # 漏洩確認(外部通信)をしない

漏洩確認は Have I Been Pwned の Pwned Passwords API(k-匿名性方式)を使う。
SHA-1 ハッシュの先頭5文字だけを送信し、パスワード本体や完全なハッシュは送らない。
"""
import argparse
import getpass
import hashlib
import math
import re
import sys
import urllib.request

COMMON = {"password", "passw0rd", "123456", "12345678", "123456789", "qwerty", "abc123", "letmein",
          "admin", "welcome", "iloveyou", "monkey", "dragon", "login", "princess", "sunshine",
          "11111111", "00000000", "password1", "qwertyuiop", "1q2w3e4r", "asdfghjkl"}
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm"]


def entropy_bits(pw: str) -> float:
    pool = 0
    pool += 26 if re.search(r"[a-z]", pw) else 0
    pool += 26 if re.search(r"[A-Z]", pw) else 0
    pool += 10 if re.search(r"\d", pw) else 0
    pool += 33 if re.search(r"[^A-Za-z0-9]", pw) else 0
    return len(pw) * math.log2(pool) if pool else 0.0


def weaknesses(pw: str):
    w = []
    low = pw.lower()
    if len(pw) < 12:
        w.append("12文字未満です(長さが最も重要です)")
    if low in COMMON or low.rstrip("0123456789!") in COMMON:
        w.append("よく使われるパスワードです")
    if re.fullmatch(r"(.)\1+", pw):
        w.append("同じ文字の繰り返しです")
    elif re.search(r"(.)\1{3,}", pw):
        w.append("同じ文字が4回以上連続しています")
    for seq in SEQUENCES:
        for i in range(len(seq) - 3):
            if seq[i:i + 4] in low or seq[i:i + 4][::-1] in low:
                w.append("連続した文字列(abcd, 1234, qwer 等)を含みます")
                break
        else:
            continue
        break
    if re.fullmatch(r"[a-zA-Z]+", pw) or re.fullmatch(r"\d+", pw):
        w.append("文字種が1種類だけです")
    return w


def rate(pw: str):
    bits = entropy_bits(pw)
    w = weaknesses(pw)
    if any("よく使われる" in x or "繰り返し" in x for x in w):
        bits = min(bits, 20)
    elif w:
        bits = min(bits, 50)
    if bits < 28:
        return "非常に弱い", bits, w
    if bits < 40:
        return "弱い", bits, w
    if bits < 60:
        return "普通", bits, w
    if bits < 80:
        return "強い", bits, w
    return "非常に強い", bits, w


def pwned_count(pw: str, timeout: float = 10.0) -> int:
    """漏洩に含まれていた回数。0なら未確認。通信失敗時は例外。"""
    sha = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha[:5], sha[5:]
    req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{prefix}",
                                 headers={"User-Agent": "pwcheck", "Add-Padding": "true"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        for line in r.read().decode().splitlines():
            h, _, c = line.partition(":")
            if h == suffix:
                return int(c)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="漏洩確認の外部通信をしない")
    args = ap.parse_args()
    pw = getpass.getpass("診断するパスワード: ")
    if not pw:
        return 2
    label, bits, w = rate(pw)
    print(f"強度: {label} (推定 {bits:.0f} ビット)")
    for x in w:
        print(f"  - {x}")
    rc = 1 if label in ("非常に弱い", "弱い") else 0
    if not args.offline:
        try:
            n = pwned_count(pw)
            if n:
                print(f"漏洩: 既知の漏洩データに {n:,} 回出現しています。使用しないでください")
                rc = 1
            else:
                print("漏洩: 既知の漏洩データには見つかりませんでした")
        except OSError as e:
            print(f"漏洩確認に失敗しました(通信エラー): {e}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
