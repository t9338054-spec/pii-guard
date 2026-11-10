#!/usr/bin/env python3
"""login_monitor: ログインログから不審な挙動(乗っ取りの兆候)を検出する

入力形式(CSV、ヘッダ行は任意):
  2026-11-10T09:00:01,alice,203.0.113.5,fail
  時刻(ISO 8601), ユーザー, IPアドレス, 結果(success|fail)

使い方:
  python login_monitor.py login.csv [--window 600] [--fail-threshold 5] [--user-threshold 5] [--spray-threshold 5]

検出内容:
  BRUTE_FORCE   同一IPが短時間に多数失敗(総当たり)
  TARGETED      同一ユーザーが短時間に多数失敗(標的型・複数IPからの攻撃を含む)
  SPRAYING      同一IPが多数の異なるユーザーで失敗(クレデンシャルスタッフィング/パスワードスプレー)
  SUSPECT_LOGIN 失敗が続いた直後の成功(突破された可能性) ★最優先で対応
  NEW_IP        過去に見たことのないIPからの成功ログイン(参考)

検出ありで終了コード1。
"""
import argparse
import csv
import re
import sys
from collections import defaultdict, deque
from datetime import datetime


NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3})')


def parse_csv(lines):
    events = []
    for n, row in enumerate(csv.reader(lines), 1):
        if len(row) < 4 or not row[0].strip():
            continue
        try:
            ts = datetime.fromisoformat(row[0].strip())
        except ValueError:
            if n == 1:
                continue  # ヘッダ行
            print(f"警告: {n}行目の時刻を解釈できません: {row[0]!r}", file=sys.stderr)
            continue
        result = row[3].strip().lower()
        events.append((ts, row[1].strip(), row[2].strip(), result in ("success", "ok", "1", "true")))
    return events


def parse_nginx(lines, login_path="/login"):
    """nginx/Apache combined 形式。login_path への POST のうち 401/403 を失敗、200/301/302/303 を成功とみなす。
    ユーザー名はアクセスログに通常出ないため Basic認証のユーザー、無ければ '-' になる(IP単位の検出が中心)。"""
    events = []
    for n, line in enumerate(lines, 1):
        m = NGINX_RE.match(line)
        if not m or m["method"] != "POST" or not m["path"].split("?")[0].startswith(login_path):
            continue
        try:
            ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            print(f"警告: {n}行目の時刻を解釈できません", file=sys.stderr)
            continue
        status = int(m["status"])
        if status in (401, 403):
            ok = False
        elif status in (200, 301, 302, 303):
            ok = True
        else:
            continue
        events.append((ts, m["user"], m["ip"], ok))
    return events


def parse_windows(lines):
    """Windows セキュリティログ(4624=成功, 4625=失敗)をCSV出力したもの。必要な列:
    TimeCreated, Id, TargetUserName, IpAddress (README の PowerShell 例で作成できる)。"""
    events = []
    for row in csv.DictReader(lines):
        try:
            ts = datetime.fromisoformat(row["TimeCreated"].strip().replace("Z", "+00:00"))
            eid = int(row["Id"])
        except (KeyError, ValueError):
            continue
        if eid not in (4624, 4625):
            continue
        events.append((ts, row.get("TargetUserName", "").strip(), (row.get("IpAddress") or "-").strip(), eid == 4624))
    return events


def detect_format(first_line):
    if "TimeCreated" in first_line:
        return "windows"
    if NGINX_RE.match(first_line):
        return "nginx"
    return "csv"


def parse(path, fmt="auto", login_path="/login"):
    with open(path, newline="", encoding="utf-8-sig") as f:
        lines = f.read().splitlines()
    if fmt == "auto":
        fmt = detect_format(lines[0] if lines else "")
    events = {"csv": parse_csv, "windows": parse_windows,
              "nginx": lambda ls: parse_nginx(ls, login_path)}[fmt](lines)
    events.sort(key=lambda e: e[0])
    return events


def analyze(events, window, fail_th, user_th, spray_th):
    findings = []
    by_ip, by_user = defaultdict(deque), defaultdict(deque)
    recent_fail_user = defaultdict(deque)
    seen_ips = defaultdict(set)
    flagged = set()

    def add(kind, key, ts, msg):
        if (kind, key) not in flagged:  # 同じ対象の重複通知を抑制
            flagged.add((kind, key))
            findings.append((ts, kind, msg))

    def trim(q, ts):
        while q and (ts - q[0][0]).total_seconds() > window:
            q.popleft()

    for ts, user, ip, ok in events:
        if not ok:
            by_ip[ip].append((ts, user))
            by_user[user].append((ts, ip))
            recent_fail_user[user].append(ts)
            trim(by_ip[ip], ts)
            trim(by_user[user], ts)
            if len(by_ip[ip]) >= fail_th:
                add("BRUTE_FORCE", ip, ts, f"IP {ip} が {window}秒以内に {len(by_ip[ip])} 回失敗")
            users = {u for _, u in by_ip[ip]}
            if len(users) >= spray_th:
                add("SPRAYING", ip, ts, f"IP {ip} が {window}秒以内に {len(users)} 人のユーザーで失敗")
            if len(by_user[user]) >= user_th:
                ips = {i for _, i in by_user[user]}
                add("TARGETED", user, ts, f"ユーザー {user} に {window}秒以内に {len(by_user[user])} 回失敗({len(ips)} IP)")
        else:
            q = recent_fail_user[user]
            while q and (ts - q[0]).total_seconds() > window:
                q.popleft()
            if len(q) >= 3:
                findings.append((ts, "SUSPECT_LOGIN",
                                 f"ユーザー {user} が直近 {len(q)} 回失敗後に {ip} からログイン成功 → 乗っ取りの可能性"))
                q.clear()
            if seen_ips[user] and ip not in seen_ips[user]:
                findings.append((ts, "NEW_IP", f"ユーザー {user} が初出のIP {ip} からログイン成功"))
            seen_ips[user].add(ip)
    findings.sort(key=lambda f: f[0])
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="ログイン監視")
    ap.add_argument("logfile")
    ap.add_argument("--window", type=int, default=600, help="集計ウィンドウ秒(既定600)")
    ap.add_argument("--fail-threshold", type=int, default=5, help="IPあたりの失敗回数(既定5)")
    ap.add_argument("--user-threshold", type=int, default=5, help="ユーザーあたりの失敗回数(既定5)")
    ap.add_argument("--spray-threshold", type=int, default=5, help="IPあたりの異なるユーザー数(既定5)")
    ap.add_argument("--format", choices=["auto", "csv", "nginx", "windows"], default="auto",
                    help="ログ形式(既定: 自動判定)")
    ap.add_argument("--login-path", default="/login", help="nginx形式でログインとみなすパス(既定 /login)")
    a = ap.parse_args()
    events = parse(a.logfile, a.format, a.login_path)
    findings = analyze(events, a.window, a.fail_threshold,
                       a.user_threshold, a.spray_threshold)
    for ts, kind, msg in findings:
        print(f"[{ts.isoformat()}] {kind:13} {msg}")
    print(f"\nイベント数: {len(events)} / 検出: {len(findings)}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
