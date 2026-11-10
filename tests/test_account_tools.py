import base64
from datetime import datetime

import login_monitor as lm
import pwcheck
import totp


# ---- totp ----
def test_totp_rfc6238_vector():
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp.hotp(totp._key(secret), 59 // 30, 8) == "94287082"


def test_totp_verify_window_and_replay():
    s = totp.new_secret()
    code = totp.totp(s, at=1000)
    step = totp.verify(s, code, at=1000)
    assert step == 1000 // 30
    assert totp.verify(s, code, at=1000, last_step=step) is None   # 再利用は拒否
    assert totp.verify(s, code, at=1000 + 30) is not None          # 1ステップのずれは許容
    assert totp.verify(s, code, at=1000 + 120) is None             # 大きなずれは拒否
    assert totp.verify(s, "abc123", at=1000) is None


def test_provisioning_uri():
    uri = totp.provisioning_uri("ABC", "a@b.c", "My App")
    assert uri.startswith("otpauth://totp/My%20App:a%40b.c?secret=ABC")


# ---- pwcheck ----
def test_pwcheck_ratings():
    assert pwcheck.rate("password123")[0] == "非常に弱い"
    assert pwcheck.rate("aaaaaaaaaaaaaaaa")[0] == "非常に弱い"
    assert pwcheck.rate("correct-horse-battery-staple-92")[0] == "非常に強い"
    assert any("連続" in w for w in pwcheck.weaknesses("abcd9Xk#Qz!7"))


# ---- login_monitor ----
def test_login_monitor_detects(tmp_path):
    rows = [f"2026-11-10T09:00:0{i},bob,198.51.100.9,fail" for i in range(1, 7)]
    rows.append("2026-11-10T09:00:09,bob,198.51.100.9,success")
    rows += [f"2026-11-10T09:05:00,{u},192.0.2.7,fail" for u in "abcde"]
    p = tmp_path / "l.csv"
    p.write_text("\n".join(rows))
    ev = lm.parse(str(p))
    kinds = {k for _, k, _ in lm.analyze(ev, 600, 5, 5, 5)}
    assert {"BRUTE_FORCE", "TARGETED", "SPRAYING", "SUSPECT_LOGIN"} <= kinds


def test_login_monitor_quiet_on_normal(tmp_path):
    p = tmp_path / "l.csv"
    p.write_text("2026-11-10T09:00:00,alice,203.0.113.5,success\n2026-11-10T09:00:30,alice,203.0.113.5,fail\n")
    assert lm.analyze(lm.parse(str(p)), 600, 5, 5, 5) == []


def test_login_monitor_nginx(tmp_path):
    line = '198.51.100.9 - - [10/Nov/2026:09:00:0{i} +0900] "POST /login HTTP/1.1" 401 12 "-" "curl"'
    lines = [line.format(i=i) for i in range(1, 6)]
    lines.append('198.51.100.1 - - [10/Nov/2026:09:00:10 +0900] "GET /index HTTP/1.1" 200 5 "-" "x"')
    p = tmp_path / "access.log"
    p.write_text("\n".join(lines))
    assert lm.detect_format(lines[0]) == "nginx"
    ev = lm.parse(str(p))
    assert len(ev) == 5 and not any(e[3] for e in ev)
    assert "BRUTE_FORCE" in {k for _, k, _ in lm.analyze(ev, 600, 5, 99, 99)}


def test_login_monitor_windows(tmp_path):
    rows = ["TimeCreated,Id,TargetUserName,IpAddress"]
    rows += [f"2026-11-10T09:00:0{i}Z,4625,admin,203.0.113.7" for i in range(1, 6)]
    rows.append("2026-11-10T09:00:09Z,4624,admin,203.0.113.7")
    rows.append("2026-11-10T09:00:10Z,4688,admin,-")  # 無関係なイベントは無視
    p = tmp_path / "win.csv"
    p.write_text("\n".join(rows))
    ev = lm.parse(str(p))
    assert len(ev) == 6 and ev[-1][3] is True
    assert "SUSPECT_LOGIN" in {k for _, k, _ in lm.analyze(ev, 600, 5, 5, 5)}
