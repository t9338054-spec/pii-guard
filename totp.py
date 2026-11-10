#!/usr/bin/env python3
"""totp: 認証アプリ方式(RFC 6238 TOTP)の多要素認証を実装した標準ライブラリのみのモジュール

CLI:
  python totp.py new <アカウント名> [--issuer 名前]   新しい秘密鍵と登録用URIを発行
  python totp.py code <秘密鍵>                         現在のコードを表示
  python totp.py verify <秘密鍵> <コード>              検証(終了コード 0=OK)

Webアプリへの組み込み例:
  secret = new_secret()                        # ユーザー登録時に生成してDBへ(暗号化して)保存
  uri = provisioning_uri(secret, "alice", "MyApp")   # QRコード化して認証アプリに登録させる
  step = verify(secret, user_input, last_step=db.last_totp_step)
  if step is not None:                         # 成功
      db.last_totp_step = step                 # リプレイ攻撃防止: 同じコードの再利用を拒否
"""
import base64
import hashlib
import hmac
import secrets
import struct
import sys
import time
from urllib.parse import quote

PERIOD = 30
DIGITS = 6


def new_secret(nbytes: int = 20) -> str:
    return base64.b32encode(secrets.token_bytes(nbytes)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS, algo=hashlib.sha1) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), algo).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(secret: str, at: float = None, period: int = PERIOD, digits: int = DIGITS) -> str:
    t = time.time() if at is None else at
    return hotp(_key(secret), int(t // period), digits)


def verify(secret: str, code: str, window: int = 1, last_step: int = None,
           at: float = None, period: int = PERIOD, digits: int = DIGITS):
    """成功したら使用したタイムステップ(int)を返し、失敗なら None。
    window: 前後何ステップの時計ずれを許容するか。last_step 以前のステップは拒否(再利用防止)。"""
    code = code.strip().replace(" ", "")
    if len(code) != digits or not code.isdigit():
        return None
    now_step = int((time.time() if at is None else at) // period)
    key = _key(secret)
    matched = None
    for step in range(now_step - window, now_step + window + 1):
        # 全候補を定時間で比較し、タイミング攻撃を避ける
        if hmac.compare_digest(hotp(key, step, digits), code) and (last_step is None or step > last_step):
            matched = step
    return matched


def provisioning_uri(secret: str, account: str, issuer: str = "MyApp") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "new":
        issuer = sys.argv[sys.argv.index("--issuer") + 1] if "--issuer" in sys.argv else "MyApp"
        s = new_secret()
        print(f"秘密鍵: {s}\n登録用URI(QRコード化して認証アプリに読み込ませる):\n{provisioning_uri(s, sys.argv[2], issuer)}")
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "code":
        print(totp(sys.argv[2]))
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "verify":
        ok = verify(sys.argv[2], sys.argv[3]) is not None
        print("OK" if ok else "NG")
        return 0 if ok else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
