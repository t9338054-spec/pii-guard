# 情報保護ツール集

個人情報の漏洩対策とアカウント乗っ取り対策のための、依存の少ない Python ツール群です。

| ツール | 用途 |
|---|---|
| `pii_guard.py` | 個人情報・秘密情報の検出、マスク、ファイル/フォルダの暗号化、git pre-commit フック |
| `pii_guard_gui.py` | 上記の GUI 版(tkinter) |
| `pwcheck.py` | パスワードの強度判定と漏洩確認 |
| `login_monitor.py` | ログイン履歴から乗っ取りの兆候を検出 |
| `totp.py` | 認証アプリ方式 (TOTP, RFC 6238) の多要素認証 |

必要環境: Python 3.9 以上。暗号化機能のみ `pip install cryptography` が必要です。
テスト: `pip install pytest` のあと `python -m pytest`

## pii_guard

```powershell
python pii_guard.py scan <ファイル/フォルダ>          # 検出(値はマスクして表示)
python pii_guard.py mask <ファイル> [-o 出力]         # マスク済みコピーを作成
python pii_guard.py encrypt <ファイル/フォルダ> [--delete-original]
python pii_guard.py decrypt <ファイル.enc/フォルダ> [--delete-encrypted]
python pii_guard.py hook install                      # 個人情報を含むコミットを止める
python pii_guard.py scan --staged                     # フックが内部で実行する検査
```

- 検出対象: メール、電話、クレジットカード(Luhn検証)、マイナンバー(検査用数字検証)、郵便番号、住所、氏名、IP、AWSキー、パスワード/トークンの代入、秘密鍵
- 氏名・住所は正規表現による簡易検出です。見逃しや誤検出があります
- 暗号化は PBKDF2-SHA256(60万回)+ Fernet(AES-128-CBC + HMAC)。パスワードを忘れると復号できません
- パスワードは対話入力が基本です。自動化では環境変数 `PII_GUARD_PASSWORD` も使えますが、環境変数は他のプロセスから見える場合があります
- 意図的にコミットする場合は `git commit --no-verify`

## pwcheck

```powershell
python pwcheck.py            # 強度判定 + 漏洩確認
python pwcheck.py --offline  # 外部通信なし
```

漏洩確認は Have I Been Pwned の Pwned Passwords API を使い、SHA-1 ハッシュの先頭5文字だけを送ります。

## login_monitor

```powershell
python login_monitor.py <ログファイル> [--format auto|csv|nginx|windows] [--window 600] [--fail-threshold 5]
```

終了コード 1 は検出ありです。形式は自動判定されます。

- **csv**: `時刻(ISO8601),ユーザー,IP,success|fail`
- **nginx**: combined 形式。`--login-path`(既定 `/login`)への POST の 401/403 を失敗、200/301/302/303 を成功とみなします。アクセスログにはユーザー名が出ないため、IP 単位の検出が中心になります
- **windows**: セキュリティログの 4624(成功)/4625(失敗)を、次の PowerShell で CSV にしたもの(管理者権限が必要)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=(Get-Date).AddDays(-1)} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ TimeCreated = $_.TimeCreated.ToString('o'); Id = $_.Id
                       TargetUserName = $d['TargetUserName']; IpAddress = $d['IpAddress'] }
  } | Export-Csv -NoTypeInformation -Encoding UTF8 win.csv
```

検出種別: `BRUTE_FORCE`(IP 単位の総当たり)、`TARGETED`(ユーザー単位)、`SPRAYING`(1 IP から多数ユーザー)、`SUSPECT_LOGIN`(失敗が続いた直後の成功。最優先で対応)、`NEW_IP`(初出 IP からの成功。参考情報)。閾値は環境に合わせて調整してください。

## totp

```python
import totp
secret = totp.new_secret()                          # 登録時に生成し、暗号化して保存
uri = totp.provisioning_uri(secret, "alice", "MyApp")  # QRコード化して認証アプリに読み込ませる
step = totp.verify(secret, user_input, last_step=saved_step)
if step is not None:
    saved_step = step                               # 同じコードの再利用(リプレイ)を防ぐ
```

CLI: `python totp.py new <アカウント名>` / `code <秘密鍵>` / `verify <秘密鍵> <コード>`

## 限界

これらは対策の一部です。検出は網羅的ではなく、暗号化した元ファイルの安全な削除(SSD では上書き消去が確実でないこと)や、バックアップ・クラウド上のコピーまでは管理しません。MFA の導入、パスワードマネージャー、更新の適用といった基本対策と併用してください。
