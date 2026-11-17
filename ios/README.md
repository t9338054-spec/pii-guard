# PII Guard for iPhone

> Mac がなくても使える Web アプリ版が `web/` にあります(https://t9338054-spec.github.io/pii-guard/)。通常はそちらを使ってください。

個人情報の**検出・マスク**と**ファイル暗号化**を、通信なし・端末内だけで行う SwiftUI アプリです(iOS 16 以上)。

> **状態: 未ビルド・未テスト。** 開発環境が Windows で Swift/Xcode が無かったため、コンパイルも実行もしていません。
> 初回ビルドで細かなコンパイルエラーが出る可能性があります。エラー内容を貼ってもらえれば修正します。

## 構成
```
ios/
├─ PIIGuardCore/        ロジック(Swift Package)。検出・マスク・暗号化とXCTest
│   ├─ Sources/PIIGuardCore/Detector.swift
│   ├─ Sources/PIIGuardCore/FileCrypto.swift
│   └─ Tests/PIIGuardCoreTests/PIIGuardCoreTests.swift
└─ PIIGuardApp/         画面(SwiftUI)
    ├─ PIIGuardApp.swift
    └─ ContentView.swift
```

## ビルド手順(Mac + Xcode 15 以上が必要)
1. Xcode で **File > New > Project > iOS > App** を作る(Product Name: `PIIGuard`、Interface: SwiftUI、Language: Swift)。
2. 自動生成された `PIIGuardApp.swift` と `ContentView.swift` を、このフォルダの同名ファイルで置き換える。
3. **File > Add Package Dependencies… > Add Local…** で `ios/PIIGuardCore` を選び、アプリターゲットに追加する。
4. 先にロジックだけ確認したい場合は、ターミナルで `cd ios/PIIGuardCore && swift test`(Mac)。
5. iPhone を接続し、Signing & Capabilities で自分の Apple ID のチームを選んで Run。
   無料の Apple ID でも実機に入れられますが、7日ごとに再署名が必要です。App Store 配布には Apple Developer Program(有料)が必要です。

## 仕様と注意
- **検出**: メール、電話、クレジットカード(Luhn)、マイナンバー(検査用数字)、郵便番号、住所、氏名、IP、AWSキー、パスワード/トークン、秘密鍵。氏名・住所は簡易検出で、見逃しや誤検出があります。画面にも生の値は出さずマスクして表示します。
- **暗号化**: AES-256-GCM、鍵は PBKDF2-HMAC-SHA256(60万回)。パスワードを忘れると復号できません。
- **互換性**: デスクトップ版 Python の `.enc`(Fernet)とは**形式が異なり、相互に復号できません**。必要なら揃えられます。
- 出力ファイルは一時フォルダに作られ、共有シートから「ファイルに保存」等で書き出します。元ファイルは削除しません。
- 大きなファイルは全体をメモリに読み込むため、数十MB程度までを想定しています。
