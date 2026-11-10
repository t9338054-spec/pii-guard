import Foundation

/// 検出結果。range は NSString (UTF-16) 基準。
public struct Match: Equatable {
    public let range: NSRange
    public let kind: String
}

/// 個人情報・秘密情報の検出とマスキング(デスクトップ版 pii_guard.py と同じルール)
public enum Detector {

    private struct Rule {
        let kind: String
        let regex: NSRegularExpression
        let check: ((String) -> Bool)?
    }

    private static let prefecture =
        "(?:北海道|東京都|(?:京都|大阪)府|(?:青森|岩手|宮城|秋田|山形|福島|茨城|栃木|群馬|埼玉|千葉|神奈川|新潟|富山|石川|福井|山梨|長野|岐阜|静岡|愛知|三重|滋賀|兵庫|奈良|和歌山|鳥取|島根|岡山|広島|山口|徳島|香川|愛媛|高知|福岡|佐賀|長崎|熊本|大分|宮崎|鹿児島|沖縄)県)"

    private static func rule(_ kind: String, _ pattern: String, _ check: ((String) -> Bool)? = nil) -> Rule {
        // パターンは固定の文字列なので、コンパイル失敗はプログラムの誤り
        Rule(kind: kind, regex: try! NSRegularExpression(pattern: pattern), check: check)
    }

    private static let rules: [Rule] = [
        rule("メールアドレス", #"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"#),
        rule("電話番号", #"(?<!\d)0\d{1,4}[-ー ]\d{1,4}[-ー ]\d{3,4}(?!\d)|(?<!\d)0[789]0\d{8}(?!\d)"#),
        rule("クレジットカード", #"(?<!\d)(?:\d[ -]?){13,16}(?!\d)"#) { v in
            let d = digits(v)
            return (13...16).contains(d.count) && luhnOK(d)
        },
        rule("マイナンバー", #"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)"#) { v in
            myNumberOK(digits(v))
        },
        rule("郵便番号", #"(?<![\d-])\d{3}-\d{4}(?![\d-])"#),
        rule("IPアドレス", #"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)"#),
        rule("AWSキー", #"AKIA[0-9A-Z]{16}"#),
        rule("秘密情報(キー/トークン)",
             #"(?i)(?:api[_-]?key|secret|token|passw(?:or)?d|パスワード)\s*[:=：]\s*['"]?[^\s'"]{6,}"#),
        rule("秘密鍵", #"-----BEGIN [A-Z ]*PRIVATE KEY-----"#),
        rule("住所", prefecture + #"[^\s,、。「」]{2,30}?\d{1,4}(?:[-ー丁目番地号]\d{0,4}){0,3}[^\s,、。]{0,12}"#),
        rule("氏名",
             #"(?:氏名|名前|お名前|契約者|代表者|担当者)\s*[:：]\s*[一-龥ぁ-んァ-ヶ]{1,5}[ 　]?[一-龥ぁ-んァ-ヶ]{1,5}"#
             + #"|(?<![一-龥ぁ-んァ-ヶ])[一-龥]{1,4}[ 　]?[一-龥]{1,3}(?=様|殿|さん(?![ぁ-ん]))"#),
    ]

    // MARK: - 検証

    static func digits(_ s: String) -> [Int] {
        s.compactMap { $0.isASCII ? $0.wholeNumberValue : nil }
    }

    static func luhnOK(_ d: [Int]) -> Bool {
        var total = 0
        var alt = false
        for n in d.reversed() {
            var v = n
            if alt {
                v *= 2
                if v > 9 { v -= 9 }
            }
            total += v
            alt.toggle()
        }
        return total % 10 == 0
    }

    /// マイナンバー(12桁)の検査用数字の検証
    static func myNumberOK(_ n: [Int]) -> Bool {
        guard n.count == 12 else { return false }
        var s = 0
        for p in 1...11 {
            let q = p <= 6 ? p + 1 : p - 5
            s += n[11 - p] * q
        }
        let r = s % 11
        return (r <= 1 ? 0 : 11 - r) == n[11]
    }

    // MARK: - 公開API

    /// 重複を除いた検出結果(位置順。同じ開始位置なら長い一致を優先)
    public static func find(in text: String) -> [Match] {
        let ns = text as NSString
        let whole = NSRange(location: 0, length: ns.length)
        var hits: [Match] = []
        for r in rules {
            r.regex.enumerateMatches(in: text, options: [], range: whole) { m, _, _ in
                guard let m = m else { return }
                if let check = r.check, !check(ns.substring(with: m.range)) { return }
                hits.append(Match(range: m.range, kind: r.kind))
            }
        }
        hits.sort {
            $0.range.location != $1.range.location
                ? $0.range.location < $1.range.location
                : $0.range.length > $1.range.length
        }
        var result: [Match] = []
        var lastEnd = -1
        for h in hits where h.range.location >= lastEnd {
            result.append(h)
            lastEnd = h.range.location + h.range.length
        }
        return result
    }

    public static func maskValue(_ value: String, kind: String) -> String {
        switch kind {
        case "メールアドレス":
            let parts = value.split(separator: "@", maxSplits: 1, omittingEmptySubsequences: false)
            return String(parts[0].prefix(1)) + "***@" + (parts.count > 1 ? String(parts[1]) : "")
        case "クレジットカード", "マイナンバー", "電話番号":
            let d = digits(value)
            return String(repeating: "*", count: max(0, d.count - 4)) + d.suffix(4).map(String.init).joined()
        default:
            return "[\(kind):MASKED]"
        }
    }

    public static func mask(_ text: String) -> String {
        let ns = text as NSString
        var out = ""
        var pos = 0
        for m in find(in: text) {
            out += ns.substring(with: NSRange(location: pos, length: m.range.location - pos))
            out += maskValue(ns.substring(with: m.range), kind: m.kind)
            pos = m.range.location + m.range.length
        }
        out += ns.substring(from: pos)
        return out
    }
}
