import SwiftUI
import UniformTypeIdentifiers
import PIIGuardCore

struct ContentView: View {
    var body: some View {
        TabView {
            ScanView()
                .tabItem { Label("検出・マスク", systemImage: "eye.slash") }
            CryptoView()
                .tabItem { Label("暗号化", systemImage: "lock.doc") }
        }
    }
}

// MARK: - 検出・マスク

struct ScanView: View {
    @State private var text = ""
    @State private var findings: [(kind: String, masked: String)] = []
    @State private var masked = ""
    @State private var scanned = false
    @State private var importing = false
    @State private var message: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("テキスト(貼り付け or ファイル読込)") {
                    TextEditor(text: $text)
                        .frame(minHeight: 140)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    HStack {
                        Button("貼り付け") { text = UIPasteboard.general.string ?? text }
                        Spacer()
                        Button("ファイルを開く") { importing = true }
                        Spacer()
                        Button("クリア", role: .destructive) { clear() }
                    }
                    .buttonStyle(.borderless)
                }

                Section {
                    Button("検出する") { scan() }
                }

                if scanned {
                    Section("検出結果(\(findings.count)件)") {
                        if findings.isEmpty {
                            Text("個人情報は見つかりませんでした").foregroundStyle(.secondary)
                        }
                        ForEach(findings.indices, id: \.self) { i in
                            HStack {
                                Text(findings[i].kind).font(.subheadline).bold()
                                Spacer()
                                Text(findings[i].masked).font(.system(.body, design: .monospaced))
                            }
                        }
                    }
                    if !findings.isEmpty {
                        Section("マスク後のテキスト") {
                            Text(masked).textSelection(.enabled)
                            HStack {
                                Button("コピー") { UIPasteboard.general.string = masked }
                                Spacer()
                                ShareLink(item: masked)
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                }
                if let message {
                    Section { Text(message).foregroundStyle(.red) }
                }
            }
            .navigationTitle("PII Guard")
            .fileImporter(isPresented: $importing, allowedContentTypes: [.plainText, .text, .json, .commaSeparatedText]) { result in
                load(result)
            }
        }
    }

    private func scan() {
        message = nil
        findings = Detector.find(in: text).map { m in
            let raw = (text as NSString).substring(with: m.range)
            // 画面にも生の値は表示しない(肩越しの覗き見対策)
            return (m.kind, Detector.maskValue(raw, kind: m.kind))
        }
        masked = Detector.mask(text)
        scanned = true
    }

    private func clear() {
        text = ""; findings = []; masked = ""; scanned = false; message = nil
    }

    private func load(_ result: Result<URL, Error>) {
        do {
            let url = try result.get()
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: url)
            guard data.count <= 5_000_000 else { message = "ファイルが大きすぎます(5MBまで)"; return }
            guard let s = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .shiftJIS) else {
                message = "テキストとして読み込めません"; return
            }
            text = s
            scanned = false
        } catch {
            message = error.localizedDescription
        }
    }
}

// MARK: - 暗号化

struct CryptoView: View {
    @State private var password = ""
    @State private var confirm = ""
    @State private var importing = false
    @State private var working = false
    @State private var outputURL: URL?
    @State private var message: String?
    @State private var isError = false

    private enum Mode { case encrypt, decrypt }
    @State private var mode: Mode = .encrypt

    var body: some View {
        NavigationStack {
            Form {
                Section("パスワード(8文字以上)") {
                    SecureField("パスワード", text: $password)
                    SecureField("確認のため再入力(暗号化時)", text: $confirm)
                    Text("パスワードを忘れると復号できません。復旧手段はありません。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section {
                    Button("ファイルを選んで暗号化") { start(.encrypt) }
                    Button("暗号化ファイル(.enc)を復号") { start(.decrypt) }
                }
                .disabled(working)

                if working { Section { ProgressView("処理中…") } }

                if let message {
                    Section { Text(message).foregroundStyle(isError ? .red : .green) }
                }
                if let outputURL {
                    Section("出力ファイル") {
                        Text(outputURL.lastPathComponent)
                        ShareLink(item: outputURL)  // 「ファイルに保存」やAirDropなどで書き出す
                    }
                }
            }
            .navigationTitle("ファイル暗号化")
            .fileImporter(isPresented: $importing, allowedContentTypes: [.item]) { result in
                run(result)
            }
        }
    }

    private func start(_ m: Mode) {
        mode = m
        message = nil
        outputURL = nil
        if password.count < 8 { return fail("パスワードは8文字以上にしてください") }
        if m == .encrypt && password != confirm { return fail("パスワードが一致しません") }
        importing = true
    }

    private func fail(_ s: String) { message = s; isError = true }

    private func run(_ result: Result<URL, Error>) {
        let mode = self.mode
        let pw = password
        working = true
        Task.detached(priority: .userInitiated) {
            // PBKDF2 は意図的に重い処理なので UI スレッドから外す
            let outcome: Result<URL, Error> = Result {
                let url = try result.get()
                let access = url.startAccessingSecurityScopedResource()
                defer { if access { url.stopAccessingSecurityScopedResource() } }
                let input = try Data(contentsOf: url)
                let name = url.lastPathComponent
                let out: Data
                var outName: String
                if mode == .encrypt {
                    out = try FileCrypto.encrypt(input, password: pw)
                    outName = name + ".enc"
                } else {
                    out = try FileCrypto.decrypt(input, password: pw)
                    outName = name.hasSuffix(".enc") ? String(name.dropLast(4)) : name + ".dec"
                }
                let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                let dest = dir.appendingPathComponent(outName)
                try out.write(to: dest, options: [.completeFileProtection])
                return dest
            }
            await MainActor.run {
                working = false
                switch outcome {
                case .success(let dest):
                    outputURL = dest
                    message = mode == .encrypt ? "暗号化しました" : "復号しました"
                    isError = false
                case .failure(let e):
                    fail(e.localizedDescription)
                }
            }
        }
    }
}
