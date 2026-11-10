#!/usr/bin/env python3
"""pii_guard の GUI (tkinter)。検出・マスク・暗号化・復号をボタンで実行する。"""
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

import pii_guard as pg


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PII Guard - 個人情報保護ツール")
        self.geometry("760x520")
        self.path = tk.StringVar()

        top = tk.Frame(self)
        top.pack(fill="x", padx=8, pady=8)
        tk.Entry(top, textvariable=self.path).pack(side="left", fill="x", expand=True)
        tk.Button(top, text="ファイル", command=self.pick_file).pack(side="left", padx=2)
        tk.Button(top, text="フォルダ", command=self.pick_dir).pack(side="left")

        bar = tk.Frame(self)
        bar.pack(fill="x", padx=8)
        for label, fn in (("検出", self.scan), ("マスク出力", self.mask),
                          ("暗号化", self.encrypt), ("復号", self.decrypt)):
            tk.Button(bar, text=label, width=12, command=fn).pack(side="left", padx=2)

        self.out = tk.Text(self, state="disabled", wrap="none")
        self.out.pack(fill="both", expand=True, padx=8, pady=8)

    # ---- ヘルパ ----
    def log(self, msg):
        self.out.config(state="normal")
        self.out.insert("end", msg + "\n")
        self.out.see("end")
        self.out.config(state="disabled")

    def pick_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.path.set(p)

    def pick_dir(self):
        p = filedialog.askdirectory()
        if p:
            self.path.set(p)

    def target(self):
        p = Path(self.path.get())
        if not p.exists():
            messagebox.showwarning("PII Guard", "ファイルまたはフォルダを選択してください")
            return None
        return p

    def ask_password(self, confirm):
        pw = simpledialog.askstring("パスワード", "パスワード(8文字以上):", show="*", parent=self)
        if not pw:
            return None
        if confirm:
            if len(pw) < 8:
                messagebox.showwarning("PII Guard", "8文字以上にしてください")
                return None
            if simpledialog.askstring("パスワード", "確認のため再入力:", show="*", parent=self) != pw:
                messagebox.showwarning("PII Guard", "パスワードが一致しません")
                return None
        return pw

    # ---- 操作 ----
    def scan(self):
        t = self.target()
        if not t:
            return
        n = 0
        for p in pg.iter_files(t):
            text = pg.read_text(p)
            if text is None:
                continue
            for s, e, kind in pg.find_pii(text):
                self.log(f"{p}:{text.count(chr(10), 0, s) + 1}: {kind}: {pg.mask_value(text[s:e], kind)}")
                n += 1
        self.log(f"--- 検出数: {n} ---")

    def mask(self):
        t = self.target()
        if not t or t.is_dir():
            messagebox.showinfo("PII Guard", "マスクはファイルを選択してください")
            return
        text = pg.read_text(t)
        if text is None:
            messagebox.showwarning("PII Guard", "テキストとして読めません")
            return
        out = t.with_name(t.stem + ".masked" + t.suffix)
        out.write_text(pg.mask_text(text), encoding="utf-8")
        self.log(f"マスク済み: {out}")

    def encrypt(self):
        t = self.target()
        if not t:
            return
        pw = self.ask_password(confirm=True)
        if not pw:
            return
        delete = messagebox.askyesno("PII Guard", "暗号化後に元ファイルを削除しますか?")
        files = [p for p in pg.iter_files(t)] if t.is_dir() else [t]
        for p in files:
            self.log(f"暗号化: {pg.encrypt_file(p, pw, delete)}")

    def decrypt(self):
        t = self.target()
        if not t:
            return
        pw = self.ask_password(confirm=False)
        if not pw:
            return
        files = list(t.rglob("*.enc")) if t.is_dir() else [t]
        for p in files:
            try:
                self.log(f"復号: {pg.decrypt_file(p, pw)}")
            except ValueError as e:
                self.log(f"{p}: {e}")


if __name__ == "__main__":
    App().mainloop()
