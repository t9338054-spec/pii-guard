import pytest

import pii_guard as pg


def kinds(text):
    return [k for _, _, k in pg.find_pii(text)]


def test_email_and_mask():
    assert kinds("連絡: taro@example.com") == ["メールアドレス"]
    assert pg.mask_text("taro@example.com") == "t***@example.com"


def test_phone_not_confused_with_postal():
    assert kinds("tel 090-1234-5678") == ["電話番号"]
    assert pg.mask_text("tel 090-1234-5678") == "tel *******5678"


def test_credit_card_luhn():
    assert kinds("card 4111 1111 1111 1111") == ["クレジットカード"]
    assert "クレジットカード" not in kinds("card 4111 1111 1111 1112")  # Luhn不正


def test_mynumber_checkdigit():
    # 先頭11桁 12345678901 → 検査用数字を計算して有効な番号を作る
    base = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1]
    s = sum(base[11 - p - 1] * (p + 1 if p <= 6 else p - 5) for p in range(1, 12))
    check = 0 if s % 11 <= 1 else 11 - s % 11
    valid = "".join(map(str, base + [check]))
    assert pg._my_check([int(c) for c in valid])
    assert not pg._my_check([int(c) for c in valid[:-1] + str((check + 1) % 10)])


def test_postal_and_address_and_name():
    assert "郵便番号" in kinds("〒100-0001")
    assert "住所" in kinds("東京都千代田区1-1-1")
    assert "氏名" in kinds("氏名: 山田 太郎")
    assert "氏名" in kinds("山田太郎様へ")


def test_secrets():
    assert "秘密情報(キー/トークン)" in kinds("password: Secret12345")
    assert "AWSキー" in kinds("AKIAABCDEFGHIJKLMNOP")
    assert "秘密鍵" in kinds("-----BEGIN RSA PRIVATE KEY-----")


def test_no_false_positive_on_plain_text():
    assert kinds("今日はいい天気です。会議は15時からです。") == []


def test_encrypt_decrypt_roundtrip(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("秘密", encoding="utf-8")
    enc = pg.encrypt_file(f, "password123", delete_original=True)
    assert not f.exists() and enc.exists()
    assert "秘密".encode() not in enc.read_bytes()
    out = pg.decrypt_file(enc, "password123")
    assert out.read_text(encoding="utf-8") == "秘密"


def test_decrypt_wrong_password_and_tamper(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("data")
    enc = pg.encrypt_file(f, "password123")
    with pytest.raises(ValueError):
        pg.decrypt_file(enc, "wrong-password")
    blob = bytearray(enc.read_bytes())
    blob[-3] ^= 0x01
    enc.write_bytes(bytes(blob))
    with pytest.raises(ValueError):
        pg.decrypt_file(enc, "password123")
