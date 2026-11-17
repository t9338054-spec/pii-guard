"""アプリアイコン（南京錠）のPNGを標準ライブラリだけで生成する。"""
import math, struct, zlib, sys, os

def png(path, size, pixels):
    raw = b"".join(b"\x00" + bytes(pixels[y*size*3:(y+1)*size*3]) for y in range(size))
    def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    data = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)) \
        + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    open(path, "wb").write(data)

def inside_lock(x, y):
    # 座標は 0..1。南京錠の本体と、つる（U字）
    if 0.28 <= x <= 0.72 and 0.46 <= y <= 0.80:
        # 本体の角丸
        r = 0.05
        cx = min(max(x, 0.28 + r), 0.72 - r); cy = min(max(y, 0.46 + r), 0.80 - r)
        if (x-cx)**2 + (y-cy)**2 <= r*r:
            # 鍵穴
            if (x-0.5)**2 + (y-0.60)**2 <= 0.045**2: return False
            if abs(x-0.5) <= 0.018 and 0.60 <= y <= 0.70: return False
            return True
    d = math.hypot(x-0.5, y-0.40)
    if y <= 0.40 and 0.115 <= d <= 0.175: return True
    if 0.40 <= y <= 0.47 and (0.325 <= x <= 0.385 or 0.615 <= x <= 0.675): return True
    return False

def render(size, ss=4):
    px = []
    top, bot = (37, 99, 235), (15, 23, 42)
    for j in range(size):
        for i in range(size):
            acc = [0, 0, 0]
            for sj in range(ss):
                for si in range(ss):
                    x = (i + (si+.5)/ss) / size; y = (j + (sj+.5)/ss) / size
                    t = y
                    c = [round(top[k]*(1-t) + bot[k]*t) for k in range(3)]
                    if inside_lock(x, y): c = [255, 255, 255]
                    for k in range(3): acc[k] += c[k]
            px += [a // (ss*ss) for a in acc]
    return px

out = sys.argv[1]
for name, size in [("apple-touch-icon.png", 180), ("icon-192.png", 192), ("icon-512.png", 512)]:
    png(os.path.join(out, name), size, render(size, 3 if size > 200 else 4))
    print("wrote", name)
