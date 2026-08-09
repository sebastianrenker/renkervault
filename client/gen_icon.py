"""Erzeugt das RenkerVault-Schild-Icon in allen von Tauri/Windows benötigten
Größen/Formaten aus einer einzigen Vektor-Zeichnung (reines Pillow, kein SVG-Renderer nötig).
"""
import math
from PIL import Image, ImageDraw

BG = (10, 15, 13, 255)        # Graphit (--bg)
ACCENT = (46, 230, 168, 255)  # Smaragd (--accent)
ACCENT_DIM = (46, 230, 168, 90)
WHITE = (214, 229, 222, 255)


def draw_shield(size: int) -> Image.Image:
    s = size * 4  # supersampling für glatte Kanten
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    cx = s / 2

    # Hintergrund: abgerundetes dunkles Quadrat
    r = s * 0.18
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=r, fill=BG)

    # Schild-Umriss
    top = s * 0.18
    shield_w = s * 0.56
    left = cx - shield_w / 2
    right = cx + shield_w / 2
    mid = s * 0.58
    bottom = s * 0.86
    pts = [
        (cx, top),
        (right, top + shield_w * 0.32),
        (right, mid),
        (cx, bottom),
        (left, mid),
        (left, top + shield_w * 0.32),
    ]
    d.polygon(pts, fill=(*ACCENT[:3], 40), outline=ACCENT, width=max(2, int(s * 0.014)))

    # Schloss-Körper
    lock_w = s * 0.22
    lock_h = s * 0.18
    lock_top = s * 0.50
    lx0, ly0 = cx - lock_w / 2, lock_top
    lx1, ly1 = cx + lock_w / 2, lock_top + lock_h
    d.rounded_rectangle([lx0, ly0, lx1, ly1], radius=s * 0.02, fill=(*ACCENT[:3], 60), outline=ACCENT, width=max(2, int(s * 0.012)))

    # Schloss-Bügel
    shackle_r = lock_w * 0.42
    shackle_top = ly0 - shackle_r
    d.arc([cx - shackle_r, shackle_top - shackle_r * 0.15, cx + shackle_r, shackle_top + shackle_r * 1.5],
          start=180, end=360, fill=ACCENT, width=max(2, int(s * 0.02)))

    # Schlüsselloch
    hole_r = s * 0.018
    hole_cy = ly0 + lock_h * 0.35
    d.ellipse([cx - hole_r, hole_cy - hole_r, cx + hole_r, hole_cy + hole_r], fill=ACCENT)
    d.rectangle([cx - hole_r * 0.5, hole_cy, cx + hole_r * 0.5, hole_cy + hole_r * 1.6], fill=ACCENT)

    return img.resize((size, size), Image.LANCZOS)


if __name__ == "__main__":
    import sys
    outdir = sys.argv[1] if len(sys.argv) > 1 else "src-tauri/icons"

    sizes_png = {
        "32x32.png": 32, "128x128.png": 128, "128x128@2x.png": 256,
        "icon.png": 512,
        "Square30x30Logo.png": 30, "Square44x44Logo.png": 44,
        "Square71x71Logo.png": 71, "Square89x89Logo.png": 89,
        "Square107x107Logo.png": 107, "Square142x142Logo.png": 142,
        "Square150x150Logo.png": 150, "Square284x284Logo.png": 284,
        "Square310x310Logo.png": 310, "StoreLogo.png": 50,
    }
    for name, sz in sizes_png.items():
        draw_shield(sz).save(f"{outdir}/{name}")

    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    imgs = [draw_shield(s) for s in ico_sizes]
    imgs[-1].save(f"{outdir}/icon.ico", format="ICO",
                  sizes=[(s, s) for s in ico_sizes],
                  append_images=imgs[:-1])

    draw_shield(512).save(f"{outdir}/icon.png")
    print("icons written to", outdir)
