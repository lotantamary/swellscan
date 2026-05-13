"""
Demo-only script: render a verdict heading onto the bottom sand band of each
hero panel so we can preview whether baked-in typography is worth the backend
work. Outputs go to addon/design-refs/, never overwrite the canonical assets.
"""
from pathlib import Path
import numpy as np
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "backend" / "illustration" / "assets"
OUT_DIR = ROOT / "addon" / "design-refs"

PALETTE = {
    "safe":       (110, 156, 135),   # sage
    "suspicious": (212, 154, 63),    # amber
    "malicious":  (184,  68, 43),    # coral
}
DARK = (44, 38, 32)
SCORES = {"safe": 8, "suspicious": 42, "malicious": 87}
LABELS = {"safe": "SAFE", "suspicious": "SUSPICIOUS", "malicious": "MALICIOUS"}

LABEL_FONT = "C:/Windows/Fonts/impact.ttf"
SCORE_FONT = "C:/Windows/Fonts/arialbd.ttf"


def detect_bottom_band(img: Image.Image) -> int:
    """Return the y-coordinate where the bottom sand band starts."""
    arr = np.array(img)
    h, w, _ = arr.shape
    sample = arr[h - 2, w // 2].astype(int)
    for y in range(h - 1, -1, -1):
        mid = arr[y, w // 4 : 3 * w // 4].astype(int)
        diff = np.abs(mid - sample).max(axis=1)
        if (diff < 18).mean() < 0.85:
            return y + 1
    return 0


def bake(name: str) -> None:
    src = ASSETS / f"{name}.png"
    img = Image.open(src).convert("RGB")
    band_top = detect_bottom_band(img)
    band_h = img.height - band_top

    # If the existing band is too small, extend with the sampled sand color.
    MIN_BAND = 130
    if band_h < MIN_BAND:
        sand = tuple(np.array(img)[img.height - 2, img.width // 2].tolist())
        extra = MIN_BAND - band_h
        new = Image.new("RGB", (img.width, img.height + extra), sand)
        new.paste(img, (0, 0))
        img = new
        band_top = img.height - MIN_BAND
        band_h = MIN_BAND

    draw = ImageDraw.Draw(img)
    label_size = int(band_h * 0.58)
    score_size = int(band_h * 0.50)
    f_label = ImageFont.truetype(LABEL_FONT, label_size)
    f_score = ImageFont.truetype(SCORE_FONT, score_size)

    label_text = LABELS[name]
    score_text = f"{SCORES[name]}/100"
    sep = "  ·  "

    lb = draw.textbbox((0, 0), label_text, font=f_label)
    sp = draw.textbbox((0, 0), sep, font=f_score)
    sc = draw.textbbox((0, 0), score_text, font=f_score)
    lw, lh = lb[2] - lb[0], lb[3] - lb[1]
    pw, ph = sp[2] - sp[0], sp[3] - sp[1]
    sw, sh = sc[2] - sc[0], sc[3] - sc[1]
    total_w = lw + pw + sw

    cy = band_top + band_h / 2
    label_y = cy - lh / 2 - lb[1]
    sep_y = cy - ph / 2 - sp[1]
    score_y = cy - sh / 2 - sc[1]
    start_x = (img.width - total_w) / 2

    draw.text((start_x, label_y), label_text, fill=PALETTE[name], font=f_label)
    draw.text((start_x + lw, sep_y), sep, fill=(140, 130, 110), font=f_score)
    draw.text((start_x + lw + pw, score_y), score_text, fill=DARK, font=f_score)

    out = OUT_DIR / f"{name}-headed.png"
    img.save(out, optimize=True)
    print(f"{name}: band_top={band_top}  band_h={band_h}  size={img.size}  -> {out.name}")


for n in ("safe", "suspicious", "malicious"):
    bake(n)
