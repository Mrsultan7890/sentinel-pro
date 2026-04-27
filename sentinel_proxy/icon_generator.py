# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
#
# Unauthorized copying, distribution, or modification of this software,
# via any medium, is strictly prohibited without written permission.
#
# Licensed users may use this software under the terms of their license.
# For licensing: https://github.com/Mrsultan7890/osints
# ============================================================================

"""
SentinelProxy Icon Generator
=============================
Programmatically generates the SentinelProxy icon using PIL.
No external files needed — pure Python.

Generates:
  - sentinel_proxy_icon.png  (256x256)
  - sentinel_proxy_icon_32.png (32x32  — taskbar)
  - sentinel_proxy_icon.ico   (multi-size ICO)

Design: Neon teal hexagon shield + octopus silhouette on deep black background.
"""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import math

ICON_DIR = Path(__file__).parent

# ── Color palette (matches app theme) ────────────────────────────────────────
BG_COLOR     = (8,  12,  14)       # #080c0e  deep black-green
ACCENT       = (0,  229, 192)      # #00e5c0  neon teal
ACCENT2      = (0,  184, 154)      # #00b89a  teal darker
ACCENT_DIM   = (0,  61,  53)       # #003d35  teal bg tint
BORDER       = (30, 48,  53)       # #1e3035
GREEN_NEON   = (57, 255, 110)      # #39ff6e
RED_NEON     = (255, 59, 92)       # #ff3b5c
TEXT_COLOR   = (205, 232, 224)     # #cde8e0


def _hex_points(cx: float, cy: float, r: float, rotation: float = 0):
    """Return 6 (x, y) points of a regular hexagon."""
    pts = []
    for i in range(6):
        angle = math.radians(60 * i + rotation)
        pts.append((cx + r * math.cos(angle), cy + r * math.sin(angle)))
    return pts


def _draw_hexagon(draw: ImageDraw.Draw, cx, cy, r,
                  fill=None, outline=None, width=2, rotation=30):
    pts = _hex_points(cx, cy, r, rotation)
    if fill:
        draw.polygon(pts, fill=fill)
    if outline:
        draw.polygon(pts, outline=outline, width=width)


def _draw_glow(draw: ImageDraw.Draw, cx, cy, r, color, layers=6):
    """Draw concentric hexagons for glow effect."""
    for i in range(layers, 0, -1):
        alpha = int(40 * (i / layers))
        glow_color = color + (alpha,)
        _draw_hexagon(draw, cx, cy, r + i * 3,
                      outline=glow_color, width=1, rotation=30)


def _draw_octopus(draw: ImageDraw.Draw, cx, cy, size, color):
    """
    Draw a simplified octopus silhouette:
    - Round head
    - 8 curved tentacles radiating outward
    """
    head_r = size * 0.28

    # Head
    draw.ellipse(
        (cx - head_r, cy - head_r * 1.1,
         cx + head_r, cy + head_r * 0.9),
        fill=color
    )

    # Eyes
    eye_r   = head_r * 0.18
    eye_off = head_r * 0.35
    eye_y   = cy - head_r * 0.15
    eye_col = BG_COLOR
    draw.ellipse((cx - eye_off - eye_r, eye_y - eye_r,
                  cx - eye_off + eye_r, eye_y + eye_r), fill=eye_col)
    draw.ellipse((cx + eye_off - eye_r, eye_y - eye_r,
                  cx + eye_off + eye_r, eye_y + eye_r), fill=eye_col)

    # 8 tentacles
    tentacle_angles = [
        -80, -50, -20, 20,
         50,  80, 110, 140,
    ]
    for angle_deg in tentacle_angles:
        angle = math.radians(angle_deg)
        # Start at bottom of head
        sx = cx + head_r * 0.6 * math.cos(angle)
        sy = cy + head_r * 0.7

        # Control points for bezier-like curve (approximated with lines)
        mid_r  = size * 0.55
        end_r  = size * 0.85
        spread = math.radians(angle_deg * 0.8 + 90)

        mx = cx + mid_r * math.cos(spread)
        my = cy + mid_r * math.sin(spread) * 0.6 + head_r * 0.5

        ex = cx + end_r * math.cos(spread)
        ey = cy + end_r * math.sin(spread) * 0.7 + head_r * 0.3

        # Draw tentacle as thick line segments
        t_width = max(2, int(size * 0.045))
        draw.line([(sx, sy), (mx, my), (ex, ey)],
                  fill=color, width=t_width, joint='curve')

        # Sucker dots on tentacle
        for frac in [0.4, 0.7, 0.9]:
            dot_x = sx + (ex - sx) * frac
            dot_y = sy + (ey - sy) * frac
            dot_r = max(1, int(size * 0.025))
            draw.ellipse((dot_x - dot_r, dot_y - dot_r,
                          dot_x + dot_r, dot_y + dot_r),
                         fill=BG_COLOR)


def generate_icon(size: int = 256) -> Image.Image:
    """Generate SentinelProxy icon at given size."""
    img  = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    cx = size / 2
    cy = size / 2
    r  = size * 0.46

    # ── Background circle ─────────────────────────────────────────────────────
    bg_r = size * 0.48
    draw.ellipse((cx - bg_r, cy - bg_r, cx + bg_r, cy + bg_r),
                 fill=BG_COLOR + (255,))

    # ── Outer glow hexagon ────────────────────────────────────────────────────
    _draw_glow(draw, cx, cy, r, ACCENT, layers=5)

    # ── Hexagon fill (dark teal) ──────────────────────────────────────────────
    _draw_hexagon(draw, cx, cy, r, fill=ACCENT_DIM + (220,), rotation=30)

    # ── Hexagon border (neon teal) ────────────────────────────────────────────
    border_w = max(2, size // 40)
    _draw_hexagon(draw, cx, cy, r,
                  outline=ACCENT + (255,), width=border_w, rotation=30)

    # ── Inner hexagon (subtle) ────────────────────────────────────────────────
    _draw_hexagon(draw, cx, cy, r * 0.88,
                  outline=ACCENT2 + (80,), width=1, rotation=30)

    # ── Octopus ───────────────────────────────────────────────────────────────
    oct_color = ACCENT + (230,)
    _draw_octopus(draw, cx, cy - size * 0.02, size * 0.42, oct_color)

    # ── Corner dots (decorative) ──────────────────────────────────────────────
    dot_r = max(2, size // 55)
    for angle_deg in range(0, 360, 60):
        angle = math.radians(angle_deg + 30)
        dx    = cx + (r + border_w + dot_r + 2) * math.cos(angle)
        dy    = cy + (r + border_w + dot_r + 2) * math.sin(angle)
        draw.ellipse((dx - dot_r, dy - dot_r, dx + dot_r, dy + dot_r),
                     fill=ACCENT + (180,))

    return img


def generate_all_icons():
    """Generate all icon sizes and save to ICON_DIR."""
    sizes = {
        'sentinel_proxy_icon_256.png': 256,
        'sentinel_proxy_icon_128.png': 128,
        'sentinel_proxy_icon_64.png':  64,
        'sentinel_proxy_icon_32.png':  32,
        'sentinel_proxy_icon_16.png':  16,
    }

    imgs = {}
    for fname, sz in sizes.items():
        img = generate_icon(sz)
        img.save(ICON_DIR / fname)
        imgs[sz] = img

    # Save multi-size ICO
    ico_path = ICON_DIR / 'sentinel_proxy_icon.ico'
    imgs[256].save(
        ico_path,
        format='ICO',
        sizes=[(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)],
        append_images=[imgs[128], imgs[64], imgs[32], imgs[16]],
    )

    # Save main PNG (256)
    main_png = ICON_DIR / 'sentinel_proxy_icon.png'
    imgs[256].save(main_png)

    return {
        'png':    main_png,
        'ico':    ico_path,
        'png_32': ICON_DIR / 'sentinel_proxy_icon_32.png',
    }


def get_tk_icon(root, size: int = 64):
    """
    Returns a PhotoImage suitable for root.iconphoto().
    Generates icon on-the-fly if file doesn't exist.
    """
    import tkinter as tk
    png_path = ICON_DIR / f'sentinel_proxy_icon_{size}.png'
    if not png_path.exists():
        generate_all_icons()
    try:
        return tk.PhotoImage(file=str(png_path))
    except Exception:
        # Fallback: generate in-memory
        img = generate_icon(size)
        import tempfile, os
        tmp = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
        img.save(tmp.name)
        tmp.close()
        photo = tk.PhotoImage(file=tmp.name)
        os.unlink(tmp.name)
        return photo


if __name__ == '__main__':
    paths = generate_all_icons()
    print('Icons generated:')
    for k, v in paths.items():
        print(f'  {k}: {v}')
