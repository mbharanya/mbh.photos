#!/usr/bin/env python3
"""
watermark.py — add a subtle text watermark to images.

Usage examples:
  # Single file, default watermark "mbh.photos"
  python watermark.py input.jpg

  # Whole folder (recursively) -> write to ./watermarked
  python watermark.py ./photos -o ./watermarked

  # Customize look/placement
  python watermark.py ./photos -t "mbh.photos" --opacity 0.25 --scale 0.035 \
    --position bottom-right --margin 0.02

  # Use a specific TTF font
  python watermark.py input.png --font "/System/Library/Fonts/Supplemental/Arial.ttf"
  
  # Resize and compress for web
  python watermark.py ./photos -o ./web --resize 1920 --quality 80
"""

import argparse
import os
from pathlib import Path
from typing import Tuple

from PIL import Image, ImageDraw, ImageFont

# --------- Helpers ---------
def load_font(font_path: str | None, px: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """
    Try user font, then common system fonts, then Pillow's bundled DejaVuSans.
    """
    candidates = []
    if font_path:
        candidates.append(font_path)
    candidates += [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/Library/Fonts/Arial.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
    ]

    for fp in candidates:
        p = Path(fp)
        if p.exists():
            try:
                return ImageFont.truetype(str(p), px)
            except Exception:
                pass

    # Final fallback: Pillow's bundled DejaVuSans
    try:
        import PIL
        pil_fonts = Path(PIL.__file__).with_name("fonts")
        djv = pil_fonts / "DejaVuSans.ttf"
        if djv.exists():
            return ImageFont.truetype(str(djv), px)
    except Exception:
        pass

    # Absolute last resort (bitmap, tiny)
    return ImageFont.load_default()

def compute_anchor(position: str) -> str:
    # Map friendly positions to Pillow anchors
    return {
        "bottom-right": "rs",
        "bottom-left": "ls",
        "top-right": "rt",
        "top-left": "lt",
        "center": "mm",
    }[position]

def place_point(size: Tuple[int, int], margin_px: int, position: str) -> Tuple[int, int]:
    W, H = size
    if position == "bottom-right":
        return (W - margin_px, H - margin_px)
    if position == "bottom-left":
        return (margin_px, H - margin_px)
    if position == "top-right":
        return (W - margin_px, margin_px)
    if position == "top-left":
        return (margin_px, margin_px)
    # center
    return (W // 2, H // 2)

def add_watermark(
    im: Image.Image,
    text: str = "mbh.photos",
    scale: float = 0.035,
    opacity: float = 0.25,
    margin: float = 0.02,
    position: str = "bottom-right",
    font_path: str | None = None,
    stroke_ratio: float = 0.12,
) -> Image.Image:
    """
    scale: font size as fraction of image width (e.g., 0.035 = 3.5% of width)
    opacity: 0..1
    margin: margin as fraction of min(width,height)
    position: bottom-right|bottom-left|top-right|top-left|center
    stroke_ratio: outline thickness relative to font size
    """
    if im.mode != "RGBA":
        im = im.convert("RGBA")
    W, H = im.size

    # --- Dynamic font sizing: make text ~ (scale * image width) ---
    # Interpret `scale` as desired text-width ratio of image width.
    target_text_w = max(1, int(W * scale))

    # Start with a reasonable guess, then refine
    test_px = max(12, int(W * scale))  # initial guess
    font = load_font(font_path, test_px)

    # Function to measure text width accurately with anchor-insensitive metric
    def measure_text_w(fnt: ImageFont.ImageFont) -> int:
        # textbbox gives (l, t, r, b)
        tmp_img = Image.new("RGB", (10, 10))
        tmp_draw = ImageDraw.Draw(tmp_img)
        l, t, r, b = tmp_draw.textbbox((0, 0), text, font=fnt, stroke_width=max(1, int(fnt.size * 0.12)))
        return r - l

    # Adjust font size using a couple of passes
    for _ in range(8):
        w_now = measure_text_w(font)
        if w_now == 0:
            break
        ratio = target_text_w / w_now
        if 0.95 <= ratio <= 1.05:
            break
        # Update size (limit growth to avoid overshoot)
        new_px = int(font.size * min(1.5, max(0.67, ratio)))
        new_px = max(12, min(new_px, max(W, H)))  # clamp
        if new_px == font.size:
            break
        font = load_font(font_path, new_px)

    font_px = getattr(font, "size", test_px)
    margin_px = max(2, int(min(W, H) * margin))

    # Create overlay
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    # Measure text (for centering accuracy with default font variations)
    # Using anchor simplifies placement; still keep stroke to improve legibility.
    anchor = compute_anchor(position)
    xy = place_point((W, H), margin_px, position)

    # Colors
    # Foreground near-white with adjustable alpha; soft shadow for readability
    a = max(0, min(255, int(255 * opacity)))
    fg = (255, 255, 255, a)
    shadow = (0, 0, 0, int(a * 0.9))

    stroke_w = max(1, int(font_px * stroke_ratio))

    # Soft drop shadow first (offset a couple of pixels)
    shadow_offset = max(1, int(font_px * 0.06))
    draw.text(
        (xy[0] + shadow_offset, xy[1] + shadow_offset),
        text,
        font=font,
        fill=shadow,
        anchor=anchor,
        stroke_width=0,
    )

    # Main text with subtle outline (stroke) to stand out on busy areas
    draw.text(
        xy,
        text,
        font=font,
        fill=fg,
        anchor=anchor,
        stroke_width=stroke_w,
        stroke_fill=(0, 0, 0, int(a * 0.6)),
    )

    # Composite
    out = Image.alpha_composite(im, overlay)
    return out.convert("RGB")  # default to RGB for broad compatibility


def process_one(
    in_path: Path,
    out_path: Path,
    args: argparse.Namespace,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with Image.open(in_path) as im:
        exif = im.info.get("exif")
        icc = im.info.get("icc_profile")

        out_img = add_watermark(
            im,
            text=args.text,
            scale=args.scale,
            opacity=args.opacity,
            margin=args.margin,
            position=args.position,
            font_path=args.font,
            stroke_ratio=args.stroke_ratio,
        )

        # ✨ NEW: Resize if requested
        if args.resize and args.resize > 0:
            # thumbnail resizes in-place and preserves aspect ratio
            out_img.thumbnail((args.resize, args.resize))

        save_kwargs = {}
        dst_ext = out_path.suffix.lower()
        if dst_ext in (".jpg", ".jpeg"):
            # Don’t use subsampling="keep" — it breaks after edits/compositing.
            save_kwargs.update(dict(
                quality=args.quality, # ✨ CHANGED: Use quality from args
                optimize=True,
                progressive=True,
                subsampling=0,   # 0=4:4:4. Remove this line to let Pillow decide.
            ))
            if exif:
                save_kwargs["exif"] = exif
            if icc:
                save_kwargs["icc_profile"] = icc
        elif dst_ext in (".png",):
            # Keep alpha if any operations produced it
            if out_img.mode != "RGBA" and "A" in im.getbands():
                out_img = out_img.convert("RGBA")
        else:
            # TIFF/WEBP etc — keep defaults; still try to preserve ICC when possible
            if icc:
                save_kwargs["icc_profile"] = icc

        # Be robust if any encoder kwarg isn’t supported by the local Pillow build
        try:
            out_img.save(out_path, **save_kwargs)
        except Exception:
            # Retry with safer defaults
            save_kwargs.pop("optimize", None)
            save_kwargs.pop("progressive", None)
            save_kwargs.pop("subsampling", None)
            out_img.save(out_path, **save_kwargs)



def iter_images(root: Path):
    exts = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff"}
    if root.is_file():
        if root.suffix.lower() in exts:
            yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            yield p


# --------- CLI ---------
def main():
    parser = argparse.ArgumentParser(description="Add a subtle text watermark to images.")
    parser.add_argument("input", help="Input image file or folder")
    parser.add_argument("-o", "--output", help="Output file or folder (default: ./watermarked)")
    parser.add_argument("-t", "--text", default="© mbh.photos", help="Watermark text")
    parser.add_argument("--position", default="bottom-right",
                        choices=["bottom-right", "bottom-left", "top-right", "top-left", "center"],
                        help="Watermark position")
    parser.add_argument("--opacity", type=float, default=0.25, help="Watermark opacity (0..1)")
    parser.add_argument("--scale", type=float, default=0.035, help="Font size as fraction of image width")
    parser.add_argument("--margin", type=float, default=0.02, help="Margin as fraction of min(width,height)")
    parser.add_argument("--font", type=str, default=None, help="Path to a .ttf/.otf font file")
    parser.add_argument("--stroke-ratio", type=float, default=0.12, help="Outline thickness relative to font size")
    parser.add_argument("--skip-existing", action="store_true", help="Do not overwrite existing outputs")
    
    # ✨ NEW ARGUMENTS
    parser.add_argument("--resize", type=int, default=None,
                        help="Resize output image so its longest side is N pixels (e.g., 1920)")
    parser.add_argument("--quality", type=int, default=85,
                        help="JPEG save quality (1-100, default: 85)")

    args = parser.parse_args()

    in_path = Path(args.input)
    if args.output:
        out_path = Path(args.output)
    else:
        out_path = Path("./watermarked")

    if in_path.is_file():
        # If output is a folder or omitted, keep name
        if out_path.exists() and out_path.is_dir():
            dst = out_path / in_path.name
        elif out_path.suffix:
            dst = out_path
        else:
            out_path.mkdir(parents=True, exist_ok=True)
            dst = out_path / in_path.name
        if args.skip_existing and dst.exists():
            print(f"SKIP: {dst} already exists")
            return
        process_one(in_path, dst, args)
        print(f"OK  : {in_path} -> {dst}")
        return

    # Folder mode
    out_path.mkdir(parents=True, exist_ok=True)
    for src in iter_images(in_path):
        rel = src.relative_to(in_path)
        dst = out_path / rel
        if args.skip_existing and dst.exists():
            print(f"SKIP: {dst} already exists")
            continue
        process_one(src, dst, args)
        print(f"OK  : {src} -> {dst}")

if __name__ == "__main__":
    main()