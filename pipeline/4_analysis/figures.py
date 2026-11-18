"""
Sleuthline 2.0c - figures of the report, drawn as SVG by the program (no plotting library needed).

attack_graph_svg: the attack path, one box per stage (supported or contested hypotheses, or the key timeline events
when there is no hypothesis), in time order, left to right and row by row, with the host(s), the time, the status
and the confidence. Embedded in Word as SVG (Word 2016+ / 365) with a PNG fallback (blank_png).
"""
from __future__ import annotations

import struct
import zlib
from xml.sax.saxutils import escape

NAVY, ORANGE, AMBER, MUTED, LINE, ZEBRA, INK = "#1A2382", "#BC4A22", "#D9822B", "#6B7089", "#C9D6EA", "#EAF2FA", "#151A3D"
STATUS_COLOR = {("supported", "confirmed"): NAVY, ("supported", "probable"): AMBER, ("supported", "possible"): AMBER,
                ("contested", None): ORANGE, ("open", None): MUTED, ("event", None): NAVY}
FONT = "Inter, Segoe UI, Arial, sans-serif"
W, COLS, BOX_W, GAP, ROW_GAP, TOP = 1000, 3, 290, 65, 54, 20


def wrap(text: str, width: int, max_lines: int) -> list[str]:
    words, lines, cur = str(text).split(), [], ""
    for w in words:
        if len(cur) + len(w) + (1 if cur else 0) <= width:
            cur = f"{cur} {w}" if cur else w
        else:
            if cur:
                lines.append(cur)
            cur = w if len(w) <= width else w[:width - 1] + "…"
        if len(lines) == max_lines:
            break
    if cur and len(lines) < max_lines:
        lines.append(cur)
    if len(lines) == max_lines and " ".join(lines).count(" ") + 1 < len(words):
        lines[-1] = lines[-1][:width - 1].rstrip() + "…"
    return lines


def color_of(node: dict) -> str:
    st = node.get("status")
    return STATUS_COLOR.get((st, node.get("confidence") if st == "supported" else None), MUTED)


def attack_graph_svg(nodes: list[dict]) -> tuple[str, int, int]:
    """nodes: [{id, title, when, hosts, status, confidence, label}] in time order. Returns (svg, width, height)."""
    for n in nodes:
        n["_lines"] = wrap(n.get("title") or "", 40, 4 if n.get("hosts") else 5)
    # box height from the longest text of the figure: no empty boxes, no clipped text
    BOX_H = max(((90 if n.get("hosts") else 74) + len(n["_lines"]) * 17 for n in nodes), default=120) + 8
    rows = (len(nodes) + COLS - 1) // COLS
    height = TOP + rows * BOX_H + (rows - 1) * ROW_GAP + 70
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {height}" width="{W}" height="{height}" '
           f'font-family="{FONT}">',
           '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
           f'<path d="M0,0 L10,5 L0,10 z" fill="{MUTED}"/></marker></defs>',
           f'<rect x="0" y="0" width="{W}" height="{height}" fill="#FFFFFF"/>']
    pos = []
    for i, _ in enumerate(nodes):
        r, c = divmod(i, COLS)
        pos.append((c * (BOX_W + GAP), TOP + r * (BOX_H + ROW_GAP)))
    # arrows first (under the boxes)
    for i in range(len(nodes) - 1):
        (x1, y1), (x2, y2) = pos[i], pos[i + 1]
        if y1 == y2:
            out.append(f'<line x1="{x1 + BOX_W}" y1="{y1 + BOX_H / 2}" x2="{x2 - 4}" y2="{y2 + BOX_H / 2}" stroke="{MUTED}" '
                       'stroke-width="2.2" marker-end="url(#arr)"/>')
        else:
            ym = y1 + BOX_H + ROW_GAP / 2
            out.append(f'<path d="M{x1 + BOX_W / 2},{y1 + BOX_H} L{x1 + BOX_W / 2},{ym} L{x2 + BOX_W / 2},{ym} '
                       f'L{x2 + BOX_W / 2},{y2 - 4}" fill="none" stroke="{MUTED}" stroke-width="2.2" marker-end="url(#arr)"/>')
    for n, (x, y) in zip(nodes, pos):
        col = color_of(n)
        dash = ' stroke-dasharray="6 4"' if n.get("status") in ("contested", "open") or n.get("confidence") in ("probable", "possible") else ""
        out.append(f'<rect x="{x}" y="{y}" width="{BOX_W}" height="{BOX_H}" rx="8" fill="{ZEBRA}" stroke="{col}" stroke-width="2"{dash}/>')
        out.append(f'<path d="M{x},{y + 8} a8,8 0 0 1 8,-8 h{BOX_W - 16} a8,8 0 0 1 8,8 v24 h-{BOX_W} z" fill="{col}"/>')
        out.append(f'<text x="{x + 12}" y="{y + 21}" font-size="14" font-weight="600" fill="#FFFFFF">'
                   f'{escape(str(n.get("label") or ""))}</text>')
        out.append(f'<text x="{x + BOX_W - 12}" y="{y + 21}" font-size="12" fill="#FFFFFF" text-anchor="end">'
                   f'{escape(str(n.get("id") or ""))}</text>')
        out.append(f'<text x="{x + 12}" y="{y + 52}" font-size="12.5" font-weight="600" fill="{NAVY}">'
                   f'{escape(str(n.get("when") or "")[:40])}</text>')
        if n.get("hosts"):
            out.append(f'<text x="{x + 12}" y="{y + 69}" font-size="11.5" fill="{MUTED}">{escape(", ".join(n["hosts"])[:44])}</text>')
        ty = y + (90 if n.get("hosts") else 74)
        for k, line in enumerate(n.pop("_lines")):
            out.append(f'<text x="{x + 12}" y="{ty + k * 17}" font-size="13" fill="{INK}">{escape(line)}</text>')
    # legend
    ly = height - 34
    items = [(NAVY, "", "supported, confirmed"), (AMBER, ' stroke-dasharray="6 4"', "supported, probable"),
             (ORANGE, ' stroke-dasharray="6 4"', "contested (a contradiction was found)")]
    x = 0
    for col, dash, label in items:
        out.append(f'<rect x="{x}" y="{ly}" width="26" height="16" rx="3" fill="{ZEBRA}" stroke="{col}" stroke-width="2"{dash}/>')
        out.append(f'<text x="{x + 34}" y="{ly + 13}" font-size="12.5" fill="{MUTED}">{escape(label)}</text>')
        x += 34 + 8 * len(label) + 30
    out.append("</svg>")
    return "".join(out), W, height


def blank_png(width: int, height: int) -> bytes:
    """White PNG (fallback image of an SVG for the readers that cannot display SVG)."""
    width, height = max(1, int(width)), max(1, int(height))
    raw = b"".join(b"\x00" + b"\xff" * (width * 3) for _ in range(height))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
