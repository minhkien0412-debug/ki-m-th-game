#!/usr/bin/env python3
"""Sinh bản vẽ SVG có kích thước (native shapes, currentColor) từ design_info.json — dùng cho trang spec."""
import json, os

S = 4.0          # px / mm
ACC = "var(--acc)"
WARN = "var(--warn)"
HALO = ' paint-order="stroke" stroke="var(--surface)" stroke-width="3" stroke-linejoin="round"'


def load(layout):
    return json.load(open(os.path.join("out", layout, "design_info.json"), encoding="utf-8"))


class Draw:
    def __init__(self, W, H, ox, oy):
        self.W, self.H, self.ox, self.oy = W, H, ox, oy
        self.el = []

    def P(self, x, y):
        return (self.ox + x * S, self.oy - y * S)

    def rect(self, cx, cy, w, h, r=0, fill="none", sw=1.2, dash=None, stroke="currentColor"):
        x0, y0 = self.P(cx - w / 2, cy + h / 2)
        d = ' stroke-dasharray="%s"' % dash if dash else ""
        self.el.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="%.1f" fill="%s" stroke="%s" stroke-width="%s"%s/>' %
                       (x0, y0, w * S, h * S, r * S, fill, stroke, sw, d))

    def rrect_body(self, w, h, rt, rb, fill="none", sw=1.6):
        hw, hh = w / 2, h / 2
        p = self.P
        arc = lambda r, x, y: " A%.1f %.1f 0 0 0 %.1f %.1f" % ((r * S, r * S) + p(x, y))
        path = "M%.1f %.1f" % p(-hw + rb, -hh)
        path += " L%.1f %.1f" % p(hw - rb, -hh) + arc(rb, hw, -hh + rb)
        path += " L%.1f %.1f" % p(hw, hh - rt) + arc(rt, hw - rt, hh)
        path += " L%.1f %.1f" % p(-hw + rt, hh) + arc(rt, -hw, hh - rt)
        path += " L%.1f %.1f" % p(-hw, -hh + rb) + arc(rb, -hw + rb, -hh) + " Z"
        self.el.append('<path d="%s" fill="%s" stroke="currentColor" stroke-width="%s"/>' % (path, fill, sw))

    def circle(self, cx, cy, d, fill="none", sw=1.2, stroke="currentColor", dash=None):
        x, y = self.P(cx, cy)
        dd = ' stroke-dasharray="%s"' % dash if dash else ""
        self.el.append('<circle cx="%.1f" cy="%.1f" r="%.1f" fill="%s" stroke="%s" stroke-width="%s"%s/>' % (x, y, d / 2 * S, fill, stroke, sw, dd))

    def cross(self, cx, cy, s=1.5):
        x, y = self.P(cx, cy)
        self.el.append('<path d="M%.1f %.1f h%.1f M%.1f %.1f v%.1f" stroke="currentColor" stroke-width="0.8"/>' % (x - s * S / 2, y, s * S, x, y - s * S / 2, s * S))

    def text(self, x, y, t, size=11, anchor="middle", fill="currentColor", weight="", mono=True, halo=False, dx=0, dy=0):
        px, py = self.P(x, y)
        fam = "var(--mono)" if mono else "var(--sans)"
        w = ' font-weight="%s"' % weight if weight else ""
        self.el.append('<text x="%.1f" y="%.1f" font-size="%s" font-family="%s" text-anchor="%s" fill="%s"%s%s>%s</text>' %
                       (px + dx, py + dy + size * 0.35, size, fam, anchor, fill, w, HALO if halo else "", t))

    def _dimline(self, a, b, color):
        self.el.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1" marker-start="url(#da)" marker-end="url(#da)"/>' % (a[0], a[1], b[0], b[1], color))

    def dim_h(self, x0, x1, y, label, color=ACC, size=10.5, below=False):
        a, b = self.P(x0, y), self.P(x1, y)
        self._dimline(a, b, color)
        for x in (x0, x1):
            p = self.P(x, y)
            self.el.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="0.7"/>' % (p[0], p[1] - 6, p[0], p[1] + 6, color))
        self.text((x0 + x1) / 2, y, label, size=size, fill=color, halo=True, dy=(13 if below else -6))

    def dim_v(self, y0, y1, x, label, color=ACC, size=10.5, side=1):
        """side=1: nhãn bên trái đường dóng, -1: bên phải"""
        a, b = self.P(x, y0), self.P(x, y1)
        self._dimline(a, b, color)
        for y in (y0, y1):
            p = self.P(x, y)
            self.el.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="0.7"/>' % (p[0] - 6, p[1], p[0] + 6, p[1], color))
        px, py = self.P(x, (y0 + y1) / 2)
        tx = px - 9 * side
        self.el.append('<text x="%.1f" y="%.1f" font-size="%s" font-family="var(--mono)" text-anchor="middle" fill="%s" transform="rotate(-90 %.1f %.1f)"%s>%s</text>' %
                       (tx, py + size * 0.35, size, color, tx, py + size * 0.35, HALO, label))

    def leader(self, x, y, tx, ty, label, color=WARN, size=10.5, anchor="start"):
        a, b = self.P(x, y), self.P(tx, ty)
        self.el.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="0.9"/>' % (a[0], a[1], b[0], b[1], color))
        self.el.append('<circle cx="%.1f" cy="%.1f" r="1.8" fill="%s"/>' % (a[0], a[1], color))
        self.text(tx + (0.8 if anchor == "start" else -0.8), ty, label, size=size, anchor=anchor, fill=color, mono=False, halo=True)

    def svg(self, label):
        defs = ('<defs><marker id="da" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
                '<path d="M0 2 L10 5 L0 8 z" fill="context-stroke"/></marker></defs>')
        return ('<svg viewBox="0 0 %d %d" role="img" aria-label="%s" xmlns="http://www.w3.org/2000/svg" '
                'style="max-width:100%%;height:auto;display:block">%s%s</svg>' % (self.W, self.H, label, defs, "".join(self.el)))


def front_drawing(layout):
    d = load(layout)
    W, L = d["body"]["w"], d["body"]["l"]
    hw, hl = W / 2, L / 2
    D = Draw(int(W * S + 660), int(L * S + 150), 370, 66 + hl * S)
    D.rrect_body(W, L, d["body"]["r_top"], d["body"]["r_bot"], fill="var(--surface)")
    cx, cy = d["display"]["center"]; ww, wh = d["display"]["window"]; pw, ph = d["display"]["pocket"]
    D.rect(cx, cy, pw, ph, 0.5, dash="4 3", sw=0.8, stroke="var(--muted)")
    D.rect(cx, cy, ww, wh, 1, fill="var(--screen)", sw=1.2)
    D.cross(cx, cy, 3)
    D.text(cx, cy - 4, "active 49 × 37", size=10, fill="var(--muted)")
    keys = d["mx"]["keys"]
    for i, (x, y) in enumerate(keys):
        D.rect(x, y, 18, 18, 1, dash="3 3", sw=0.7, stroke="var(--muted)")
        D.rect(x, y, d["mx"]["cut"], d["mx"]["cut"], 0, fill="var(--mxfill)", sw=1.2)
        D.text(x, y, d["mx"]["labels"][i], size=13, mono=False, weight="600")
    cols = d["keypad"]["cols_x"]; rows = d["keypad"]["rows_y"]
    for y in rows:
        for x in cols:
            D.circle(x, y, d["keypad"]["hole_d"], fill="var(--keyfill)")
    for (x, y) in d["screws"]["m2_positions"] + d["screws"]["m25_through_pi"]:
        D.circle(x, y, 2.4, dash="1.5 1.5", sw=0.7, stroke="var(--muted)")
    # --- kích thước ---
    D.dim_h(-hw, hw, hl + 8, "77.0")
    D.dim_v(-hl, hl, -hw - 44, "165.5")
    D.dim_v(0, cy, -hw - 14, "%.0f" % cy)
    D.dim_h(cx - ww / 2, cx + ww / 2, cy + wh / 2 + 4, "%.1f" % ww, size=10)
    D.dim_v(cy - wh / 2, cy + wh / 2, cx + ww / 2 + 5, "%.1f" % wh, side=-1, size=10)
    xs = sorted(set(k[0] for k in keys)); ys = sorted(set(k[1] for k in keys))
    if len(ys) == 2:   # split: chuỗi kích thước bên trái  -30 -> -5 -> 0 -> 14
        D.dim_v(ys[0], ys[1], xs[1] - 12, "19.0", side=-1, size=10)
        D.dim_h(xs[0], xs[1], ys[1] + 12, "%.0f" % (xs[1] - xs[0]), size=10)
        D.dim_v(rows[0], ys[0], -hw - 28, "%.0f" % (ys[0] - rows[0]), size=10)
        D.dim_v(ys[0], 0, -hw - 28, "%.0f" % -ys[0], size=10)
        D.dim_v(0, ys[1], -hw - 28, "%.0f" % ys[1], size=10)
        D.dim_h(0, xs[1], ys[0] - 12, "%.1f" % xs[1], size=10)
        D.leader(xs[1] + 7, ys[1] - 7, hw + 6, ys[1] - 16, "lỗ MX 14 × 14, plate 1.5, pitch 19", color=ACC)
    else:              # row
        D.dim_h(xs[0], xs[1], ys[0] - 13, "19.0", size=10)
        D.dim_v(rows[0], 0, -hw - 28, "%.0f" % -rows[0], size=10)
        D.dim_v(0, ys[0], -hw - 28, "%.0f" % ys[0], size=10)
        D.dim_h(0, xs[-1], ys[0] - 13, "%.1f" % xs[-1], size=10)
        D.leader(xs[-1] + 7, ys[0] + 7, hw + 6, ys[0] + 16, "lỗ MX 14 × 14, plate 1.5, pitch 19", color=ACC)
    D.dim_h(cols[0], cols[1], rows[0] + 8, "11.0", size=10)
    D.dim_v(rows[1], rows[0], (cols[2] + cols[3]) / 2, "13.0", side=-1, size=10)
    D.dim_h(cols[0], cols[-1], rows[-1] - 8, "%.0f" % (cols[-1] - cols[0]), size=10)
    D.leader(hw - 1.2, hl - 1.2, hw + 6, hl - 10, "R4", color=ACC)
    D.leader(hw - 2.6, -hl + 2.6, hw + 6, -hl + 12, "R9", color=ACC)
    D.leader(cx + pw / 2, cy - ph / 2 + 4, hw + 6, cy - ph / 2 - 3, "hộc module 60.5 × 43 × 4.6 — đo lại PCB", color=WARN)
    D.leader(cols[-1] + 2.5, rows[-1] + 1.5, hw + 6, rows[-1] + 10, "lỗ Ø6.0 · nút Ø5.5, vành Ø8", color=ACC)
    D.text(0, -hl - 14, "MẶT TRƯỚC — nhìn từ ngoài · mm · tâm (0,0) giữa máy, +Y lên đỉnh · vòng đứt = boss ốc phía trong", size=10.5, fill="var(--muted)", mono=False)
    return D.svg("Bản vẽ mặt trước có kích thước: cửa sổ màn hình, lỗ phím cơ, lưới phím tròn, bo góc")


def back_drawing(layout):
    d = load(layout)
    W, L = d["body"]["w"], d["body"]["l"]
    hw, hl = W / 2, L / 2
    D = Draw(int(W * S + 660), int(L * S + 150), 370, 66 + hl * S)
    D.rrect_body(W, L, d["body"]["r_top"], d["body"]["r_bot"], fill="var(--surface)")
    wall = 2.0
    D.rrect_body(W - 2 * wall, L - 2 * wall, d["body"]["r_top"] - wall, d["body"]["r_bot"] - wall, sw=0.7)
    pi = d["pi"]
    pcx, pcy = (pi["x"][0] + pi["x"][1]) / 2, (pi["y"][0] + pi["y"][1]) / 2
    D.rect(pcx, pcy, 65, 30, 1, dash="4 3", sw=0.8, stroke="var(--muted)")
    for (x, y) in pi["holes"]:
        D.circle(x, y, 2.75, sw=0.6, stroke="var(--muted)")
    am = d["amp"]; ax, ay = am["center"]
    D.rect(ax, ay, am["size"][0], am["size"][1], 0, fill="var(--ampfill)", sw=1.0)
    D.text(ax, ay, "amp", size=10, mono=False)
    D.text(ax + am["size"][0] / 2 + 2, pcy + 9, "Pi Zero 2 W (bóng)", size=9.5, mono=False, fill="var(--muted)", anchor="start")
    b = d["battery"]; bx0, bx1 = b["bay_x"]; by0, by1 = b["bay_y"]
    bcx, bcy = (bx0 + bx1) / 2, (by0 + by1) / 2
    D.rect(bcx, bcy, bx1 - bx0 + 2.4, by1 - by0 + 2.4, 0, sw=1.0)
    D.rect(bcx, bcy, bx1 - bx0, by1 - by0, 0, fill="var(--batfill)", sw=1.2)
    D.text(bcx, bcy + 3, "hộc pin", size=11, mono=False)
    D.text(bcx, bcy - 3, "35 × 52 × 10.5", size=10.5)
    h = d["header_press_ridge"]; hx, hy = h["center"]; hl_, hw_ = h["size"][0], h["size"][1]
    D.rect(hx, hy, hl_, hw_, 0, fill="var(--ridgefill)", sw=1.2)
    for x in h["cols_x"]:
        for y in h["rows_y"]:
            D.circle(x, y, 1.3, sw=0.5)
    sp = d["speaker"]; sx, sy = sp["center"]
    D.circle(sx, sy, sp["d"], fill="var(--spkfill)", sw=1.2)
    n, sw_, sl, pitch = sp["slits"]
    for i in range(n):
        D.rect(sx + (i - (n - 1) / 2) * pitch, sy, sw_, sl, 0, fill="var(--surface)", sw=0.6)
    ch = d["charger"]; cx, cy = ch["center"]
    D.rect(cx, cy, ch["size"][0], ch["size"][1], 0, fill="var(--chgfill)", sw=1.2)
    D.text(cx, cy, "sạc + tăng áp", size=10, mono=False)
    D.rect(cx, -hl + 1, ch["typec_slot"][0], 2.0, 1, fill="var(--surface)", sw=0.8)
    for (x, y) in d["screws"]["m2_positions"]:
        D.circle(x, y, 5.5, sw=0.8); D.circle(x, y, 2.4, sw=0.6)
    for (x, y) in d["screws"]["m25_through_pi"]:
        D.circle(x, y, 5.5, sw=0.8, stroke=WARN); D.circle(x, y, 2.7, sw=0.6, stroke=WARN)
    # --- kích thước ---
    D.dim_h(bx0, bx1, by1 + 9, "35.0")
    D.dim_v(by0, by1, bx1 + 8, "52.0", side=-1)
    D.cross(bcx, bcy, 3)
    D.text(bcx, bcy - 9, "tâm (0, %.1f)" % bcy, size=10, fill="var(--muted)")
    D.dim_h(hx - hl_ / 2, hx + hl_ / 2, hy - 7, "51.5 · tâm x = %.1f" % hx)
    D.dim_v(hy - hw_ / 2, hy + hw_ / 2, hx + hl_ / 2 + 6, "5.0", side=-1, size=10)
    D.dim_v(0, hy, hw + 12, "%.2f" % hy, side=-1, size=10)
    D.dim_v(sy, 0, -hw - 28, "%.0f" % -sy, size=10)
    D.dim_h(sx, 0, sy + sp["d"] / 2 + 6, "%.0f" % -sx, size=10)
    D.dim_h(0, cx, cy + ch["size"][1] / 2 + 6, "%.0f" % cx, size=10)
    D.leader(hx + 12, hy + hw_ / 2, hw + 6, hy + 12, "gờ ép header 51.5 × 5 × 2.96 · 40 lỗ Ø1.3 sâu 3.0", color=ACC)
    D.leader(cx + ch["size"][0] / 2, -hl + 1, hw + 6, -hl + 8, "Type-C 9.5 × 3.5, tâm z 5.2 (cạnh đáy)", color=ACC)
    D.leader(sx - 9, sy + 9, -hw - 8, sy + 24, "loa Ø28 · 5 khe 1.5 × 10", color=ACC, anchor="end")
    D.leader(d["screws"]["m25_through_pi"][1][0] - 2.7, d["screws"]["m25_through_pi"][1][1], -hw - 8, hl - 4, "M2.5 xuyên lỗ Pi", color=WARN, anchor="end")
    D.leader(cx - ch["size"][0] / 2, cy - 4, -hw - 8, cy - 16, "sạc IP5306 28 × 20 — đo lại", color=WARN, anchor="end")
    D.text(0, -hl - 14, "NẮP LƯNG — mặt trong, nhìn từ phía trước xuyên xuống (trục X trùng tờ 1) · mm", size=10.5, fill="var(--muted)", mono=False)
    return D.svg("Bản vẽ mặt trong nắp lưng: hộc pin, gờ ép header, loa, module sạc, vị trí ốc")


def section_drawing(layout):
    d = load(layout)
    T = d["body"]["t"]
    S2 = 19.0
    W, H = 1000, 580
    x0 = 150
    X = lambda z: x0 + z * S2
    el = []
    rows_y = [70, 240, 410]
    names = ["A · màn hình / Pi", "B · phím cơ + pin", "C · bàn phím Casio"]
    outside_count = [0, 0, 0]

    def layer(row, z0, z1, label, fill):
        y = rows_y[row]
        w = (z1 - z0) * S2
        el.append('<rect x="%.1f" y="%d" width="%.1f" height="64" fill="%s" stroke="currentColor" stroke-width="0.8"/>' % (X(z0), y, w, fill))
        xm = X((z0 + z1) / 2)
        if w >= 6.3 * len(label) + 8:
            el.append('<text x="%.1f" y="%d" font-size="10.5" font-family="var(--sans)" text-anchor="middle" fill="currentColor">%s</text>' % (xm, y + 36, label))
        else:
            k = outside_count[row]; outside_count[row] += 1
            up = (k % 2 == 0)
            ty = y - 10 - 12 * (k // 2) if up else y + 64 + 16 + 12 * (k // 2)
            ly = y if up else y + 64
            el.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%.1f" stroke="var(--muted)" stroke-width="0.7"/>' % (xm, ly, xm, ty + (4 if up else -9)))
            el.append('<text x="%.1f" y="%.1f" font-size="9.5" font-family="var(--sans)" text-anchor="middle" fill="currentColor"%s>%s</text>' % (xm, ty, HALO, label))

    h = d["header_press_ridge"]; pi = d["pi"]; disp = d["display"]; b = d["battery"]; kp = d["keypad"]
    layer(0, 0, 2, "lưng 2", "var(--shellfill)")
    layer(0, 2, h["z"][1], "gờ ép 2.96", "var(--ridgefill)")
    layer(0, h["z"][1], pi["pcb_z"][0], "đế header 2.54", "var(--ridgefill)")
    layer(0, pi["pcb_z"][0], pi["pcb_z"][1], "PCB Pi 1.5", "var(--pcbfill)")
    layer(0, pi["pcb_z"][1], pi["components_z"][1], "linh kiện 3.5", "var(--pcbfill)")
    layer(0, pi["components_z"][1], h["long_pin_tip_z"], "kim dài → 13.5", "var(--ridgefill)")
    layer(0, h["display_bottom_z"], disp["module_z"][1], "màn hình 4.5", "var(--screen)")
    layer(0, T - disp["bezel_t"], T, "bezel 1.5", "var(--shellfill)")
    layer(1, 0, 2, "lưng 2", "var(--shellfill)")
    layer(1, 2, b["bay_z"][1], "hộc pin 10.5 (pin 10)", "var(--batfill)")
    layer(1, T - 1.5 - 5 - 3.3, T - 1.5 - 5, "chân MX 3.3", "var(--mxfill)")
    layer(1, T - 1.5 - 5, T - 1.5, "thân switch 5.0", "var(--mxfill)")
    layer(1, T - 1.5, T, "plate 1.5", "var(--shellfill)")
    layer(2, 0, 2, "lưng 2", "var(--shellfill)")
    layer(2, 2, 7, "loa 5", "var(--spkfill)")
    layer(2, kp["pcb_z"][0], kp["pcb_z"][1], "board 1.6", "var(--pcbfill)")
    layer(2, kp["tactile_z"][0], kp["tactile_z"][1], "tactile 4.3", "var(--keyfill)")
    layer(2, T - 3, T - 2, "vành 1", "var(--keyfill)")
    layer(2, T - 2, T, "mặt 2", "var(--shellfill)")
    for name, y in zip(names, rows_y):
        el.append('<text x="14" y="%d" font-size="11.5" font-family="var(--sans)" font-weight="600" fill="currentColor">%s</text>' % (y + 36, name))
    zy = 522
    el.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="currentColor" stroke-width="1"/>' % (X(0), zy, X(T), zy))
    for z in [0, 2, 4.96, 7.5, 9, 12.5, 13.9, 15, 18.5, 20]:
        el.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="currentColor" stroke-width="0.8"/>' % (X(z), zy - 4, X(z), zy + 4))
        el.append('<text x="%.1f" y="%d" font-size="9.5" font-family="var(--mono)" text-anchor="end" fill="var(--acc)" transform="rotate(-55 %.1f %d)">%s</text>' % (X(z) + 3, zy + 20, X(z) + 3, zy + 20, ("%g" % z)))
    el.append('<text x="%.1f" y="%d" font-size="10.5" font-family="var(--sans)" text-anchor="middle" fill="var(--muted)">z (mm) từ mặt lưng ngoài (0) tới mặt trước ngoài (20) · mặt phân khuôn z = 7.5</text>' % (X(T / 2), zy + 46))
    el.append('<line x1="%.1f" y1="14" x2="%.1f" y2="%d" stroke="var(--warn)" stroke-width="1" stroke-dasharray="5 3"/>' % (X(7.5), X(7.5), zy - 8))
    el.append('<text x="%.1f" y="16" font-size="10" font-family="var(--sans)" text-anchor="start" fill="var(--warn)"%s>phân khuôn z 7.5</text>' % (X(7.5) + 5, HALO))
    return ('<svg viewBox="0 0 %d %d" role="img" aria-label="Mặt cắt chồng lớp theo chiều dày ở ba vùng của máy" xmlns="http://www.w3.org/2000/svg" style="max-width:100%%;height:auto;display:block">%s</svg>' % (W, H, "".join(el)))


PALETTE = {"var(--acc)": "#1F5FBF", "var(--warn)": "#B8620A", "var(--muted)": "#6B7280", "var(--surface)": "#fff",
           "var(--screen)": "#BFD7F5", "var(--mxfill)": "#F4C7B5", "var(--keyfill)": "#E5E7EB", "var(--batfill)": "#F7E3A1",
           "var(--ridgefill)": "#D9D4C7", "var(--spkfill)": "#CBD5E1", "var(--chgfill)": "#F5B8B8", "var(--ampfill)": "#C7CFF7",
           "var(--pcbfill)": "#BFE3C9", "var(--shellfill)": "#D1D5DB", "var(--mono)": "monospace", "var(--sans)": "sans-serif"}

if __name__ == "__main__":
    out = {}
    for L in ("split", "row"):
        out["front_" + L] = front_drawing(L)
        out["back_" + L] = back_drawing(L)
    out["section"] = section_drawing("split")
    json.dump(out, open("drawings.json", "w", encoding="utf-8"), ensure_ascii=False)
    for k, v in out.items():
        s = v
        for a, b_ in PALETTE.items():
            s = s.replace(a, b_)
        open("out/drawing_%s.svg" % k, "w", encoding="utf-8").write(s)
    print("drawings:", {k: len(v) for k, v in out.items()})
