#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
casio_handheld.py — Vỏ máy chơi game cầm tay kiểu Casio fx-580VN X (FNF + Geometry Dash)
=========================================================================================
Mô hình THAM SỐ dựng bằng CadQuery (Python). Chạy:

    python3 casio_handheld.py                 # xuất bố cục mặc định (split) vào ./out/split
    python3 casio_handheld.py --layout row    # 4 phím cơ nằm ngang hàng   -> ./out/row
    python3 casio_handheld.py --layout all    # cả hai

Xuất ra: STEP (mở trong Fusion 360 / SolidWorks / FreeCAD), STL (in 3D, đã xoay đúng
hướng in), assembly STEP (vỏ + linh kiện tham chiếu) và bản vẽ SVG.

HỆ TOẠ ĐỘ: X = chiều rộng (phải +), Y = chiều dài (đỉnh máy +), Z = chiều dày.
           z = 0 là MẶT LƯNG ngoài, z = T là MẶT TRƯỚC ngoài. Tâm máy tại (0, 0).
Mọi kích thước tính bằng mm.
"""
import argparse
import json
import math
import os
import sys

import cadquery as cq
from cadquery import exporters

# =============================================================================
# 1. THAM SỐ THIẾT KẾ  (sửa ở đây, chạy lại là ra file mới)
# =============================================================================
P = dict(
    # ---- Vỏ ngoài — form factor Casio fx-580VN X / fx-991EX ----
    body_w=77.0,            # chiều rộng
    body_l=165.5,           # chiều dài
    T=20.0,                 # chiều dày tổng (Casio gốc 11.1 mm thân / 13.8 mm kèm nắp; 20.0 do chồng lớp header ép + màn hình)
    r_top=4.0,              # bo góc 2 góc đỉnh (R3–R5)
    r_bot=9.0,              # bo góc 2 góc đáy  (R8–R10)
    wall=2.0,               # dày thành bên
    face_t=2.0,             # dày mặt trước (vùng phím)
    back_t=2.0,             # dày nắp lưng
    fillet_front=2.0,       # bo mép mặt trước
    fillet_back=2.5,        # bo mép mặt lưng (cầm êm tay)
    split_z=7.5,            # mặt phân khuôn nắp trước / nắp lưng (đo từ mặt lưng ngoài)
    lip_h=2.0, lip_t=1.0,   # gờ định vị (lip) trên nắp lưng
    tol=0.25,               # dung sai khớp âm–dương cho PLA (0.25–0.30)

    # ---- Màn hình 2.4" SPI 240x320 (ILI9341 / ST7789) ----
    disp_c=(0.0, 56.0),         # tâm vùng hiển thị
    disp_active=(49.0, 37.0),   # active area 48.96 x 36.72 mm (pitch 0.153 mm)
    disp_win_clear=0.3,         # mỗi bên, cửa sổ = active + 2*clear
    disp_pcb=(60.0, 42.5),      # KÍCH THƯỚC PCB MODULE — ĐO LẠI BẰNG THƯỚC KẸP THEO MODULE THẬT
    disp_t=4.5,                 # dày module (không header; hàn dây thẳng vào pad)
    disp_pocket_clear=0.25,     # mỗi bên
    disp_pocket_extra=0.1,      # dư chiều sâu hộc
    bezel_t=1.5,                # mặt trước mỏng 1.5 mm quanh cửa sổ (gờ đỡ màn hình)
    disp_rim_t=1.2, disp_rim_h=4.0,   # gờ định vị quanh hộc màn hình, mặt trong

    # ---- Cụm phím cơ Cherry MX (FNF) ----
    mx_cut=14.0,            # lỗ khoét chuẩn MX 14 x 14
    mx_plate_t=1.5,         # plate đúng 1.5 mm để lẫy switch ngậm
    mx_pocket=16.0,         # hốc mặt trong quanh lỗ để plate còn đúng 1.5 mm
    mx_pitch=19.0,          # pitch tâm–tâm (chuẩn 19.05; keycap 1u = 18.0)

    # ---- Bàn phím "Casio" (tactile 6x6x4.3 + keycap in 3D) ----
    key_hole_d=6.0,         # lỗ khoét tròn
    key_cap_d=5.5,          # đường kính nút in
    key_cap_proud=1.5,      # nút nhô khỏi mặt máy
    key_flange_d=8.0, key_flange_t=1.0,   # vành giữ dưới mặt máy (nút không rơi ra ngoài)
    key_pitch_x=11.0, key_pitch_y=13.0,   # 11 ngang x 13 dọc (yêu cầu). Perfboard 2.54: đổi thành 10.16 x 12.70
    key_cols=6,
    tact_h=4.3,             # cao switch tactile 6x6x4.3 (thân 3.5 + cần 0.8)
    perf_t=1.6,             # dày board phím

    # ---- Pin Li-Po 103450 (10 x 34 x 50 mm) — hộc theo yêu cầu 35.0 x 52.0 x 10.5 ----
    bat=(34.0, 50.0, 10.0),
    bat_bay=(35.0, 52.0, 10.5),
    bat_rib_t=1.2,

    # ---- Raspberry Pi Zero 2 W (cũng đúng cho Radxa Zero 3W / Orange Pi Zero 2W: 65 x 30) ----
    pi=(65.0, 30.0, 1.5),   # PCB
    pi_comp_h=3.5,          # cao linh kiện (mặt linh kiện quay về lưng)
    pi_hole_inset=3.5,      # lỗ M2.5 cách mép 3.5 mm -> khoảng cách lỗ 58 x 23
    pi_gap_top=1.75,        # cách thành trên (cạnh cổng HDMI/USB)
    pi_hdr_rows=(3.5, 6.04),    # 2 hàng lỗ GPIO cách cạnh dài (phía đối diện cổng) — KIỂM TRA LẠI THEO BẢN VẼ PI
    pi_pin_clear=0.4,       # khe hở đầu kim dài <-> lưng module màn hình

    # ---- Header 2x20 KHÔNG HÀN, ép bằng gờ nhựa trên nắp lưng (yêu cầu) ----
    hdr_len=51.5, hdr_w=5.0,        # gờ nhựa đặc 51.5 x 5.0 (đế header thật 50.8 x 5.08)
    hdr_base_t=2.54,                # dày đế nhựa đen
    hdr_pin_long=6.0, hdr_pin_short=3.0,   # kim dài cắm vào lỗ Pi, kim ngắn 3 mm quay về gờ
    hdr_hole_d=1.3, hdr_hole_depth=3.0,    # 40 lỗ trên đỉnh gờ cho đầu kim (kim 0.64 vuông, chéo 0.9)
    hdr_preload=0.0,                # >0 = gờ cao thêm để ép có lực (0.2 mm hợp lý); 0 = vừa chạm

    # ---- Loa / nguồn / âm thanh ----
    spk_d=28.0, spk_h=5.0,
    spk_slits=5, spk_slit_w=1.5, spk_slit_l=10.0, spk_slit_pitch=3.5,
    charger=(28.0, 20.0, 1.6),   # module sạc + tăng áp 5V (IP5306 Type-C) — đo lại theo module thật
    typec_slot=(9.5, 3.5),       # lỗ Type-C hình elip/stadium
    amp=(17.0, 20.0, 3.0),       # MAX98357A I2S
    sw_slot=(4.0, 2.0),          # lỗ công tắc gạt SS12D00

    # ---- Ốc vít ----
    m2_pilot=1.7, m2_clear=2.4, m2_cb=4.6,       # M2 tự ren vào boss PLA
    m25_pilot=2.05, m25_clear=2.7, m25_cb=5.2,   # M2.5 xuyên lỗ Pi
    boss_od=5.0, boss_back_od=5.5, cb_depth=1.0,
)

LAYOUTS = {
    # 2 cặp phím dọc hai bên (kiểu D-pad / nút A-B) — mặc định
    "split": dict(
        mx_keys=[(-27.5, 14.0), (-27.5, -5.0), (27.5, 14.0), (27.5, -5.0)],
        mx_labels=["←", "↓", "↑", "→"],
        bat_c=(0.0, 1.5),                 # hộc pin nằm giữa hai cụm phím cơ
        bat_ribs_y=(8.0, -12.0),          # gân đè pin trên nắp trước
        key_rows=[-30.0, -43.0, -56.0, -69.0],
        bosses_side=[(32.0, 29.0), (-32.0, 29.0), (32.0, -20.0), (-32.0, -20.0)],
    ),
    # 4 phím cơ nằm ngang một hàng (kiểu DFJK trên PC)
    "row": dict(
        mx_keys=[(-28.5, 22.0), (-9.5, 22.0), (9.5, 22.0), (28.5, 22.0)],
        mx_labels=["←", "↓", "↑", "→"],
        bat_c=(0.0, -10.7),               # hộc pin nằm dưới hàng phím cơ (y -36.7 .. 15.3)
        bat_ribs_y=(-2.0, -22.0),
        key_rows=[-42.0, -55.0, -68.0],
        bosses_side=[(33.5, 40.0), (-33.5, 40.0), (32.0, -20.0), (-32.0, -20.0)],
    ),
}

# =============================================================================
# 2. HÀM DỰNG HÌNH CƠ BẢN
# =============================================================================
S2 = 1.0 / math.sqrt(2.0)


def rrect(w, l, r_top, r_bot, z=0.0):
    """Biên dạng chữ nhật bo góc, bán kính đỉnh/đáy khác nhau, tâm tại gốc, nằm ở cao độ z."""
    hw, hl = w / 2.0, l / 2.0
    wp = cq.Workplane("XY", origin=(0, 0, z)).moveTo(-hw + r_bot, -hl).lineTo(hw - r_bot, -hl)
    if r_bot > 1e-3:
        c = (hw - r_bot, -hl + r_bot)
        wp = wp.threePointArc((c[0] + r_bot * S2, c[1] - r_bot * S2), (hw, -hl + r_bot))
    wp = wp.lineTo(hw, hl - r_top)
    if r_top > 1e-3:
        c = (hw - r_top, hl - r_top)
        wp = wp.threePointArc((c[0] + r_top * S2, c[1] + r_top * S2), (hw - r_top, hl))
    wp = wp.lineTo(-hw + r_top, hl)
    if r_top > 1e-3:
        c = (-hw + r_top, hl - r_top)
        wp = wp.threePointArc((c[0] - r_top * S2, c[1] + r_top * S2), (-hw, hl - r_top))
    wp = wp.lineTo(-hw, -hl + r_bot)
    if r_bot > 1e-3:
        c = (-hw + r_bot, -hl + r_bot)
        wp = wp.threePointArc((c[0] - r_bot * S2, c[1] - r_bot * S2), (-hw + r_bot, -hl))
    return wp.close()


def prism(w, l, r_top, r_bot, z0, z1, cx=0.0, cy=0.0):
    return rrect(w, l, r_top, r_bot, z0).extrude(z1 - z0).translate((cx, cy, 0))


def box(x0, x1, y0, y1, z0, z1):
    return (cq.Workplane("XY").box(x1 - x0, y1 - y0, z1 - z0, centered=(False, False, False))
            .translate((x0, y0, z0)))


def cbox(cx, cy, w, l, z0, z1):
    return box(cx - w / 2, cx + w / 2, cy - l / 2, cy + l / 2, z0, z1)


def cyl(cx, cy, z0, z1, d):
    return cq.Workplane("XY", origin=(cx, cy, z0)).circle(d / 2.0).extrude(z1 - z0)


def slot_wall_x(cx, cz, y, L, D, depth=6.0):
    """Rãnh stadium nằm ngang trong thành vuông góc trục Y (thành đỉnh/đáy)."""
    return cq.Workplane("XZ", origin=(cx, y, cz)).slot2D(L, D, 0).extrude(depth / 2, both=True)


def rect_wall_x(cx, cz, y, W, H, depth=6.0):
    return cq.Workplane("XZ", origin=(cx, y, cz)).rect(W, H).extrude(depth / 2, both=True)


def rect_wall_y(cy, cz, x, W, H, depth=6.0):
    """Lỗ chữ nhật trong thành vuông góc trục X (thành trái/phải)."""
    return cq.Workplane("YZ", origin=(x, cy, cz)).rect(W, H).extrude(depth / 2, both=True)


def vol(shape):
    try:
        return shape.val().Volume()
    except Exception:
        return 0.0


# =============================================================================
# 3. DỰNG MÔ HÌNH
# =============================================================================
def build(layout_name):
    L = LAYOUTS[layout_name]
    W, BL, T = P["body_w"], P["body_l"], P["T"]
    wall, face_t, back_t = P["wall"], P["face_t"], P["back_t"]
    split = P["split_z"]
    face_in = T - face_t                      # mặt trong của mặt trước
    r_top, r_bot = P["r_top"], P["r_bot"]
    hw, hl = W / 2, BL / 2
    in_w, in_l = W - 2 * wall, BL - 2 * wall  # lòng trong
    in_hw, in_hl = in_w / 2, in_l / 2

    info = {}   # số liệu dẫn xuất để in ra / viết tài liệu

    # ------------------------------------------------------------- vị trí linh kiện
    dcx, dcy = P["disp_c"]
    aw, ah = P["disp_active"]
    win_w, win_h = aw + 2 * P["disp_win_clear"], ah + 2 * P["disp_win_clear"]
    pw, ph = P["disp_pcb"]
    pk_w, pk_h = pw + 2 * P["disp_pocket_clear"], ph + 2 * P["disp_pocket_clear"]
    pocket_z1 = T - P["bezel_t"]
    pocket_z0 = pocket_z1 - (P["disp_t"] + P["disp_pocket_extra"])
    disp_z0 = pocket_z0                            # module tựa đáy hộc (đệm xốp phía Pi)

    # Raspberry Pi LẬT: mặt LINH KIỆN quay về màn hình, mặt HÀN quay về lưng.
    # Header 2x20 cắm kim dài từ mặt hàn vào lỗ Pi (không hàn); kim dài nhô qua mặt linh kiện
    # 6.0 - 1.5 = 4.5 mm nên màn hình phải cách mặt linh kiện >= 4.5 + pi_pin_clear.
    pi_w, pi_l, pi_t = P["pi"]
    pin_proud = P["hdr_pin_long"] - pi_t
    pi_z1 = pocket_z0 - (pin_proud + P["pi_pin_clear"])   # mặt linh kiện (mặt trước PCB)
    pi_z0 = pi_z1 - pi_t                                  # mặt hàn (mặt sau PCB)
    pi_comp_z1 = pi_z1 + P["pi_comp_h"]
    hdr_z1 = pi_z0                                        # đế nhựa header tựa mặt hàn
    hdr_z0 = hdr_z1 - P["hdr_base_t"]
    ridge_z0 = back_t
    ridge_z1 = hdr_z0 - P["hdr_preload"]                  # đỉnh gờ chạm mặt sau đế nhựa
    ridge_h = ridge_z1 - ridge_z0
    # lỗ kim có thể ăn nhẹ vào sàn nắp lưng; cần còn >= 1.0 mm nhựa dưới đáy lỗ
    assert ridge_h + back_t - P["hdr_hole_depth"] >= 1.0, "lỗ kim xuyên sàn nắp lưng — tăng T"
    pi_x0 = -in_hw                                 # sát thành trái -> khe thẻ nhớ ngay thành máy
    pi_x1 = pi_x0 + pi_w
    pi_y1 = in_hl - P["pi_gap_top"]
    pi_y0 = pi_y1 - pi_l
    hi = P["pi_hole_inset"]
    pi_holes = [(pi_x0 + hi, pi_y0 + hi), (pi_x0 + hi, pi_y1 - hi),
                (pi_x1 - hi, pi_y0 + hi), (pi_x1 - hi, pi_y1 - hi)]
    pi_screw_holes = [pi_holes[0], pi_holes[1]]    # 2 lỗ bên trái nằm ngoài hộc màn hình -> bắt ốc xuyên Pi
    # Cổng trên cạnh Pi Zero (tính từ mép trái PCB): mini-HDMI 12.4, USB OTG 41.4, PWR 54.0
    hdmi_x = pi_x0 + 12.4
    usb_x = pi_x0 + 41.4
    sd_y = (pi_y0 + pi_y1) / 2
    # Header GPIO 2x20: cạnh dài phía dưới (đối diện cổng), 20 cột 2.54 mm cân giữa chiều dài PCB
    pi_cx = (pi_x0 + pi_x1) / 2
    hdr_cols_x = [pi_cx + (i - 9.5) * 2.54 for i in range(20)]
    hdr_rows_y = [pi_y0 + r for r in P["pi_hdr_rows"]]
    hdr_cy = sum(hdr_rows_y) / 2.0

    # Pin
    bw, bl_, bt = P["bat"]
    bbw, bbl, bbd = P["bat_bay"]
    bcx, bcy = L["bat_c"]
    bay_z0 = back_t
    bay_z1 = back_t + bbd
    rib = P["bat_rib_t"]

    # Bàn phím Casio
    kp = P["key_pitch_x"]
    key_cols_x = [(i - (P["key_cols"] - 1) / 2.0) * kp for i in range(P["key_cols"])]
    key_rows_y = L["key_rows"]
    keys = [(x, y) for y in key_rows_y for x in key_cols_x]
    flange_z1 = face_in
    flange_z0 = face_in - P["key_flange_t"]
    tact_z1 = flange_z0                       # đỉnh cần switch chạm vành nút
    tact_z0 = tact_z1 - P["tact_h"]
    perf_z1 = tact_z0
    perf_z0 = perf_z1 - P["perf_t"]
    perf_y1 = max(key_rows_y) + 3.0 + 0.5     # thân switch 6 mm + 0.5
    perf_y0 = min(key_rows_y) - 3.0 - 0.5
    perf_x = 64.0
    perf_cy = (perf_y0 + perf_y1) / 2

    # MX
    mx_keys = L["mx_keys"]
    mx_hous_below = 5.0      # thân dưới plate (plate top -> đáy switch)
    mx_pin = 3.3             # chân + chốt định vị
    mx_hous_above = 6.6      # thân trên plate
    mx_cap_h = 8.0           # keycap DSA
    mx_cap_gap = 1.6

    # Loa / sạc / amp (khoang lưng dưới bàn phím)
    spk_c = (-18.0, -52.0) if layout_name == "split" else (-18.0, -56.0)
    ch_w, ch_l, ch_t = P["charger"]
    ch_c = (12.0, -in_hl + 1.0 + ch_l / 2)
    ch_z0 = back_t
    jack_z0 = ch_z0 + ch_t
    jack_h = 3.2
    typec_cz = jack_z0 + jack_h / 2
    amp_c = (0.0, 68.0)          # dưới Pi, khoang lưng vùng màn hình (gần chân I2S), trên gờ header
    sw_y, sw_z = 48.0, 13.5

    # Boss / ốc
    bosses_m2 = [(33.5, 78.0)] + list(L["bosses_side"]) + [(30.0, -76.0), (-30.0, -76.0)]
    bosses_pi = pi_screw_holes

    # ------------------------------------------------------------- NẮP TRƯỚC
    front = prism(W, BL, r_top, r_bot, split, T)
    front = front.faces(">Z").edges().fillet(P["fillet_front"])
    front = front.cut(prism(in_w, in_l, r_top - wall, r_bot - wall, split - 1, face_in))

    # gờ định vị quanh hộc màn hình (mặt trong)
    rt = P["disp_rim_t"]
    rim = (prism(pk_w + 2 * rt, pk_h + 2 * rt, 0.5 + rt, 0.5 + rt, face_in - P["disp_rim_h"], face_in, dcx, dcy)
           .cut(prism(pk_w, pk_h, 0.5, 0.5, face_in - P["disp_rim_h"] - 1, face_in + 1, dcx, dcy)))
    front = front.union(rim)
    # hộc màn hình + cửa sổ
    front = front.cut(prism(pk_w, pk_h, 0.5, 0.5, pocket_z0, pocket_z1, dcx, dcy))
    front = front.cut(prism(win_w, win_h, 1, 1, face_in - 1, T + 1, dcx, dcy))
    try:
        sel = cq.selectors.BoxSelector((dcx - win_w / 2 - 0.5, dcy - win_h / 2 - 0.5, T - 0.05),
                                       (dcx + win_w / 2 + 0.5, dcy + win_h / 2 + 0.5, T + 0.05))
        front = front.edges(sel).chamfer(0.8)
        info["window_chamfer"] = 0.8
    except Exception as e:  # pragma: no cover
        info["window_chamfer"] = "skipped: %s" % e

    # phím cơ MX: lỗ 14x14 + hốc trong 16x16 để plate còn 1.5 mm
    for (x, y) in mx_keys:
        front = front.cut(cbox(x, y, P["mx_pocket"], P["mx_pocket"], face_in - 1, T - P["mx_plate_t"]))
        front = front.cut(cbox(x, y, P["mx_cut"], P["mx_cut"], face_in - 1, T + 1))

    # bàn phím Casio: lỗ tròn
    for (x, y) in keys:
        front = front.cut(cyl(x, y, face_in - 1, T + 1, P["key_hole_d"]))

    # gân đè pin
    for y in L["bat_ribs_y"]:
        front = front.union(cbox(bcx, y, bbw - 3.0, rib, bay_z1, face_in))

    # boss M2 (từ mặt phân khuôn lên mặt trong) + gân nối thành
    bo = P["boss_od"]
    for (x, y) in bosses_m2:
        front = front.union(cyl(x, y, split, face_in, bo))
        # gân nối về thành gần nhất (bắt đầu phía trên gờ lip của nắp lưng)
        web_z0 = split + P["lip_h"] + P["tol"] + 0.1
        if abs(y) > 70:   # boss gần thành đỉnh/đáy
            yw = in_hl if y > 0 else -in_hl
            front = front.union(box(x - 0.6, x + 0.6, min(y, yw), max(y, yw), web_z0, face_in))
        else:
            xw = in_hw if x > 0 else -in_hw
            front = front.union(box(min(x, xw), max(x, xw), y - 0.6, y + 0.6, web_z0, face_in))
    for (x, y) in bosses_m2:
        front = front.cut(cyl(x, y, split - 1, split + 8.0, P["m2_pilot"]))
    # boss M2.5 xuyên Pi (chạm mặt trên PCB Pi)
    for (x, y) in bosses_pi:
        front = front.union(cyl(x, y, pi_z1, face_in, bo))
        front = front.cut(cyl(x, y, pi_z1 - 1, pi_z1 + 6.5, P["m25_pilot"]))

    # ------------------------------------------------------------- NẮP LƯNG
    back = prism(W, BL, r_top, r_bot, 0, split)
    back = back.faces("<Z").edges().fillet(P["fillet_back"])
    back = back.cut(prism(in_w, in_l, r_top - wall, r_bot - wall, back_t, split + 1))

    # gờ lip
    tol, lt, lh = P["tol"], P["lip_t"], P["lip_h"]
    lip = (prism(in_w - 2 * tol, in_l - 2 * tol, r_top - wall - tol, r_bot - wall - tol, split - 0.01, split + lh)
           .cut(prism(in_w - 2 * tol - 2 * lt, in_l - 2 * tol - 2 * lt,
                      max(r_top - wall - tol - lt, 0.3), r_bot - wall - tol - lt, split - 1, split + lh + 1)))
    # bỏ lip ở chỗ boss nắp trước đi qua và dọc vùng Pi (cổng/khe thẻ nhớ sát thành)
    for (x, y) in bosses_m2 + bosses_pi:
        lip = lip.cut(cyl(x, y, split - 1, split + lh + 1, bo + 2 * tol + 0.2))
    lip = lip.cut(box(-hw - 1, pi_x1 + 2.0, pi_y0 - 2.0, hl + 1, split - 1, split + lh + 1))
    back = back.union(lip)

    # boss lưng (ống đệm) + lỗ xuyên + counterbore
    bbo = P["boss_back_od"]
    for (x, y) in bosses_m2:
        back = back.union(cyl(x, y, back_t - 0.01, split, bbo))
        if abs(y) > 70:
            yw = in_hl if y > 0 else -in_hl
            back = back.union(box(x - 0.6, x + 0.6, min(y, yw), max(y, yw), back_t - 0.01, split))
        else:
            xw = in_hw if x > 0 else -in_hw
            back = back.union(box(min(x, xw), max(x, xw), y - 0.6, y + 0.6, back_t - 0.01, split))
    for (x, y) in bosses_m2:
        back = back.cut(cyl(x, y, -1, split + 1, P["m2_clear"]))
        back = back.cut(cyl(x, y, -1, P["cb_depth"], P["m2_cb"]))
    # trụ đỡ Pi (lên tới mặt dưới PCB Pi) — ốc M2.5 xuyên lỗ Pi vào boss nắp trước
    for (x, y) in bosses_pi:
        back = back.union(cyl(x, y, back_t - 0.01, pi_z0, bbo))
        back = back.cut(cyl(x, y, -1, pi_z0 + 1, P["m25_clear"]))
        back = back.cut(cyl(x, y, -1, P["cb_depth"], P["m25_cb"]))

    # GỜ ÉP HEADER 40 CHÂN: khối đặc 51.5 x 5.0, đỉnh gờ chạm mặt sau đế nhựa header,
    # 40 lỗ Ø1.3 sâu 3.0 trên đỉnh gờ cho đầu kim ngắn
    back = back.union(cbox(pi_cx, hdr_cy, P["hdr_len"], P["hdr_w"], back_t - 0.01, ridge_z1))
    holes = None
    for x in hdr_cols_x:
        for y in hdr_rows_y:
            h = cyl(x, y, ridge_z1 - P["hdr_hole_depth"], ridge_z1 + 1, P["hdr_hole_d"])
            holes = h if holes is None else holes.union(h)
    back = back.cut(holes)

    # hộc pin: khung gân 1.2 mm, sâu đúng 10.5 từ mặt trong nắp lưng
    frame = (cbox(bcx, bcy, bbw + 2 * rib, bbl + 2 * rib, back_t - 0.01, bay_z1)
             .cut(cbox(bcx, bcy, bbw, bbl, back_t - 1, bay_z1 + 1)))
    frame = frame.cut(cbox(bcx, bcy + bbl / 2 + rib / 2, 5.0, rib + 2, bay_z1 - 3.5, bay_z1 + 1))  # rãnh luồn dây pin
    back = back.union(frame)

    # loa: vòng định vị + khe thoát âm
    back = back.union(cyl(spk_c[0], spk_c[1], back_t - 0.01, back_t + 1.5, P["spk_d"] + 2.5)
                      .cut(cyl(spk_c[0], spk_c[1], back_t - 1, back_t + 3, P["spk_d"] + 0.5)))
    n = P["spk_slits"]
    for i in range(n):
        x = spk_c[0] + (i - (n - 1) / 2.0) * P["spk_slit_pitch"]
        back = back.cut(cbox(x, spk_c[1], P["spk_slit_w"], P["spk_slit_l"], -1, back_t + 1))

    # khung giữ module sạc (hở phía cổng Type-C)
    chf = (cbox(ch_c[0], ch_c[1], ch_w + 2 * rib + 0.8, ch_l + 2 * rib + 0.8, back_t - 0.01, back_t + 2.5)
           .cut(cbox(ch_c[0], ch_c[1], ch_w + 0.8, ch_l + 0.8, back_t - 1, back_t + 4))
           .cut(cbox(ch_c[0], ch_c[1] - ch_l / 2 - 2, ch_w + 4, 6, back_t - 1, back_t + 4)))
    back = back.union(chf)

    # ------------------------------------------------------------- LỖ TRÊN THÀNH (cắt cả 2 nắp)
    cuts = []
    cuts.append(rect_wall_x(hdmi_x, pi_z1 + 1.9, hl, 12.5, 4.5))                  # mini-HDMI (cạnh đỉnh)
    cuts.append(rect_wall_x(usb_x, pi_z1 + 1.5, hl, 9.0, 3.5))                    # micro-USB OTG (cạnh đỉnh)
    cuts.append(rect_wall_y(sd_y, pi_z1 + 1.5, -hw, 16.0, 3.5))                   # khe thẻ microSD (thành trái)
    cuts.append(rect_wall_y(sw_y, sw_z, hw, P["sw_slot"][0], P["sw_slot"][1]))    # công tắc gạt (thành phải)
    cuts.append(slot_wall_x(ch_c[0], typec_cz, -hl, P["typec_slot"][0], P["typec_slot"][1]))  # Type-C (cạnh đáy)
    for c in cuts:
        front = front.cut(c)
        back = back.cut(c)

    # ------------------------------------------------------------- NÚT BẤM IN 3D (bàn phím Casio)
    cap_z0, cap_z1 = face_in, T + P["key_cap_proud"]
    keycap = (cyl(0, 0, flange_z0, flange_z1, P["key_flange_d"])
              .union(cyl(0, 0, flange_z1 - 0.01, cap_z1, P["key_cap_d"])))
    try:
        keycap = keycap.faces(">Z").edges().fillet(0.6)
    except Exception:
        pass

    # ------------------------------------------------------------- LINH KIỆN THAM CHIẾU (kiểm tra va chạm)
    refs = {}
    # header 2x20 không hàn: đế + 40 kim (kim dài xuyên PCB về phía màn hình, kim ngắn vào gờ)
    pins = None
    pin_holes = None
    for x in hdr_cols_x:
        for y in hdr_rows_y:
            pin_s = cbox(x, y, 0.64, 0.64, hdr_z0 - P["hdr_pin_short"], hdr_z1 + P["hdr_pin_long"])
            hole_s = cyl(x, y, pi_z0 - 1, pi_z1 + 1, 1.0)
            pins = pin_s if pins is None else pins.union(pin_s)
            pin_holes = hole_s if pin_holes is None else pin_holes.union(hole_s)
    refs["gpio_header"] = cbox(pi_cx, hdr_cy, 50.8, 5.08, hdr_z0, hdr_z1).union(pins)
    refs["pi_pcb"] = box(pi_x0, pi_x1, pi_y0, pi_y1, pi_z0, pi_z1).cut(pin_holes)
    comp = box(pi_x0, pi_x1, pi_y0, pi_y1, pi_z1, pi_comp_z1)
    for (x, y) in pi_holes:
        comp = comp.cut(cyl(x, y, pi_z1 - 1, pi_comp_z1 + 1, 6.0))
    comp = comp.cut(cbox(pi_cx, hdr_cy, 52.5, 7.0, pi_z1 - 1, pi_comp_z1 + 1))   # vùng header không có linh kiện
    refs["pi_components"] = comp
    refs["display_module"] = cbox(dcx, dcy, pw, ph, disp_z0, disp_z0 + P["disp_t"])
    refs["display_active"] = cbox(dcx, dcy, aw, ah, disp_z0 + P["disp_t"], disp_z0 + P["disp_t"] + 0.2)
    refs["battery"] = cbox(bcx, bcy, bw, bl_, bay_z0, bay_z0 + bt)
    for i, (x, y) in enumerate(mx_keys):
        s = (cbox(x, y, 15.6, 15.6, T, T + mx_hous_above)
             .union(cbox(x, y, 13.9, 13.9, T - mx_hous_below, T + 0.01))
             .union(cbox(x, y, 10.0, 10.0, T - mx_hous_below - mx_pin, T - mx_hous_below + 0.01)))
        refs["mx_switch_%d" % i] = s
        refs["mx_keycap_%d" % i] = cbox(x, y, 18.0, 18.0, T + mx_hous_above + mx_cap_gap,
                                        T + mx_hous_above + mx_cap_gap + mx_cap_h)
    tact_all = None
    caps_all = None
    for (x, y) in keys:
        t = cbox(x, y, 6.0, 6.0, tact_z0, tact_z0 + 3.5).union(cyl(x, y, tact_z0 + 3.5 - 0.01, tact_z1, 3.5))
        c = keycap.translate((x, y, 0))
        tact_all = t if tact_all is None else tact_all.union(t)
        caps_all = c if caps_all is None else caps_all.union(c)
    refs["tactile_switches"] = tact_all
    refs["printed_keycaps"] = caps_all
    refs["key_pcb"] = cbox(0, perf_cy, perf_x, perf_y1 - perf_y0, perf_z0, perf_z1)
    refs["speaker"] = cyl(spk_c[0], spk_c[1], back_t, back_t + P["spk_h"], P["spk_d"])
    jack = cq.Workplane("XZ", origin=(ch_c[0], -in_hl - 0.5, jack_z0 + jack_h / 2)).slot2D(8.9, jack_h, 0).extrude(3.5, both=True)
    refs["charger"] = cbox(ch_c[0], ch_c[1], ch_w, ch_l, ch_z0, ch_z0 + ch_t).union(jack)
    refs["power_switch"] = box(in_hw - 3.7, in_hw, sw_y - 4.3, sw_y + 4.3, sw_z - 2.0, sw_z + 2.0)
    refs["amp_max98357a"] = cbox(amp_c[0], amp_c[1], P["amp"][0], P["amp"][1], back_t, back_t + P["amp"][2])

    # ------------------------------------------------------------- SỐ LIỆU DẪN XUẤT
    info.update(dict(
        layout=layout_name,
        body=dict(w=W, l=BL, t=T, r_top=r_top, r_bot=r_bot),
        display=dict(center=P["disp_c"], window=(round(win_w, 2), round(win_h, 2)),
                     pocket=(round(pk_w, 2), round(pk_h, 2)), pocket_depth=round(pocket_z1 - pocket_z0, 2),
                     bezel_t=P["bezel_t"], module_z=(round(disp_z0, 2), round(disp_z0 + P["disp_t"], 2))),
        pi=dict(x=(pi_x0, pi_x1), y=(pi_y0, pi_y1), pcb_z=(round(pi_z0, 2), round(pi_z1, 2)),
                components_z=(round(pi_z1, 2), round(pi_comp_z1, 2)), holes=pi_holes,
                screw_holes=pi_screw_holes, hdmi_x=hdmi_x, usb_x=usb_x, sd_y=sd_y,
                orientation="mặt linh kiện quay về màn hình, mặt hàn quay về lưng"),
        header_press_ridge=dict(size=(P["hdr_len"], P["hdr_w"], round(ridge_h, 2)), center=(pi_cx, round(hdr_cy, 2)),
                                z=(ridge_z0, round(ridge_z1, 2)), holes=(40, P["hdr_hole_d"], P["hdr_hole_depth"]),
                                cols_x=[round(v, 2) for v in hdr_cols_x], rows_y=[round(v, 2) for v in hdr_rows_y],
                                header_base_z=(round(hdr_z0, 2), round(hdr_z1, 2)),
                                long_pin_tip_z=round(hdr_z1 + P["hdr_pin_long"], 2), display_bottom_z=round(disp_z0, 2)),
        battery=dict(cell=P["bat"], bay=P["bat_bay"], bay_center=L["bat_c"], bay_z=(bay_z0, bay_z1),
                     bay_y=(bcy - bbl / 2, bcy + bbl / 2), bay_x=(bcx - bbw / 2, bcx + bbw / 2)),
        mx=dict(keys=mx_keys, labels=L["mx_labels"], cut=P["mx_cut"], plate_t=P["mx_plate_t"],
                pocket=P["mx_pocket"], pitch=P["mx_pitch"],
                below_plate_clearance_needed=mx_hous_below + mx_pin + 1.5),
        keypad=dict(cols_x=[round(v, 2) for v in key_cols_x], rows_y=key_rows_y, n_keys=len(keys),
                    hole_d=P["key_hole_d"], cap_d=P["key_cap_d"], flange=(P["key_flange_d"], P["key_flange_t"]),
                    tactile_z=(round(tact_z0, 2), round(tact_z1, 2)), pcb=(perf_x, round(perf_y1 - perf_y0, 2)),
                    pcb_z=(round(perf_z0, 2), round(perf_z1, 2)), pcb_y=(perf_y0, perf_y1)),
        speaker=dict(center=spk_c, d=P["spk_d"], slits=(n, P["spk_slit_w"], P["spk_slit_l"], P["spk_slit_pitch"])),
        charger=dict(center=ch_c, size=P["charger"], typec_slot=P["typec_slot"], typec_z=round(typec_cz, 2)),
        amp=dict(center=amp_c, size=P["amp"]),
        power_switch=dict(wall="right", y=sw_y, z=sw_z, slot=P["sw_slot"]),
        screws=dict(m2_positions=bosses_m2, m25_through_pi=bosses_pi,
                    m2_len="M2 x 12 tự ren (7 con)", m25_len="M2.5 x 16 tự ren xuyên lỗ Pi (2 con)"),
        split_z=split, lip=(P["lip_t"], P["lip_h"], P["tol"]),
    ))
    return front, back, keycap, refs, info


# =============================================================================
# 4. KIỂM TRA VA CHẠM
# =============================================================================
def interference_report(front, back, refs):
    bodies = dict(front_shell=front, back_shell=back)
    bodies.update(refs)
    names = list(bodies.keys())
    problems = []
    checked = 0
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            # các cặp cố ý tiếp xúc nhưng không được lồng vào nhau vẫn kiểm tra như thường
            try:
                v = vol(bodies[a].intersect(bodies[b]))
            except Exception as e:
                v = float("nan")
            checked += 1
            if not (v == v) or v > 0.05:
                problems.append((a, b, v))
    return checked, problems


def clearance_report(front, back, refs, top=14):
    """Khoảng cách nhỏ nhất giữa vỏ và từng linh kiện (0 = tiếp xúc có chủ ý, ví dụ nút tựa vành)."""
    out = {}
    for name, s in refs.items():
        try:
            out[name] = dict(front=round(front.val().distance(s.val()), 2),
                             back=round(back.val().distance(s.val()), 2))
        except Exception:
            out[name] = dict(front=None, back=None)
    return out


# =============================================================================
# 5. XUẤT FILE
# =============================================================================
def to_print_orientation(shape, flip_x=False):
    s = shape
    if flip_x:
        s = s.rotate((0, 0, 0), (1, 0, 0), 180)
    bb = s.val().BoundingBox()
    return s.translate((-bb.xmin - (bb.xmax - bb.xmin) / 2, -bb.ymin - (bb.ymax - bb.ymin) / 2, -bb.zmin))


def export_all(layout_name, outdir):
    front, back, keycap, refs, info = build(layout_name)
    os.makedirs(outdir, exist_ok=True)
    tolr = dict(tolerance=0.02, angularTolerance=0.1)

    # STEP từng chi tiết (toạ độ thiết kế)
    exporters.export(front, os.path.join(outdir, "front_shell.step"))
    exporters.export(back, os.path.join(outdir, "back_shell.step"))
    exporters.export(keycap, os.path.join(outdir, "keycap_casio.step"))
    # STL đã xoay đúng hướng in (mặt ngoài úp xuống bàn in)
    exporters.export(to_print_orientation(front, flip_x=True), os.path.join(outdir, "front_shell_print.stl"), **tolr)
    exporters.export(to_print_orientation(back), os.path.join(outdir, "back_shell_print.stl"), **tolr)
    exporters.export(to_print_orientation(keycap, flip_x=True), os.path.join(outdir, "keycap_casio_print.stl"), **tolr)

    # Assembly STEP: vỏ + linh kiện tham chiếu (mỗi thứ một solid, có tên & màu)
    asm = cq.Assembly(name="casio_handheld_%s" % layout_name)
    asm.add(front, name="front_shell", color=cq.Color(0.16, 0.17, 0.19, 1.0))
    asm.add(back, name="back_shell", color=cq.Color(0.22, 0.23, 0.26, 1.0))
    colors = dict(pi_pcb=(0.0, 0.5, 0.2), pi_components=(0.1, 0.3, 0.15), display_module=(0.1, 0.1, 0.4),
                  display_active=(0.2, 0.6, 1.0), battery=(0.85, 0.65, 0.1), key_pcb=(0.0, 0.45, 0.25),
                  tactile_switches=(0.5, 0.5, 0.5), printed_keycaps=(0.9, 0.9, 0.9), speaker=(0.3, 0.3, 0.3),
                  charger=(0.6, 0.1, 0.1), amp_max98357a=(0.1, 0.1, 0.5))
    for k, s in refs.items():
        c = colors.get(k, (0.7, 0.4, 0.1) if k.startswith("mx_switch") else (0.95, 0.35, 0.2))
        asm.add(s, name=k, color=cq.Color(c[0], c[1], c[2], 1.0))
    try:
        asm.export(os.path.join(outdir, "assembly.step"))
    except AttributeError:
        asm.save(os.path.join(outdir, "assembly.step"))

    # Bản vẽ SVG (hình chiếu)
    svgopt = dict(width=600, height=1100, marginLeft=10, marginTop=10, showAxes=False,
                  strokeWidth=0.35, strokeColor=(40, 40, 40), hiddenColor=(180, 180, 180), showHidden=False)
    exporters.export(front, os.path.join(outdir, "front_shell_top.svg"), opt=dict(svgopt, projectionDir=(0, 0, 1)))
    exporters.export(back, os.path.join(outdir, "back_shell_inside.svg"), opt=dict(svgopt, projectionDir=(0, 0, 1)))
    exporters.export(back, os.path.join(outdir, "back_shell_outside.svg"), opt=dict(svgopt, projectionDir=(0, 0, -1)))

    # Kiểm tra va chạm
    checked, problems = interference_report(front, back, refs)
    info["interference"] = dict(pairs_checked=checked, problems=[(a, b, round(v, 3)) for a, b, v in problems])
    info["min_clearances_mm"] = clearance_report(front, back, refs)
    info["volumes_cm3"] = dict(front_shell=round(vol(front) / 1000, 2), back_shell=round(vol(back) / 1000, 2),
                               keycap=round(vol(keycap) / 1000, 3))
    bbf, bbb = front.val().BoundingBox(), back.val().BoundingBox()
    info["bbox"] = dict(front=[round(v, 2) for v in (bbf.xlen, bbf.ylen, bbf.zlen)],
                        back=[round(v, 2) for v in (bbb.xlen, bbb.ylen, bbb.zlen)])
    with open(os.path.join(outdir, "design_info.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--layout", default="split", choices=["split", "row", "all"])
    ap.add_argument("--out", default="out")
    a = ap.parse_args()
    layouts = ["split", "row"] if a.layout == "all" else [a.layout]
    ok = True
    for ln in layouts:
        info = export_all(ln, os.path.join(a.out, ln))
        pr = info["interference"]
        print("== layout %-5s : %d cặp kiểm tra, %d va chạm; thể tích vỏ trước %.1f cm³, lưng %.1f cm³" % (
            ln, pr["pairs_checked"], len(pr["problems"]), info["volumes_cm3"]["front_shell"],
            info["volumes_cm3"]["back_shell"]))
        for a_, b_, v in pr["problems"]:
            print("   !! VA CHẠM %-18s x %-18s : %.3f mm³" % (a_, b_, v))
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
