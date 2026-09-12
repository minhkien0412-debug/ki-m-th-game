# Vỏ máy chơi game cầm tay kiểu Casio fx-580VN X — mô hình 3D tham số

Vỏ in 3D hai mảnh (nắp trước + nắp lưng) theo form factor Casio fx-580VN X / fx-991EX
(77 × 165.5 mm), bên trong chứa Raspberry Pi Zero 2 W, màn hình 2.4" SPI, pin Li-Po 103450,
4 switch phím cơ Cherry MX cho FNF / Geometry Dash và 24 phím tactile kiểu bàn phím Casio.

Mô hình dựng bằng **CadQuery** (Python). Mọi kích thước là tham số trong `casio_handheld.py`,
sửa xong chạy lại là ra bộ file mới. Kiểm tra va chạm tự động: **253 cặp vỏ/linh kiện, 0 va chạm**
ở cả hai bố cục.

## 1. Tệp trong gói

```
casio_handheld.py        mô hình tham số (nguồn — đây là "bản vẽ gốc")
render_assembly.py       render PNG assembly (matplotlib)
render_preview.py        render PNG từ STL
out/split/               bố cục mặc định: 2 cặp phím cơ hai bên
out/row/                 bố cục thay thế: 4 phím cơ nằm ngang một hàng
  front_shell.step       nắp trước  (toạ độ thiết kế, mở trong Fusion 360 / SolidWorks / FreeCAD)
  back_shell.step        nắp lưng
  keycap_casio.step      nút bấm tròn cho bàn phím Casio (in 24 cái)
  assembly.step          vỏ + toàn bộ linh kiện tham chiếu (Pi, màn hình, pin, switch, loa, sạc…)
  *_print.stl            STL đã xoay đúng hướng in (mặt ngoài úp xuống bàn in), gốc toạ độ ở góc
  *.svg                  hình chiếu 2D
  render_*.png           ảnh xem trước
  design_info.json       toàn bộ số liệu dẫn xuất (toạ độ, cao độ, khe hở) của bố cục đó
```

Chạy lại:

```bash
pip install cadquery            # một lần
python3 casio_handheld.py                # -> out/split
python3 casio_handheld.py --layout row   # -> out/row
python3 casio_handheld.py --layout all
```

Hệ toạ độ: **X** = chiều rộng (phải +), **Y** = chiều dài (đỉnh máy +), **Z** = chiều dày,
**z = 0 là mặt lưng ngoài, z = 20 là mặt trước ngoài**. Tâm máy tại (0, 0).

## 2. Kích thước tổng thể

| Hạng mục | Giá trị |
|---|---|
| Rộng × dài | 77.0 × 165.5 mm (Casio fx-580VN X: 77 × 165.5, thân dày 11.1, kèm nắp 13.8) |
| Dày | **20.0 mm** — quyết định bởi chồng lớp gờ ép header + Pi + kim dài + màn hình (xem §3) |
| Bo góc | đỉnh R4, đáy R9 |
| Thành / mặt trước / nắp lưng | 2.0 / 2.0 / 2.0 mm |
| Bo mép | mặt trước R2, mặt lưng R2.5 |
| Mặt phân khuôn | z = 7.5 (nắp lưng cao 7.5, nắp trước cao 12.5) |
| Gờ lip | dày 1.0 × cao 2.0, dung sai 0.25 mỗi bên; bỏ lip dọc vùng Pi (thẻ nhớ, cổng) và quanh boss |
| Ốc | 7 × M2×12 tự ren + 2 × M2.5×16 xuyên lỗ Pi (§7) |

## 3. Chồng lớp (stack-up) — z tính từ mặt lưng ngoài

**Vùng A – màn hình / Pi** (Pi **lật**: mặt linh kiện quay về màn hình, mặt hàn quay về lưng)

| z (mm) | Lớp |
|---|---|
| 0 – 2.0 | sàn nắp lưng |
| 2.0 – 4.96 | **gờ ép header** 51.5 × 5.0, cao 2.96; 40 lỗ Ø1.3 sâu 3.0 trên đỉnh |
| 4.96 – 7.5 | đế nhựa đen header 2×20 (2.54) — đỉnh gờ chạm mặt sau đế |
| 7.5 – 9.0 | PCB Pi Zero 2 W (mặt hàn z 7.5, mặt linh kiện z 9.0); header cắm kim dài từ mặt hàn, không hàn |
| 9.0 – 12.5 | linh kiện Pi (3.5); đầu kim dài nhô tới z 13.5 |
| 13.9 – 18.4 | module màn hình (hộc 13.9 – 18.5, sâu 4.6); khe 0.4 trên đầu kim; đệm xốp 1 mm giữa Pi và màn hình |
| 18.5 – 20.0 | gờ mặt trước quanh cửa sổ (bezel 1.5) |

**Vùng B – phím cơ MX** (mặt trước ngoài z = 20)

| z (mm) | Lớp |
|---|---|
| 18.5 – 20 | plate 1.5 (hốc 16 × 16 khoét từ mặt trong quanh lỗ 14 × 14) |
| 15.0 – 20 | thân switch dưới plate (5.0) — chân + chốt tới z 11.7; hàn dây trực tiếp |
| 2.0 – 12.5 | **hộc pin** 35 × 52 × 10.5 (khung gân 1.2) nằm giữa hai cụm phím; pin 10 mm → z 2 – 12 |
| 12.5 – 18 | 2 gân đè pin trên nắp trước (x ±16, y = +8 và −12) |

**Vùng C – bàn phím Casio**

| z (mm) | Lớp |
|---|---|
| 18 – 20 | mặt trước, lỗ Ø6.0 |
| 17 – 18 | vành nút Ø8 × 1.0 (dưới mặt), thân nút Ø5.5 nhô 1.5 mm |
| 12.7 – 17 | switch tactile 6×6×4.3 (đỉnh cần chạm vành nút) |
| 11.1 – 12.7 | board phím 64 × 46 (split) / 64 × 33 (row), mối hàn tới ≈10 |
| 2 – 7 | loa Ø28 × 5 (vòng định vị + 5 khe 1.5 × 10, pitch 3.5, trên nắp lưng) |
| 2 – 3.6 | module sạc 28 × 20, jack Type-C z 3.6 – 6.8 |

Amp MAX98357A 17 × 20 × 3 nằm dưới Pi (z 2 – 5) tại (0, 68), gần chân I2S.

## 4. Toạ độ mặt trước

**Màn hình**: tâm (0, 56). Cửa sổ 49.6 × 37.6 (active 49 × 37 + 0.3/bên), vát mép 0.8.
Hộc module 60.5 × 43.0 (PCB 60 × 42.5 + 0.25/bên), sâu 4.6; gờ định vị 1.2 dày × 4 cao quanh hộc.

**Phím cơ MX** — lỗ 14.0 × 14.0, plate 1.5, pitch 19.0:

| Bố cục | ← | ↓ | ↑ | → |
|---|---|---|---|---|
| split (mặc định) | (−27.5, 14) | (−27.5, −5) | (27.5, 14) | (27.5, −5) |
| row | (−28.5, 22) | (−9.5, 22) | (9.5, 22) | (28.5, 22) |

Split: keycap ngoài cùng cách mép máy 2 mm, thân switch cách thành trong 1.2 mm.
Row: 4 × 19 = 76 mm trên thân 77 mm → keycap cách mép 1 mm, thân switch cách thành trong **0.2 mm**;
nếu in bị chật, giảm `mx_pitch` xuống 18.5 hoặc tăng `body_w` lên 78.

**Bàn phím Casio** — lỗ Ø6.0, pitch 11 × 13, 6 cột x = ±5.5, ±16.5, ±27.5:

| Bố cục | Hàng y | Số phím |
|---|---|---|
| split | −30, −43, −56, −69 | 24 |
| row | −42, −55, −68 | 18 |

Gợi ý gán phím (split): 0-9 . = AC DEL + − × ÷ ( ) MENU SHIFT ▲ ▼ — dùng làm bàn phím điều hướng menu.

## 5. Toạ độ nắp lưng

| Chi tiết | Vị trí / kích thước |
|---|---|
| Hộc pin (split) | tâm (0, 1.5) → x ±17.5, y −24.5 … 27.5; z 2 – 12.5; rãnh luồn dây 5 mm ở đầu +y |
| Hộc pin (row) | tâm (0, −10.7) → y −36.7 … 15.3 |
| Gờ ép header | tâm (−4, 53.77), 51.5 × 5.0 × 2.96; lỗ kim: 20 cột x = −28.13 … 20.13 (2.54), 2 hàng y = 52.5 / 55.04 |
| Trụ đỡ Pi | Ø5.5, z 2 – 7.5, tại (−33, 52.5) và (−33, 75.5), lỗ Ø2.7, counterbore Ø5.2 × 1 |
| Loa | tâm (−18, −52) [split] / (−18, −56) [row]; vòng Ø30.5/Ø28.5 cao 1.5; 5 khe 1.5 × 10 |
| Module sạc | tâm (12, −69.75), khung giữ hở phía cổng; Type-C: cạnh đáy, x = 12, stadium 9.5 × 3.5, tâm z 5.2 |
| Boss ốc lưng | Ø5.5 cao 5.5, lỗ Ø2.4, counterbore Ø4.6 × 1 |

## 6. Lỗ trên thành (cắt qua cả hai nắp khi cần)

| Cổng | Thành | Vị trí | Kích thước |
|---|---|---|---|
| mini-HDMI (Pi) | đỉnh | x = −24.1, tâm z 10.9 | 12.5 × 4.5 |
| micro-USB OTG (Pi) | đỉnh | x = +4.9, tâm z 10.5 | 9.0 × 3.5 |
| khe microSD | trái | y = 64, tâm z 10.5 | 16 × 3.5 |
| công tắc gạt SS12D00 | phải | y = 48, tâm z 13.5 | 4.0 × 2.0 |
| Type-C sạc | đáy | x = 12, tâm z 5.2 | 9.5 × 3.5 (stadium) |

Pi nằm cách thành đỉnh 1.75 mm nên HDMI/USB chỉ dùng khi cắm cáp có đầu gọt mỏng — chủ yếu cài đặt qua SSH/WiFi.

## 7. Ốc vít

| Vị trí (x, y) | Loại | Ghi chú |
|---|---|---|
| (33.5, 78) | M2×12 | góc đỉnh phải, boss hoà vào góc |
| (±32, 29) split / (±33.5, 40) row | M2×12 | có gân nối thành |
| (±32, −20) | M2×12 | có gân nối thành |
| (±30, −76) | M2×12 | góc đáy |
| (−33, 52.5), (−33, 75.5) | **M2.5×16** | xuyên lỗ gắn của Pi: sàn 2 + trụ 5.5 + PCB 1.5 + 6.5 ren vào boss nắp trước |

Boss nắp trước Ø5, lỗ mồi Ø1.7 (M2) / Ø2.05 (M2.5) cho PLA. Muốn bền hơn: khoan Ø3.4 cấy insert đồng M2.5.

## 8. Ba nhóm kích thước PHẢI đo lại bằng thước kẹp trước khi in

1. **Module màn hình** — `disp_pcb` (60 × 42.5 là số đề bài; nhiều module 2.4" thật có PCB ≈ 70 × 43 với hàng header),
   `disp_t` (4.5, không có header — nếu module có sẵn header phải tháo, hàn dây phẳng), và độ lệch active area
   so với tâm PCB (thêm offset vào `disp_c`).
2. **Module sạc** — `charger` và vị trí jack; file giả định IP5306 Type-C 28 × 20 × 1.6.
3. **Header 2×20 và lỗ GPIO của Pi** — `pi_hdr_rows` (3.5 / 6.04 mm tính từ cạnh dài đối diện cổng — đối chiếu
   bản vẽ cơ khí Pi Zero 2 W), `hdr_pin_long` / `hdr_pin_short` / `hdr_base_t` theo header mua thật.
   40 lỗ trên gờ phải trùng đúng kim, sai 1.27 mm là lệch hàng.

Ngoài ra `mx_cut` 14.0 và `key_hole_d` 6.0 nên in **coupon thử** (tấm 30 × 30 × 1.5 có một lỗ 14 × 14 và một lỗ Ø6)
để hiệu chỉnh theo máy in trước khi in cả vỏ.

## 9. Sơ đồ nối dây GPIO (Pi Zero 2 W, đánh số BCM / chân header)

| Chức năng | GPIO | Chân |
|---|---|---|
| LCD SCLK | 11 | 23 |
| LCD MOSI | 10 | 19 |
| LCD CS | 8 (CE0) | 24 |
| LCD DC | 25 | 22 |
| LCD RESET | 24 | 18 |
| LCD đèn nền (PWM1) | 13 | 33 |
| I2S BCLK (MAX98357A) | 18 | 12 |
| I2S LRCLK | 19 | 35 |
| I2S DIN | 21 | 40 |
| MX ← / ↓ / ↑ / → (nối thẳng, pull-up nội) | 4 / 17 / 27 / 22 | 7 / 11 / 13 / 15 |
| Ma trận phím – hàng R1..R4 | 5, 6, 26, 16 | 29, 31, 37, 36 |
| Ma trận phím – cột C1..C6 | 20, 23, 7, 14, 15, 9 | 38, 16, 26, 8, 10, 21 |
| 5 V vào (từ module tăng áp) | — | 2 hoặc 4 |
| GND | — | 6, 9, 14, 20, 25, 30, 34, 39 |

Ghi chú: đèn nền **không** dùng GPIO18 vì trùng I2S BCLK. GPIO14/15 là UART — tắt console serial.
4 phím MX nối thẳng (không qua ma trận) để không ghosting khi bấm hợp âm và độ trễ thấp nhất; ma trận 4×6 cần
diode 1N4148 mỗi phím nếu muốn nhấn nhiều phím cùng lúc.

## 10. Linh kiện & giá tham khảo (VNĐ, 2026, sàn TMĐT)

| Linh kiện | SL | Giá |
|---|---|---|
| Raspberry Pi Zero 2 W | 1 | 450–550k |
| Màn 2.4" SPI 240×320 ILI9341/ST7789 (không header) | 1 | 80–120k |
| Module sạc + tăng áp 5 V/2 A IP5306, cổng Type-C | 1 | 25–40k |
| Pin Li-Po 103450 3.7 V (≈1800 mAh, có mạch bảo vệ) | 1 | 60–90k |
| MAX98357A I2S amp | 1 | 35–50k |
| Loa Ø28 mm 4 Ω 2 W | 1 | 15–25k |
| Switch MX (Gateron/Outemu) + keycap 1u | 4 + 4 | 40–70k |
| Tactile 6×6×4.3 | 24 | 10–15k |
| Board phím: PCB đặt JLCPCB (pitch 11×13) hoặc perfboard (đổi pitch 10.16×12.70) | 1 | 20–150k |
| Header 2×20 đực 2.54 | 1 | 5–10k |
| Công tắc gạt SS12D00 | 1 | 3k |
| Ốc M2×12 ×7, M2.5×16 ×2 | — | 10k |
| microSD 32 GB | 1 | 80–100k |
| Kapton, xốp 1 mm, dây, thiếc | — | 30k |
| **Tổng** | | **≈ 0.9 – 1.3 triệu** (chưa tính nhựa in) |

Thời lượng pin thực tế: Pi Zero 2 W khi chơi game ≈ 2–2.5 W + đèn nền 0.3 W + loa 0.2 W, qua mạch tăng áp
hiệu suất ~88 % → pin 1800 mAh (6.7 Wh) cho **≈ 2 giờ**.

## 11. In 3D

* Vật liệu: PETG cho nắp trước (plate MX 1.5 mm chịu lực bấm tốt hơn PLA); PLA được nhưng lẫy switch làm rạn plate mỏng.
* Hướng in: file `*_print.stl` đã xoay — mặt ngoài úp bàn in, không cần support (các lỗ trên thành ≤ 12.5 mm tự bắc cầu).
* Lớp 0.16–0.2 mm, 4 chu vi, 30 % infill; vùng plate MX in 100 % (đặt modifier 1.5 mm quanh 4 lỗ).
* Lỗ nhỏ (Ø1.3 lỗ kim, Ø1.7 lỗ mồi, Ø6 lỗ nút) in bị thu ~0.1–0.2 mm — đó là lý do có coupon thử; không cộng dư
  0.5–1 mm bừa vào hộc màn hình (module sẽ lỏng).
* Thể tích: nắp trước 30.5 cm³, nắp lưng 34.4 cm³, nút 0.13 cm³ × 24 ≈ 3 cm³ → ≈ 85 g nhựa.

## 12. Lắp ráp

1. Ép 4 switch MX vào plate từ mặt ngoài (lẫy ngậm vào mặt trong hốc 16 × 16). Hàn dây tín hiệu + GND chung.
2. Đặt 24 nút in vào lỗ từ mặt trong (vành ở dưới), úp board phím đã hàn tactile lên, cố định bằng 2 điểm keo nến ở góc.
3. Đặt module màn hình vào hộc (mặt kính ra ngoài), dán 1 lớp Kapton + xốp 1 mm lên lưng module.
4. Cắm header 2×20 vào Pi từ **mặt hàn** (kim dài vào lỗ, kim ngắn 3 mm quay ra). Đặt Pi lên xốp, mặt linh kiện
   xuống màn hình, 2 lỗ trái khớp boss; hàn dây LCD / I2S / phím vào chân header phía trên đế.
5. Nắp lưng: pin vào hộc (dây ra rãnh đầu +y), loa vào vòng, module sạc vào khung (jack lọt lỗ Type-C), amp dán băng keo 2 mặt.
6. Đóng nắp: gờ ép header ấn vào đế nhựa, kim ngắn vào 40 lỗ. Bắt 7 ốc M2 và 2 ốc M2.5 (xuyên Pi) từ lưng.

Muốn gờ ép có lực thay vì chỉ chạm: đặt `hdr_preload = 0.2` (gờ cao thêm 0.2 mm) rồi xuất lại.

## 13. Những điểm đã sửa so với tư vấn ban đầu

| Tư vấn cũ | Thực tế đưa vào file |
|---|---|
| TP4056 làm mạch nguồn | TP4056 chỉ ra 3.0–4.2 V; Pi cần 5 V → phải có mạch **tăng áp** (IP5306 gộp sạc + tăng áp + bảo vệ) |
| MAX98357A nối jack tai nghe | MAX98357A là amp loa cầu (BTL), cắm tai nghe chung mass sẽ hỏng chip → chỉ loa; muốn tai nghe dùng PCM5102A |
| Dày 13.8 mm | 13.8 là số kèm nắp trượt; thân Casio 11.1; máy này 20.0 do chồng lớp |
| 4 phím cơ nằm ngang | 4 × 19 = 76 mm > lòng trong 73 mm với thân switch → chỉ vừa sát; bố cục mặc định là 2 cặp dọc hai bên |
| Cộng dư 0.5–1 mm cho co ngót | Co ngót PLA đã được firmware bù; lỗ in thu 0.1–0.2 mm — dùng coupon, không cộng bừa |
| Pin 4–5 giờ | ≈ 2 giờ với 103450 |
| Lỗ phím số d 5.5–6 | Giữ Ø6.0, thêm nút in có vành Ø8 để nút không rơi ra ngoài |

## 14. Phần mềm — nói thẳng

* **Friday Night Funkin'** bản gốc là Haxe/OpenFL, cần OpenGL ES + RAM; Pi Zero 2 W (512 MB, VideoCore IV) chạy
  chật vật, FPS thấp. Dùng bản port nhẹ / engine mở dành cho máy yếu; chưa có "bản GBA/PS1 chính thức" nào đáng tin.
* **Geometry Dash** không có bản ARM Linux; trên Pi chỉ chơi được clone mã nguồn mở. Muốn chạy APK thật cần board Android
  ≥ 2 GB RAM (**Radxa Zero 3W** cùng cỡ 65 × 30 mm, lắp vừa vỏ này — nhưng phải sửa lại vị trí lỗ cổng và kiểm tra
  hàng header).
* Màn hình SPI dùng `fbcp-ili9341` đạt ~60 FPS ở 240×320.
* Header không hàn (ép bằng gờ) tiếp xúc kém ổn định khi rung/bấm mạnh; hàn 40 chân hoặc dùng "hammer header"
  (kim ép chuyên dụng) chắc chắn hơn — gờ ép vẫn hữu ích để giữ header.
