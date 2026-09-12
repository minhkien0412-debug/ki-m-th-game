#!/usr/bin/env python3
"""Render assembly (vỏ + linh kiện tham chiếu) ra PNG bằng matplotlib, tessellate trực tiếp từ CadQuery."""
import sys, os, json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d.art3d import Poly3DCollection
import casio_handheld as m

COL = {
    "front_shell": (0.30, 0.31, 0.35), "back_shell": (0.36, 0.37, 0.41),
    "pi_pcb": (0.05, 0.45, 0.25), "pi_components": (0.15, 0.35, 0.25), "gpio_header": (0.10, 0.10, 0.10),
    "display_module": (0.15, 0.15, 0.35), "display_active": (0.25, 0.55, 0.95), "battery": (0.85, 0.65, 0.15),
    "key_pcb": (0.05, 0.45, 0.25), "tactile_switches": (0.55, 0.55, 0.55), "printed_keycaps": (0.92, 0.92, 0.90),
    "speaker": (0.25, 0.25, 0.25), "charger": (0.65, 0.12, 0.12), "amp_max98357a": (0.12, 0.12, 0.55),
    "power_switch": (0.6, 0.6, 0.6),
}
def col(name):
    if name in COL: return COL[name]
    if name.startswith("mx_switch"): return (0.75, 0.45, 0.10)
    if name.startswith("mx_keycap"): return (0.90, 0.35, 0.25)
    return (0.6, 0.6, 0.6)

def tess(shape, tol=0.08):
    v, t = shape.val().tessellate(tol, 0.5)
    v = np.array([[p.x, p.y, p.z] for p in v]); t = np.array(t)
    return v, t

def render(parts, png, elev, azim, ortho=False, size=(9, 13), title=""):
    tris, cols = [], []
    light = np.array([0.35, -0.45, 0.82]); light /= np.linalg.norm(light)
    for name, shape in parts:
        v, t = tess(shape)
        tri = v[t]
        n = np.cross(tri[:, 1] - tri[:, 0], tri[:, 2] - tri[:, 0])
        n /= (np.linalg.norm(n, axis=1, keepdims=True) + 1e-9)
        shade = 0.40 + 0.60 * np.clip(n @ light, 0, 1)
        c = np.array(col(name))
        cols.append(np.clip(shade[:, None] * c[None, :], 0, 1))
        tris.append(tri)
    tri = np.concatenate(tris); cols = np.concatenate(cols)
    fig = plt.figure(figsize=size, dpi=120)
    ax = fig.add_subplot(111, projection="3d")
    if ortho: ax.set_proj_type("ortho")
    ax.add_collection3d(Poly3DCollection(tri, facecolors=cols, edgecolors="none"))
    allv = tri.reshape(-1, 3); mn, mx = allv.min(0), allv.max(0)
    c = (mn + mx) / 2; r = (mx - mn).max() / 2 * 0.9
    ax.set_xlim(c[0]-r, c[0]+r); ax.set_ylim(c[1]-r, c[1]+r); ax.set_zlim(c[2]-r, c[2]+r)
    ax.set_box_aspect((1, 1, 1)); ax.view_init(elev=elev, azim=azim); ax.set_axis_off()
    if title: ax.set_title(title, fontsize=11)
    fig.subplots_adjust(0, 0, 1, 1); fig.savefig(png, facecolor="white", bbox_inches="tight", pad_inches=0.05)
    plt.close(fig); print("wrote", png, len(tri), "tris")

if __name__ == "__main__":
    layout = sys.argv[1]; out = os.path.join("out", layout)
    front, back, keycap, refs, info = m.build(layout)
    front_parts = [("front_shell", front)] + [(k, v) for k, v in refs.items()
                   if k.startswith("mx_") or k in ("printed_keycaps", "display_active")]
    render(front_parts, os.path.join(out, "render_front_iso.png"), 38, -62, title="Mặt trước — bố cục " + layout)
    render(front_parts, os.path.join(out, "render_front_top.png"), 90, -90, ortho=True, title="Mặt trước (chiếu đứng) — " + layout)
    back_parts = [("back_shell", back)] + [(k, v) for k, v in refs.items()
                  if k in ("battery", "speaker", "charger", "amp_max98357a", "gpio_header")]
    render(back_parts, os.path.join(out, "render_back_inside_iso.png"), 42, -62, title="Nắp lưng, mặt trong — " + layout)
    # nắp trước lật úp: nhìn vào mặt trong với Pi + màn hình + board phím
    inside_parts = [("front_shell", front)] + [(k, v) for k, v in refs.items()
                    if k in ("pi_pcb", "pi_components", "display_module", "key_pcb", "tactile_switches", "power_switch")]
    render(inside_parts, os.path.join(out, "render_front_inside_iso.png"), -42, -62, title="Nắp trước, mặt trong (nhìn từ lưng) — " + layout)
