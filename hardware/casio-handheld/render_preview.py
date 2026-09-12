#!/usr/bin/env python3
"""Render ảnh xem trước (PNG) từ STL bằng matplotlib — không cần OpenGL."""
import sys, os
import numpy as np
import trimesh
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d.art3d import Poly3DCollection

def render(stl_path, png_path, elev=35, azim=-60, color=(0.35, 0.36, 0.40), title=""):
    m = trimesh.load(stl_path)
    v, f = m.vertices, m.faces
    tri = v[f]
    # shading theo pháp tuyến
    n = m.face_normals
    light = np.array([0.3, -0.5, 0.8]); light /= np.linalg.norm(light)
    shade = 0.45 + 0.55 * np.clip(n @ light, 0, 1)
    cols = np.clip(np.outer(shade, color), 0, 1)
    fig = plt.figure(figsize=(7, 10), dpi=110)
    ax = fig.add_subplot(111, projection="3d")
    pc = Poly3DCollection(tri, facecolors=cols, edgecolors="none")
    ax.add_collection3d(pc)
    mn, mx = v.min(0), v.max(0)
    c = (mn + mx) / 2; r = (mx - mn).max() / 2
    ax.set_xlim(c[0]-r, c[0]+r); ax.set_ylim(c[1]-r, c[1]+r); ax.set_zlim(c[2]-r, c[2]+r)
    ax.set_box_aspect((1, 1, 1)); ax.view_init(elev=elev, azim=azim); ax.set_axis_off()
    ax.set_title(title)
    fig.tight_layout(); fig.savefig(png_path, facecolor="white"); plt.close(fig)
    print("wrote", png_path, "faces", len(f))

if __name__ == "__main__":
    d = sys.argv[1]
    render(os.path.join(d, "front_shell_print.stl"), os.path.join(d, "preview_front_print.png"), elev=40, azim=-65, title="front shell (hướng in: mặt ngoài úp xuống)")
    render(os.path.join(d, "back_shell_print.stl"), os.path.join(d, "preview_back_inside.png"), elev=40, azim=-65, title="back shell (mặt trong)")
    render(os.path.join(d, "keycap_casio_print.stl"), os.path.join(d, "preview_keycap.png"), elev=30, azim=-50, title="keycap")
