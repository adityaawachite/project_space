#!/usr/bin/env python3
"""
UISP-Lite 80-bit 2D Visual Cryptographic Code
Adapted from the reference implementation (single-file, local only — no
external HTTP backend calls; generation/reading happens in-process).

- Grid: 8 rows x 10 columns (80 nodes)
- filled circle = bit 0, hollow ring = bit 1
- Orientation marker: solid L-shape along bottom+right edges
- Mapping: column-major -> idx = col * ROWS + row
"""

import cv2
import numpy as np
import os
import math
from typing import Optional

ROWS = 8
COLS = 10
BITS = ROWS * COLS       # 80
HEX_LEN = 20              # 20 hex chars * 4 bits = 80 bits

DEFAULT_IMG_WIDTH = 600
DEFAULT_IMG_HEIGHT = 500
DEFAULT_MARGIN = 40
DEFAULT_LINE_BAND = 26  # reserved strip (outside the circle grid) for the L-shape marker
DEFAULT_RING_THICKNESS = 5
ORIENTATION_LINE_THICKNESS = 8
ORIENTATION_LINE_COLOR = (0, 0, 0)
MARKER_COLOR = (0, 0, 0)
BACKGROUND_COLOR = (255, 255, 255)


def hex_to_bin80(hex_id: str) -> str:
    h = hex_id.strip().lower().replace("0x", "")
    if len(h) != HEX_LEN:
        raise ValueError(f"UISP_ID must be {HEX_LEN} hex characters (got {len(h)}).")
    i = int(h, 16)
    return format(i, f'0{BITS}b')


def bin80_to_hex(bin_str: str) -> str:
    if len(bin_str) != BITS:
        raise ValueError(f"Binary string must be {BITS} bits.")
    i = int(bin_str, 2)
    return format(i, f'0{HEX_LEN}x').upper()


def rotate_image_cv(img: np.ndarray, k: int) -> np.ndarray:
    k = k % 4
    if k == 0:
        return img.copy()
    if k == 1:
        return cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE)
    if k == 2:
        return cv2.rotate(img, cv2.ROTATE_180)
    return cv2.rotate(img, cv2.ROTATE_90_COUNTERCLOCKWISE)


class VisualCryptoCode:
    def __init__(self, rows: int = ROWS, cols: int = COLS,
                 width: int = DEFAULT_IMG_WIDTH, height: int = DEFAULT_IMG_HEIGHT,
                 margin: int = DEFAULT_MARGIN, line_band: int = DEFAULT_LINE_BAND,
                 circle_radius: Optional[int] = None,
                 ring_thickness: int = DEFAULT_RING_THICKNESS,
                 orientation_thickness: int = ORIENTATION_LINE_THICKNESS):
        self.rows = rows
        self.cols = cols
        self.bits = rows * cols
        self.width = width
        self.height = height
        self.margin = margin
        self.line_band = line_band
        self.ring_thickness = ring_thickness
        self.orientation_thickness = orientation_thickness

        if circle_radius is None:
            usable_w = max(100, self.width - 2 * self.margin - self.line_band)
            usable_h = max(100, self.height - 2 * self.margin - self.line_band)
            cell = int(min(usable_w / self.cols, usable_h / self.rows))
            self.circle_radius = max(5, int(cell * 0.38))
        else:
            self.circle_radius = circle_radius

    def _grid_bounds(self):
        """Circle grid stays strictly inside this box; the L-shape marker is
        drawn in the separate `line_band` strip beyond `right`/`bottom`, so
        the two never overlap or get merged by contour detection."""
        left, top = self.margin, self.margin
        right = self.width - self.margin - self.line_band
        bottom = self.height - self.margin - self.line_band
        return left, top, right, bottom

    # ---------------- Encoding ----------------
    def generate_code(self, hex_id: str, save_path: str) -> str:
        bin_str = hex_to_bin80(hex_id)
        img = np.full((self.height, self.width, 3), BACKGROUND_COLOR, dtype=np.uint8)

        left, top, right, bottom = self._grid_bounds()
        cell_w = (right - left) / self.cols
        cell_h = (bottom - top) / self.rows

        for col in range(self.cols):
            for row in range(self.rows):
                idx = col * self.rows + row
                bit = bin_str[idx]
                cx = int(left + (col + 0.5) * cell_w)
                cy = int(top + (row + 0.5) * cell_h)
                if bit == '0':
                    cv2.circle(img, (cx, cy), self.circle_radius, MARKER_COLOR, -1, cv2.LINE_AA)
                else:
                    cv2.circle(img, (cx, cy), self.circle_radius, MARKER_COLOR, self.ring_thickness, cv2.LINE_AA)

        l, t, r, b = int(left), int(top), int(right), int(bottom)
        th = int(self.orientation_thickness)
        # The marker fills the whole reserved band out to near the true image
        # edge (not stopping partway), so it's reachable by an edge-based
        # orientation scan on a photographed/rotated copy of the code.
        band_r = self.width - 6
        band_b = self.height - 6
        # vertical bar of the L, in the reserved right-hand strip
        cv2.rectangle(img, (band_r - th, t), (band_r, band_b), ORIENTATION_LINE_COLOR, -1)
        # horizontal bar of the L, in the reserved bottom strip
        cv2.rectangle(img, (l, band_b - th), (band_r, band_b), ORIENTATION_LINE_COLOR, -1)

        os.makedirs(os.path.dirname(save_path) or '.', exist_ok=True)
        cv2.imwrite(save_path, img)
        return os.path.abspath(save_path)

    # ---------------- Decoding ----------------
    def read_code(self, image_path: str) -> str:
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError("Could not read image file.")

        img = self._auto_orient(img)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, th = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
        kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
        th = cv2.morphologyEx(th, cv2.MORPH_CLOSE, kernel, iterations=1)

        # RETR_CCOMP gives 2-level hierarchy: outer boundary contours, and (for
        # a hollow ring only) an inner "hole" contour nested underneath it.
        # A filled circle has no hole -> bit 0. A ring has a hole -> bit 1.
        contours, hierarchy = cv2.findContours(th, cv2.RETR_CCOMP, cv2.CHAIN_APPROX_SIMPLE)
        h, w = img.shape[:2]
        left, top, right, bottom = self._grid_bounds()
        cell_w = (right - left) / self.cols
        cell_h = (bottom - top) / self.rows

        grid_bits = [['' for _ in range(self.cols)] for _ in range(self.rows)]

        if hierarchy is not None:
            hierarchy = hierarchy[0]
            for i, c in enumerate(contours):
                parent = hierarchy[i][3]
                if parent != -1:
                    continue  # this is a hole contour, handled via its parent
                area = cv2.contourArea(c)
                if area < 8:
                    continue
                (cx, cy), radius = cv2.minEnclosingCircle(c)
                # Skip anything that isn't roughly the size of one marker circle —
                # this is what excludes the big L-shaped orientation bar (and any
                # background blob) from ever being mistaken for a data cell.
                if radius < 0.5 * self.circle_radius or radius > 1.7 * self.circle_radius:
                    continue
                col = int((cx - left) // cell_w)
                row = int((cy - top) // cell_h)
                if not (0 <= row < self.rows and 0 <= col < self.cols):
                    continue
                has_hole = hierarchy[i][2] != -1
                grid_bits[row][col] = '1' if has_hole else '0'

        bits_out = []
        for col in range(self.cols):
            for row in range(self.rows):
                v = grid_bits[row][col]
                if v not in ('0', '1'):
                    raise ValueError(f"Ambiguous / missing marker at row {row}, col {col}.")
                bits_out.append(v)

        return bin80_to_hex(''.join(bits_out))

    def _auto_orient(self, img: np.ndarray) -> np.ndarray:
        """Try all 4 rotations, pick the one whose bottom+right strips are darkest
        (that's where the solid L-shaped orientation marker lives)."""
        best_k, best_score = 0, -1.0
        for k in range(4):
            rot = rotate_image_cv(img, k)
            h, w = rot.shape[:2]
            sw = max(6, self.line_band + 10)
            sh = max(6, self.line_band + 10)
            right_strip = rot[:, w - sw:w]
            bottom_strip = rot[h - sh:h, :]
            gray_r = cv2.cvtColor(right_strip, cv2.COLOR_BGR2GRAY)
            gray_b = cv2.cvtColor(bottom_strip, cv2.COLOR_BGR2GRAY)
            darkness = (255 - gray_r.mean()) + (255 - gray_b.mean())
            if darkness > best_score:
                best_score = darkness
                best_k = k
        return rotate_image_cv(img, best_k)


def generate_user_code(hex_id: str, save_path: str) -> str:
    vcc = VisualCryptoCode()
    return vcc.generate_code(hex_id, save_path)


def verify_scanned_image(image_path: str, expected_hex: str) -> dict:
    vcc = VisualCryptoCode()
    try:
        decoded = vcc.read_code(image_path)
    except Exception as e:
        return {"verified": False, "decoded": None, "error": str(e)}
    return {
        "verified": decoded.upper() == expected_hex.upper(),
        "decoded": decoded,
        "error": None,
    }
