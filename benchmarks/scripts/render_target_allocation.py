#!/usr/bin/env python3
"""Render the published benchmark *target* allocation.

This uses only the Python standard library so contributors can regenerate the
SVG without installing plotting dependencies. It is deliberately a planning
visualisation, not a scan-result or risk-distribution graphic.
"""

from __future__ import annotations

import csv
from html import escape
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / "benchmarks" / "data" / "target-allocation.csv"
OUTPUT = ROOT / "assets" / "benchmarks" / "target-allocation.svg"

DISPLAY_LABELS = {
    "Biomedical and scientific research": "Biomedical & scientific research",
    "Social science, literature, and academic work": "Social science, literature & academic work",
    "Software engineering and DevOps": "Software engineering & DevOps",
    "Machine learning, data, and AI": "Machine learning, data & AI",
    "Quantitative finance and economic analysis": "Quant finance & economics",
    "Cross-domain professional automation": "Cross-domain professional automation",
}
COLORS = ["#00A6A6", "#3487D4", "#6C63C9", "#0F9D70", "#D78922", "#6B7A90"]


def main() -> None:
    with INPUT.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    labels = [row["cohort"] for row in rows]
    values = [int(row["target"]) for row in rows]
    total = sum(values)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    left, right, top, row_height = 525, 1450, 250, 95
    scale = (right - left) / 300

    grid = []
    for tick in (0, 100, 200, 300):
        x = left + tick * scale
        grid.extend(
            [
                f'<line x1="{x:.1f}" y1="190" x2="{x:.1f}" y2="780" stroke="#D7E1EA" stroke-width="2"/>',
                f'<text x="{x:.1f}" y="815" text-anchor="middle" class="axis">{tick}</text>',
            ]
        )

    bars = []
    for index, (label, value, color) in enumerate(zip(labels, values, COLORS)):
        y = top + index * row_height
        width = value * scale
        display = escape(DISPLAY_LABELS[label])
        bars.extend(
            [
                f'<text x="485" y="{y + 37}" text-anchor="end" class="label">{display}</text>',
                f'<rect x="{left}" y="{y}" width="{width:.1f}" height="52" rx="10" fill="{color}"/>',
                f'<text x="{left + width + 18:.1f}" y="{y + 36}" class="value">{value}</text>',
            ]
        )

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" viewBox="0 0 1600 900" role="img" aria-labelledby="title description">
  <title id="title">SkillGuardrail benchmark target allocation</title>
  <desc id="description">A target allocation of 1100 public Agent Skills across six cohorts. This is a planning target, not scan results.</desc>
  <style>
    .title {{ font: 700 42px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; fill: #102A43; }}
    .subtitle {{ font: 400 24px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; fill: #486075; }}
    .label {{ font: 600 21px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; fill: #203040; }}
    .value {{ font: 700 25px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; fill: #102A43; }}
    .axis {{ font: 400 19px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; fill: #617386; }}
    .note {{ font: 400 18px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; fill: #64748B; }}
  </style>
  <rect width="1600" height="900" fill="#F8FAFC"/>
  <rect x="82" y="68" width="11" height="92" rx="5" fill="#00A6A6"/>
  <text x="120" y="110" class="title">SkillGuardrail benchmark target allocation</text>
  <text x="120" y="148" class="subtitle">{total:,} public Agent Skills across six cohorts</text>
  {''.join(grid)}
  {''.join(bars)}
  <text x="800" y="865" text-anchor="middle" class="note">Planning target only — not scan results, risk prevalence, or a safety rating.</text>
</svg>
'''
    OUTPUT.write_text(svg, encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
