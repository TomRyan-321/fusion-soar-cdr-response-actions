#!/usr/bin/env python3
"""Draw a Fusion workflow YAML as the console shows it, in one image (the canvas is hard to screenshot whole).

Run: python3 docs/make-workflow-diagram.py [workflow.yaml ...]
Default: the split version's five workflows. Writes docs/workflow/<name>.svg, and .png if rsvg-convert is installed.
"""
import os
import shutil
import subprocess
import sys
from html import escape

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = ["cdr-triage-and-respond", "cdr-respond-iam", "cdr-respond-ec2", "cdr-respond-data", "cdr-respond-controls"]
BG, CARD, EDGE, LINE, TEXT, MUTED = "#141418", "#232328", "#3A3A42", "#6E6E78", "#F2F2F5", "#9A9AA5"
PURPLE, PINK, GREEN, RED, BLUE = "#9B4DE0", "#F0457A", "#C8F0C0", "#EC0000", "#7FA8F5"
NODE_W, NODE_H, ROW, COL, PAD = 230, 44, 96, 270, 50
# Action type label and icon, by action ID prefix.
KINDS = {"702d15788dbb": ("Action", "var"), "6c6eab39063f": ("Update variable", "var"),
         "7fb9eb10b239": ("Create Python script", "py"), "bdfecafafdb4": ("Action", "llm")}


def load(path):
    d = yaml.safe_load(open(path))
    nodes = {"__trigger__": {"kind": "trigger", "label": d["trigger"].get("name", "Trigger"), "next": d["trigger"].get("next") or []}}
    for k, a in (d.get("actions") or {}).items():
        kind, icon = KINDS.get(a["id"][:12], ("Action", "workflow" if a["id"].startswith("__WORKFLOW_") else "app"))
        nodes[k] = {"kind": "action", "type": kind, "icon": icon, "label": a.get("name", k), "next": a.get("next") or []}
    for k, c in (d.get("conditions") or {}).items():
        nodes[k] = {"kind": "condition", "label": "If " + " ".join(c.get("display") or [k]), "next": c.get("next") or []}
    # Branches that all lead to the same several nodes meet at one join first, as Fusion draws it.
    shared = {}
    for k, n in nodes.items():
        if len(n["next"]) > 1:
            shared.setdefault(tuple(n["next"]), []).append(k)
    for i, (targets, sources) in enumerate(shared.items()):
        if len(sources) > 1:
            join = f"__join{i}__"
            nodes[join] = {"kind": "join", "next": list(targets)}
            for k in sources:
                nodes[k]["next"] = [join]
    return d.get("name", os.path.basename(path)), nodes


def layout(nodes):
    """Layer by longest path from the trigger, then order each layer by its parents' positions."""
    parents = {k: [] for k in nodes}
    for k, n in nodes.items():
        for m in n["next"]:
            parents[m].append(k)
    layer = {"__trigger__": 0}
    changed = True
    while changed:
        changed = False
        for k, n in nodes.items():
            if k in layer:
                for m in n["next"]:
                    if layer.get(m, -1) < layer[k] + 1:
                        layer[m], changed = layer[k] + 1, True
    order = list(nodes)
    x = {}
    for depth in range(max(layer.values()) + 1):
        row = [k for k in order if layer.get(k) == depth]
        want = {k: (sum(x[p] for p in parents[k]) / len(parents[k]) if parents[k] else 0) for k in row}
        # Children of one parent spread around it, in YAML order.
        row.sort(key=lambda k: (want[k], order.index(k)))
        groups = {}
        for k in row:
            groups.setdefault(round(want[k], 3), []).append(k)
        placed = []
        for centre, ks in groups.items():
            for i, k in enumerate(ks):
                placed.append((centre + i - (len(ks) - 1) / 2, k))
        placed.sort()
        last = None
        for pos, k in placed:
            if last is not None and pos < last + 1:
                pos = last + 1
            x[k], last = pos, pos
    return layer, x, parents


def wrap(text, width=30):
    words, lines = text.split(), [""]
    for w in words:
        if len(lines[-1]) + len(w) + 1 > width and lines[-1] and len(w) <= width:
            lines.append(w)
        else:
            lines[-1] = (lines[-1] + " " + w).strip()
    return lines


def icon(kind, x, y):
    s = 22
    if kind == "var":
        return (f'<rect x="{x}" y="{y}" width="{s}" height="{s}" rx="3" fill="{GREEN}"/>'
                f'<text x="{x + s / 2}" y="{y + 15}" font-size="10" font-weight="700" fill="#1E5A2A" text-anchor="middle">{{x}}</text>')
    if kind == "workflow":
        return (f'<rect x="{x}" y="{y}" width="{s}" height="{s}" rx="3" fill="{GREEN}"/>'
                f'<path d="M {x + 7} {y + 5} L {x + 7} {y + 18} M {x + 7} {y + 5} L {x + 17} {y + 8} L {x + 7} {y + 12}" stroke="#1E5A2A" stroke-width="2" fill="#1E5A2A"/>')
    if kind == "llm":
        return (f'<rect x="{x}" y="{y}" width="{s}" height="{s}" rx="3" fill="#2E2E36" stroke="{MUTED}"/>'
                f'<path d="M {x + 6} {y + 7} L {x + 16} {y + 7} M {x + 6} {y + 11} L {x + 16} {y + 11} M {x + 6} {y + 15} L {x + 13} {y + 15}" stroke="{TEXT}" stroke-width="1.6"/>')
    # Python script and Store apps: the Falcon mark, as a red swoosh.
    return f'<path d="M {x + 3} {y + 8} C {x + 9} {y + 6}, {x + 15} {y + 9}, {x + 19} {y + 17} C {x + 14} {y + 13}, {x + 9} {y + 12}, {x + 5} {y + 13} Z" fill="{RED}"/>'


def render(name, nodes):
    layer, x, parents = layout(nodes)
    lo = min(x.values())
    cx = {k: PAD + NODE_W / 2 + (x[k] - lo) * COL for k in nodes}
    cy = {k: PAD + 50 + layer[k] * ROW + NODE_H / 2 for k in nodes}
    W = int(max(cx.values()) + NODE_W / 2 + 160 + PAD)
    H = int(max(cy.values()) + NODE_H / 2 + PAD)
    out = [f'<rect width="{W}" height="{H}" fill="{BG}"/>',
           f'<text x="{PAD}" y="{PAD + 6}" font-size="18" font-weight="700" fill="{TEXT}">{escape(name)}</text>']

    def half(k):
        return {"condition": 26, "join": 7}.get(nodes[k]["kind"], NODE_H / 2)

    def bottom(k):
        return cy[k] + half(k)

    def top(k):
        return cy[k] - half(k)

    edges, joins = [], set()
    for k, n in nodes.items():
        for m in n["next"]:
            x1, y1, x2, y2 = cx[k], bottom(k), cx[m], top(m)
            if nodes[k]["kind"] == "condition":
                y1 += 30  # below the TRUE label
            mid = y2 - 18
            if abs(x1 - x2) < 1:
                d = f"M {x1} {y1} L {x2} {y2}"
            else:
                r = min(8, abs(x2 - x1) / 2)
                sx = 1 if x2 > x1 else -1
                d = (f"M {x1} {y1} L {x1} {mid - r} Q {x1} {mid}, {x1 + sx * r} {mid} "
                     f"L {x2 - sx * r} {mid} Q {x2} {mid}, {x2} {mid + r} L {x2} {y2}")
            edges.append(f'<path d="{d}" fill="none" stroke="{LINE}" stroke-width="1.4" marker-end="url(#a)"/>')
            if len(parents[m]) > 1 and nodes[m]["kind"] != "join":
                joins.add(m)
    out += edges
    for m in joins:
        out.append(f'<rect x="{cx[m] - 7}" y="{top(m) - 25}" width="14" height="14" rx="3" fill="{BLUE}"/>'
                   f'<path d="M {cx[m] - 3} {top(m) - 21} L {cx[m]} {top(m) - 18} L {cx[m] + 3} {top(m) - 21} M {cx[m] - 3} {top(m) - 15} '
                   f'L {cx[m]} {top(m) - 18} L {cx[m] + 3} {top(m) - 15}" stroke="#1B2A55" stroke-width="1.5" fill="none"/>')

    for k, n in nodes.items():
        X, Y = cx[k], cy[k]
        if n["kind"] == "join":
            out.append(f'<rect x="{X - 7}" y="{Y - 7}" width="14" height="14" rx="3" fill="{BLUE}"/>'
                       f'<path d="M {X - 3} {Y - 3} L {X} {Y} L {X + 3} {Y - 3} M {X - 3} {Y + 3} L {X} {Y} L {X + 3} {Y + 3}" '
                       f'stroke="#1B2A55" stroke-width="1.5" fill="none"/>')
        elif n["kind"] == "trigger":
            w = NODE_W - 40
            out.append(f'<rect x="{X - w / 2}" y="{Y - 20}" width="{w}" height="40" rx="20" fill="{CARD}" stroke="{EDGE}"/>'
                       f'<circle cx="{X - w / 2 + 20}" cy="{Y}" r="11" fill="{PINK}"/>'
                       f'<path d="M {X - w / 2 + 21} {Y - 7} L {X - w / 2 + 16} {Y + 1} L {X - w / 2 + 20} {Y + 1} L {X - w / 2 + 19} {Y + 7} '
                       f'L {X - w / 2 + 24} {Y - 1} L {X - w / 2 + 20} {Y - 1} Z" fill="#FFFFFF"/>'
                       f'<text x="{X - w / 2 + 40}" y="{Y - 3}" font-size="9" fill="{MUTED}">Trigger</text>'
                       f'<text x="{X - w / 2 + 40}" y="{Y + 11}" font-size="11.5" fill="{TEXT}">{escape(n["label"])}</text>')
        elif n["kind"] == "condition":
            out.append(f'<rect x="{X - 18}" y="{Y - 18}" width="36" height="36" rx="5" transform="rotate(45 {X} {Y})" fill="{PURPLE}" stroke="#2A1440" stroke-width="4"/>'
                       f'<path d="M {X} {Y + 7} L {X} {Y - 1} M {X} {Y - 1} L {X - 5} {Y - 7} M {X} {Y - 1} L {X + 5} {Y - 7}" stroke="#FFFFFF" stroke-width="1.6" fill="none"/>')
            lines = wrap(n["label"], 24)
            out.append(f'<text x="{X + 34}" y="{Y - 6}" font-size="9" fill="{MUTED}">Condition</text>')
            for i, line in enumerate(lines):
                out.append(f'<text x="{X + 34}" y="{Y + 8 + i * 14}" font-size="11.5" fill="{TEXT}">{escape(line)}</text>')
            ty = Y + 26 + 8
            out.append(f'<line x1="{X}" y1="{Y + 26}" x2="{X}" y2="{ty}" stroke="{LINE}" stroke-width="1.4"/>'
                       f'<rect x="{X - 18}" y="{ty}" width="36" height="18" rx="2" fill="{CARD}" stroke="{EDGE}"/>'
                       f'<text x="{X}" y="{ty + 12.5}" font-size="8.5" font-weight="700" fill="{TEXT}" text-anchor="middle">TRUE</text>')
        else:
            lines = wrap(n["label"], 28)[:2]
            h = NODE_H + (12 if len(lines) > 1 else 0)
            out.append(f'<rect x="{X - NODE_W / 2}" y="{Y - NODE_H / 2}" width="{NODE_W}" height="{h}" rx="4" fill="{CARD}" stroke="{EDGE}"/>')
            out.append(icon(n["icon"], X - NODE_W / 2 + 10, Y - 11))
            out.append(f'<text x="{X - NODE_W / 2 + 42}" y="{Y - 6}" font-size="9" fill="{MUTED}">{escape(n["type"])}</text>')
            for i, line in enumerate(lines):
                out.append(f'<text x="{X - NODE_W / 2 + 42}" y="{Y + 8 + i * 14}" font-size="11.5" fill="{TEXT}">{escape(line)}</text>')

    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
            f'font-family="Inter, system-ui, -apple-system, Helvetica, Arial, sans-serif">'
            f'<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
            f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{LINE}"/></marker></defs>' + "".join(out) + "</svg>")


def main():
    paths = sys.argv[1:] or [os.path.join(ROOT, "workflows", f + ".yaml") for f in DEFAULT]
    outdir = os.path.join(ROOT, "docs", "workflow")
    os.makedirs(outdir, exist_ok=True)
    for path in paths:
        name, nodes = load(path)
        base = os.path.join(outdir, os.path.splitext(os.path.basename(path))[0])
        if "self-contained" in path:
            base += "-self-contained"
        open(base + ".svg", "w").write(render(name, nodes))
        if shutil.which("rsvg-convert"):
            subprocess.run(["rsvg-convert", "-z", "2", base + ".svg", "-o", base + ".png"], check=True)
        print("wrote", os.path.relpath(base, ROOT) + ".svg")


main()
