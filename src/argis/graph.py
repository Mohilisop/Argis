"""Pivot graph for argis.

Seed handle -> scan -> read each found profile for referenced handles & emails ->
multi-hop expansion -> export interactive HTML (vis-network) + GraphML.
"""

from __future__ import annotations

import asyncio
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from xml.dom import minidom

from argis.correlate import _fetch_signals, _hamming
from argis.intel_http import AsyncFetcher

_HANDLE_RX = re.compile(
    r"(?:github\.com/|twitter\.com/|x\.com/|instagram\.com/|linkedin\.com/in/|"
    r"reddit\.com/u(?:ser)?/|facebook\.com/|t\.me/|youtube\.com/@)"
    r"([a-zA-Z0-9_.-]+)",
    re.I,
)
_EMAIL_RX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


@dataclass
class Node:
    id: str
    label: str
    kind: str = "seed"
    url: str = ""
    platform: str = ""
    display_name: str = ""
    hop: int = 0


@dataclass
class Edge:
    source: str
    target: str
    kind: str = "reference"
    weight: float = 1.0


@dataclass
class PivotGraph:
    seed: str
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        if node.id not in self.nodes:
            self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        if edge.source != edge.target:
            self.edges.append(edge)


def _extract_referenced(text: str) -> list[tuple[str, str, str]]:
    results: list[tuple[str, str, str]] = []
    for m in _HANDLE_RX.finditer(text):
        handle = m.group(1)
        full = m.group(0)
        platform = full.split(".com")[0].split("//")[-1] if ".com" in full else ""
        url = f"https://{full}" if not full.startswith("http") else full
        results.append((platform, handle, url))
    return results


async def build_graph(
    seed: str, expand_hops: int = 1, max_expand: int = 8,
    category=None, timeout: float = 12.0, concurrency: int = 15,
    proxy=None, use_tor: bool = False, render: bool = False,
) -> PivotGraph:
    from argis.core import ArgisEngine
    from argis.correlate import Signals

    @dataclass
    class _Acct:
        sig: Signals
        handle: str
        hop: int

    g = PivotGraph(seed=seed)
    g.add_node(Node(id=seed, label=seed, kind="seed", hop=0))
    visited: set[str] = set()
    frontier = [seed]
    working: list[_Acct] = []

    async with AsyncFetcher(
        timeout=timeout, concurrency=concurrency, proxy=proxy,
        use_tor=use_tor, render=render,
    ) as fx:
        for hop in range(expand_hops + 1):
            batch = [h for h in frontier if h.lower() not in visited]
            for h in batch:
                visited.add(h.lower())
            if not batch:
                break

            async def scan_read(handle: str):
                eng = ArgisEngine(handle, timeout=timeout, concurrency=concurrency,
                                  categories=category, proxy=proxy, use_tor=use_tor)
                res = await eng.run_scan(quiet=True)
                out = []
                for p, r in res.items():
                    if r.get("status") == "FOUND" and r.get("url"):
                        s = await _fetch_signals(fx, p, r["url"], handle, True)
                        if s.error is None:
                            out.append(_Acct(s, handle, hop))
                return out

            hop_accts = [a for grp in
                         await asyncio.gather(*(scan_read(h) for h in batch))
                         for a in grp]
            working.extend(hop_accts)

            for a in hop_accts:
                nid = f"{a.sig.platform}:{a.handle.lower()}"
                g.add_node(Node(
                    id=nid, platform=a.sig.platform, label=a.handle,
                    url=a.sig.url, kind="seed" if (a.hop == 0 and a.handle == seed)
                         else "account", display_name=a.sig.display_name, hop=a.hop))
                for em in a.sig.emails:
                    eid = f"email:{em.lower()}"
                    g.add_node(Node(id=eid, platform="email", label=em,
                                    kind="email", hop=a.hop))
                    g.add_edge(Edge(nid, eid, "shared_email"))

            if hop < expand_hops:
                counter: dict[str, int] = {}
                for a in hop_accts:
                    page = await fx.get(a.sig.url)
                    src_id = f"{a.sig.platform}:{a.handle.lower()}"
                    for platform, handle, url in _extract_referenced(page.text):
                        dst_id = f"{platform}:{handle.lower()}"
                        g.add_node(Node(id=dst_id, platform=platform,
                                        label=handle, url=url, kind="account",
                                        hop=hop + 1))
                        g.add_edge(Edge(src_id, dst_id, "links_to"))
                        if handle.lower() != seed.lower():
                            counter[handle] = counter.get(handle, 0) + 1
                frontier = sorted(counter, key=lambda h: -counter[h])[:max_expand]
            else:
                frontier = []

        for i in range(len(working)):
            for j in range(i + 1, len(working)):
                ai, aj = working[i].sig, working[j].sig
                if ai.avatar_hash is not None and aj.avatar_hash is not None \
                        and bin(ai.avatar_hash ^ aj.avatar_hash).count("1") <= 6:
                    g.add_edge(Edge(
                        f"{ai.platform}:{working[i].handle.lower()}",
                        f"{aj.platform}:{working[j].handle.lower()}",
                        "shared_avatar", 0.9))
    return g


_VIS_HTML_TPL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Argis Pivot Graph — {seed}</title>
<style>
  body, html {{ margin: 0; padding: 0; height: 100%; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
  #mynetwork {{ width: 100%; height: 100vh; background: #0f172a; }}
</style>
</head>
<body>
<div id="mynetwork"></div>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<script>
const nodes = new vis.DataSet({nodes});
const edges = new vis.DataSet({edges});
const container = document.getElementById('mynetwork');
const data = {{ nodes, edges }};
const options = {{
  nodes: {{
    shape: 'dot',
    size: 16,
    font: {{ color: '#e2e8f0', size: 14, face: 'Monospace' }},
    borderWidth: 2,
    color: {{
      background: '#38bdf8',
      border: '#0ea5e9',
    }},
  }},
  edges: {{
    color: {{ color: '#334155', highlight: '#38bdf8' }},
    smooth: {{ type: 'curvedCW', roundness: 0.2 }},
    arrows: {{ to: {{ enabled: true, scaleFactor: 0.5 }} }},
  }},
  physics: {{
    solver: 'forceAtlas2Based',
    forceAtlas2Based: {{ gravitationalConstant: -40, centralGravity: 0.005, springLength: 160, springConstant: 0.02 }},
    stabilization: {{ iterations: 100 }},
  }},
  interaction: {{
    hover: true,
    tooltipDelay: 200,
    navigationButtons: true,
    keyboard: true,
  }},
}};
const network = new vis.Network(container, data, options);
</script>
</body>
</html>"""


def to_html(graph: PivotGraph) -> str:
    nodelist = []
    color_map = {"seed": "#f472b6", "account": "#38bdf8",
                 "email": "#fbbf24"}
    shape_map = {"seed": "diamond", "account": "dot", "email": "star"}
    for nid, n in graph.nodes.items():
        nodelist.append({
            "id": nid,
            "label": n.label,
            "title": f"{n.kind}: {n.label}",
            "color": color_map.get(n.kind, "#94a3b8"),
            "shape": shape_map.get(n.kind, "dot"),
        })
    edgelist = []
    for e in graph.edges:
        edgelist.append({"from": e.source, "to": e.target,
                         "title": e.kind, "arrows": "to"})
    return _VIS_HTML_TPL.format(
        seed=graph.seed,
        nodes=json.dumps(nodelist),
        edges=json.dumps(edgelist),
    )


def to_graphml(graph: PivotGraph) -> str:
    root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
    root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")

    for key_id, key_for, key_name in [
        ("kind", "node", "kind"), ("url", "node", "url"),
        ("platform", "node", "platform"), ("hop", "node", "hop"),
        ("ekind", "edge", "kind"),
    ]:
        ET.SubElement(root, "key", id=key_id, for_=key_for,
                      attr_name=key_name, attr_type="string")

    g_el = ET.SubElement(root, "graph", edgedefault="directed")
    for nid, n in graph.nodes.items():
        node_el = ET.SubElement(g_el, "node", id=nid)
        for key, val in [("kind", n.kind), ("url", n.url),
                         ("platform", n.platform), ("hop", str(n.hop))]:
            d = ET.SubElement(node_el, "data", key=key)
            d.text = val

    for i, e in enumerate(graph.edges):
        edge_el = ET.SubElement(g_el, "edge", id=f"e{i}",
                                 source=e.source, target=e.target)
        d = ET.SubElement(edge_el, "data", key="ekind")
        d.text = e.kind

    rough = ET.tostring(root, encoding="unicode")
    dom = minidom.parseString(rough.encode())
    return dom.toprettyxml(indent="  ")