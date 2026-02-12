# summoner_web_viz.py
from __future__ import annotations

import json
import threading
import time
import webbrowser
import re
import logging
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from pathlib import Path


ParseRouteFn = Callable[[str], Any]


def _tok(x: Any) -> str:
    return str(x).strip()


def _normalize_route_key(route: str) -> str:
    # Remove all whitespace.
    return re.sub(r"\s+", "", str(route or ""))


def dna_to_graph(
    dna: List[Dict[str, Any]],
    *,
    parse_route: Optional[ParseRouteFn] = None,
) -> Dict[str, Any]:
    """
    Graph extraction:

      - If parse_route is provided, use it (canonical Summoner parsing).
      - Arrow route iff parsed target or label is non-empty.
      - Node-only route: add parsed source tokens as nodes.
      - If parse_route is missing, fall back to showing receive routes as nodes.

    Note:
      route_key is taken from DNA when present (already canonicalized by the SDK).
    """
    nodes: set[str] = set()
    edges: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str, str, str]] = set()  # (src,tgt,labels_joined,route_key)

    for item in dna or []:
        if not isinstance(item, dict):
            continue

        route_raw = str(item.get("route", "")).strip()
        typ = str(item.get("type", "")).strip()
        if not route_raw:
            continue

        # Canonical/stable identifier from DNA when available.
        route_key_raw = item.get("route_key") or route_raw
        route_key = _normalize_route_key(route_key_raw)

        if parse_route is not None:
            pr = parse_route(route_raw)

            src = [_tok(n) for n in (getattr(pr, "source", ()) or ())]
            lab = [_tok(n) for n in (getattr(pr, "label", ()) or ())]
            tgt = [_tok(n) for n in (getattr(pr, "target", ()) or ())]

            is_arrow = bool(tgt) or bool(lab)

            if is_arrow:
                srcs = src or ["∅"]
                tgts = tgt or ["∅"]
                labs = [x for x in lab if x]

                for s in srcs:
                    nodes.add(s)
                for t in tgts:
                    nodes.add(t)

                labels_joined = "|".join(labs)
                for s in srcs:
                    for t in tgts:
                        key = (s, t, labels_joined, route_key)
                        if key in seen:
                            continue
                        seen.add(key)
                        edges.append(
                            {
                                "source": s,
                                "target": t,
                                "labels": labs,
                                "route_key": route_key,
                                "route_raw": route_raw,
                            }
                        )
            else:
                # Node-only route like "Optimize"
                if src:
                    for s in src:
                        nodes.add(s)
                else:
                    # Defensive fallback if the parser yields empty source
                    nodes.add(route_raw)

            continue

        # Fallback: if no parse_route, show receive routes as nodes (same as summoner_web_viz.py)
        if typ == "receive":
            nodes.add(route_raw)

    return {"nodes": sorted(nodes), "edges": edges}


_HTML_TEMPLATE = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>__TITLE__</title>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <style>
__CSS__
  </style>
</head>
<body>
  <div id="topbar">
    <div id="title">__TITLE__</div>
    <div id="status">Loading…</div>
    <div id="legend">
      <span class="dot on"></span><span>active</span>
      <span class="dot off"></span><span>inactive</span>
      <span style="margin-left:10px; opacity:0.85;">Wheel: zoom</span>
      <span style="opacity:0.85;">Drag: pan</span>
      <span style="opacity:0.85;">Ctrl+Wheel: zoom column</span>
      <span style="opacity:0.85;">Double-click: reset</span>
    </div>
  </div>
  <canvas id="c"></canvas>

  <div id="logPanel">
    <div id="logHeader">
      <div class="left">
        <span id="logDot" class="dotSmall"></span>
        <span class="logTitle">Activity</span>
        <span id="logConn" class="logConn">connecting</span>
        <span id="logLast" class="logLast">No activity yet</span>
      </div>
      <div class="right">
        <button id="logClearBtn" type="button" title="Clear activity">Clear</button>
        <button id="logReduceBtn" type="button" title="Expand/collapse activity">Expand</button>
      </div>
    </div>
    <div id="logBody"></div>
  </div>

  <script>
__JS__
  </script>
</body>
</html>
"""


_ASSET_DIR = Path(__file__).with_name("web_viz_assets")


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _render_html(title: str) -> str:
    css = _read_text(_ASSET_DIR / "viz.css")
    js  = _read_text(_ASSET_DIR / "viz.js")
    return (
        _HTML_TEMPLATE
        .replace("__TITLE__", title)
        .replace("__CSS__", css)
        .replace("__JS__", js)
    )


class _VizState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.graph: Dict[str, Any] = {"nodes": [], "edges": []}
        self.states: List[str] = []

        # Terminal log ring buffer: list of (seq, line)
        self.log_seq: int = 0
        self.logs: List[Tuple[int, str]] = []
        self.max_logs: int = 3000


class _WebVizLogHandler(logging.Handler):
    def __init__(self, viz: ClientFlowVisualizer) -> None:
        super().__init__()
        self._viz = viz

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record) if self.formatter else record.getMessage()
        except Exception:
            try:
                msg = record.getMessage()
            except Exception:
                msg = "<log format error>"
        self._viz.push_log(msg)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


class ClientFlowVisualizer:
    def __init__(self, *, title: str = "Summoner Graph", port: int = 8765) -> None:
        self.title = title
        self.port = port
        self._st = _VizState()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def set_graph_from_dna(self, dna: List[Dict[str, Any]], *, parse_route: Optional[ParseRouteFn] = None) -> None:
        g = dna_to_graph(dna, parse_route=parse_route)
        with self._st.lock:
            self._st.graph = g

    def push_states(self, states: Any) -> None:
        labels: List[str] = []

        def add(x: Any) -> None:
            labels.append(_tok(x))

        if isinstance(states, dict):
            for _k, vs in states.items():
                if isinstance(vs, (list, tuple)):
                    for v in vs:
                        add(v)
                else:
                    add(vs)
        elif isinstance(states, (list, tuple)):
            for s in states:
                add(s)
        else:
            add(states)

        with self._st.lock:
            self._st.states = labels

    def push_log(self, line: Any) -> None:
        s = _strip_ansi(_tok(line))
        if not s:
            return
        with self._st.lock:
            self._st.log_seq += 1
            self._st.logs.append((self._st.log_seq, s))
            if len(self._st.logs) > self._st.max_logs:
                # Trim from the front
                drop = len(self._st.logs) - self._st.max_logs
                if drop > 0:
                    self._st.logs = self._st.logs[drop:]

    def push_logs(self, lines: Any) -> None:
        if lines is None:
            return
        if isinstance(lines, (list, tuple)):
            for x in lines:
                self.push_log(x)
        else:
            self.push_log(lines)

    def attach_logger(
        self,
        logger: logging.Logger,
        *,
        level: int = logging.DEBUG,
        formatter: Optional[logging.Formatter] = None
    ) -> logging.Handler:
        """
        Attach a logging handler that mirrors records into the web terminal.

        If formatter is None, we try to reuse the first existing handler formatter.
        If that formatter contains ANSI escapes, we strip them in push_log().
        """
        h = _WebVizLogHandler(self)
        h.setLevel(level)
        h._keep = True  # tell configure_logger() not to remove this handler

        if formatter is not None:
            h.setFormatter(formatter)
        else:
            # Reuse an existing formatter when available
            if logger.handlers and getattr(logger.handlers[0], "formatter", None) is not None:
                h.setFormatter(logger.handlers[0].formatter)
            else:
                h.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))

        logger.addHandler(h)
        return h

    def start(self, *, open_browser: bool = True) -> None:
        if self._thread is not None:
            return

        st = self._st
        title = self.title

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code: int, body: bytes, content_type: str) -> None:
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if self.path == "/" or self.path.startswith("/?"):
                    html = _render_html(title)
                    self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
                    return

                if self.path == "/graph":
                    with st.lock:
                        body = json.dumps(st.graph).encode("utf-8")
                    self._send(200, body, "application/json; charset=utf-8")
                    return

                if self.path == "/state":
                    with st.lock:
                        body = json.dumps({"states": st.states}).encode("utf-8")
                    self._send(200, body, "application/json; charset=utf-8")
                    return

                if self.path.startswith("/logs"):
                    # /logs?after=<seq>
                    u = urlparse(self.path)
                    q = parse_qs(u.query or "")
                    after_s = (q.get("after", ["0"]) or ["0"])[0]
                    try:
                        after = int(after_s)
                    except Exception:
                        after = 0

                    with st.lock:
                        items = [(seq, line) for (seq, line) in st.logs if seq > after]
                        payload = {"seq": st.log_seq, "items": items}

                    body = json.dumps(payload).encode("utf-8")
                    self._send(200, body, "application/json; charset=utf-8")
                    return

                self._send(404, b"Not found", "text/plain; charset=utf-8")

            def log_message(self, fmt: str, *args: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)

        def run() -> None:
            assert self._server is not None
            self._server.serve_forever()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

        # Emit a single, neutral startup line (avoid sticky placeholders).
        self.push_log(f"Visualizer running at http://127.0.0.1:{self.port}/")

        if open_browser:
            time.sleep(0.15)
            webbrowser.open(f"http://127.0.0.1:{self.port}/")
