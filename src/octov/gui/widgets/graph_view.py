"""Native control-flow graph view (QGraphicsView, fully offline).

Layout: blocks are layered by longest path from the entry over the DAG that
remains after removing back edges (loops); back edges are routed around the
left side. Edge meaning is encoded three ways: colour, line style and a text
label ("T"/"F"), so it never depends on colour alone.
"""

from __future__ import annotations

from collections import defaultdict, deque

from PySide6.QtCore import QPointF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QFontMetricsF, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QGraphicsItem,
    QGraphicsPathItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsSceneMouseEvent,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QWidget,
)

from octov.core.static.cfg import BasicBlock, Function
from octov.gui.theme import PALETTES

MAX_LINES_PER_BLOCK = 14
MAX_GRAPH_BLOCKS = 600
H_GAP = 40.0
V_GAP = 56.0
PAD = 6.0

EDGE_STYLE: dict[str, tuple[str, Qt.PenStyle, str]] = {
    "true": ("#3fb950", Qt.PenStyle.SolidLine, "T"),
    "false": ("#f85149", Qt.PenStyle.DashLine, "F"),
    "jump": ("#58a6ff", Qt.PenStyle.SolidLine, ""),
    "fallthrough": ("#8b949e", Qt.PenStyle.SolidLine, ""),
}


def layer_blocks(fn: Function) -> dict[int, int]:
    """Longest-path layering over the CFG with back edges removed."""
    succ = {
        s: [e.target for e in b.successors if e.target in fn.blocks] for s, b in fn.blocks.items()
    }
    back: set[tuple[int, int]] = set()
    state: dict[int, int] = {}  # 1 = on stack, 2 = done
    stack: list[tuple[int, int]] = [(fn.start, 0)] if fn.start in fn.blocks else []
    if stack:
        state[fn.start] = 1
    while stack:
        node, idx = stack[-1]
        if idx < len(succ[node]):
            stack[-1] = (node, idx + 1)
            nxt = succ[node][idx]
            if state.get(nxt) == 1:
                back.add((node, nxt))
            elif nxt not in state:
                state[nxt] = 1
                stack.append((nxt, 0))
        else:
            state[node] = 2
            stack.pop()

    indeg: dict[int, int] = defaultdict(int)
    for s, targets in succ.items():
        for t in targets:
            if (s, t) not in back:
                indeg[t] += 1
    layer = {s: 0 for s in fn.blocks}
    queue = deque(s for s in fn.blocks if indeg[s] == 0)
    while queue:
        s = queue.popleft()
        for t in succ[s]:
            if (s, t) in back:
                continue
            layer[t] = max(layer[t], layer[s] + 1)
            indeg[t] -= 1
            if indeg[t] == 0:
                queue.append(t)
    return layer


class BlockItem(QGraphicsRectItem):
    def __init__(self, block: BasicBlock, font: QFont, palette: dict[str, str], view: CFGGraphView):
        lines = [f"loc_{block.start:x}:"]
        insns = block.instructions
        for insn in insns[:MAX_LINES_PER_BLOCK]:
            lines.append(f"{insn.address:08x}  {insn.text()}")
        if len(insns) > MAX_LINES_PER_BLOCK:
            lines.append(f"... (+{len(insns) - MAX_LINES_PER_BLOCK})")
        text = "\n".join(lines)
        metrics = QFontMetricsF(font)
        width = max(metrics.horizontalAdvance(line) for line in lines) + 2 * PAD
        height = metrics.lineSpacing() * len(lines) + 2 * PAD
        super().__init__(0, 0, width, height)
        self.block = block
        self._view = view
        self._palette = palette
        self.setBrush(QBrush(QColor(palette["base"])))
        self.set_selected(False)
        label = QGraphicsSimpleTextItem(text, self)
        label.setFont(font)
        label.setBrush(QBrush(QColor(palette["fg"])))
        label.setPos(PAD, PAD)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, False)

    def set_selected(self, on: bool) -> None:
        color = self._palette["accent"] if on else self._palette["border"]
        self.setPen(QPen(QColor(color), 2.5 if on else 1.0))

    def mousePressEvent(self, event: QGraphicsSceneMouseEvent) -> None:  # noqa: N802
        self._view.blockSelected.emit(self.block.start)
        super().mousePressEvent(event)


class EdgeItem(QGraphicsPathItem):
    def __init__(self, path: QPainterPath, kind: str) -> None:
        super().__init__(path)
        self.kind = kind
        color, style, _ = EDGE_STYLE[kind]
        pen = QPen(QColor(color), 1.6)
        pen.setStyle(style)
        self.setPen(pen)
        self.setZValue(-1)


class CFGGraphView(QGraphicsView):
    blockSelected = Signal(int)  # noqa: N815 (Qt signal naming)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.block_items: dict[int, BlockItem] = {}
        self.highlighted_block: int | None = None
        self.function: Function | None = None
        self.theme = "dark"
        self._font = QFont("Cascadia Mono")
        self._font.setStyleHint(QFont.StyleHint.Monospace)
        self._font.setPointSizeF(8.5)
        self.too_large_text = (
            "sub_{start}: {count} blocks - too large to draw; use the disassembly listing."
        )

    def clear(self) -> None:
        self.scene().clear()
        self.block_items.clear()
        self.highlighted_block = None
        self.function = None

    def set_theme(self, theme: str) -> None:
        self.theme = theme
        self.setBackgroundBrush(QBrush(QColor(PALETTES[theme]["bg"])))
        if self.function is not None:
            self.set_function(self.function)

    def wheelEvent(self, event) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)

    def set_function(self, fn: Function) -> None:
        scene = self.scene()
        scene.clear()
        self.block_items.clear()
        self.highlighted_block = None
        self.function = fn
        palette = PALETTES[self.theme]
        if len(fn.blocks) > MAX_GRAPH_BLOCKS:
            msg = scene.addSimpleText(
                self.too_large_text.format(start=f"{fn.start:x}", count=len(fn.blocks))
            )
            msg.setBrush(QBrush(QColor(palette["fg"])))
            return

        layers = layer_blocks(fn)
        by_layer: dict[int, list[int]] = defaultdict(list)
        for start in sorted(fn.blocks):
            by_layer[layers[start]].append(start)

        for start, block in fn.blocks.items():
            item = BlockItem(block, self._font, palette, self)
            scene.addItem(item)
            self.block_items[start] = item

        y = 0.0
        for depth in sorted(by_layer):
            row = [self.block_items[s] for s in by_layer[depth]]
            total = sum(i.rect().width() for i in row) + H_GAP * (len(row) - 1)
            x = -total / 2
            for item in row:
                item.setPos(x, y)
                x += item.rect().width() + H_GAP
            y += max(i.rect().height() for i in row) + V_GAP

        for start, block in fn.blocks.items():
            for edge in block.successors:
                if edge.target in self.block_items:
                    self._add_edge(start, edge.target, edge.kind, layers)
        self.setSceneRect(scene.itemsBoundingRect().adjusted(-40, -40, 40, 40))

    def _add_edge(self, src: int, dst: int, kind: str, layers: dict[int, int]) -> None:
        a, b = self.block_items[src], self.block_items[dst]
        ra, rb = a.sceneBoundingRect(), b.sceneBoundingRect()
        start = QPointF(ra.center().x(), ra.bottom())
        end = QPointF(rb.center().x(), rb.top())
        path = QPainterPath(start)
        if layers[dst] <= layers[src]:  # back edge: route around the left
            left = min(ra.left(), rb.left()) - 24
            path.lineTo(start.x(), start.y() + 12)
            path.lineTo(left, start.y() + 12)
            path.lineTo(left, end.y() - 12)
            path.lineTo(end.x(), end.y() - 12)
            path.lineTo(end)
        else:
            mid = (start.y() + end.y()) / 2
            path.cubicTo(QPointF(start.x(), mid), QPointF(end.x(), mid), end)
        # arrow head
        path.moveTo(end)
        path.lineTo(end.x() - 5, end.y() - 8)
        path.moveTo(end)
        path.lineTo(end.x() + 5, end.y() - 8)
        self.scene().addItem(EdgeItem(path, kind))
        color, _, label = EDGE_STYLE[kind]
        if label:
            text = self.scene().addSimpleText(label)
            text.setBrush(QBrush(QColor(color)))
            # Offset T to the right and F to the left so both stay readable.
            dx = 6 if kind == "true" else -14
            text.setPos(start.x() + dx, start.y() + 2)

    def highlight(self, rva: int) -> None:
        target = next(
            (s for s, item in self.block_items.items() if item.block.start <= rva < item.block.end),
            None,
        )
        if self.highlighted_block in self.block_items:
            self.block_items[self.highlighted_block].set_selected(False)
        self.highlighted_block = target
        if target is not None:
            item = self.block_items[target]
            item.set_selected(True)
            self.ensureVisible(item)
