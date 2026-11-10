"""Call graph: who calls whom, bounded neighbourhoods and the path from an entry point.

Built from results the slow lane already has (direct calls per function and the xref index);
it adds no facts and no score. A whole-program picture is unreadable beyond a few dozen
functions, so the unit shown to the analyst is the neighbourhood of one function.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from octov.core.analysis.naming import API_FAMILIES
from octov.core.analysis.scoring import SUSPICIOUS_FAMILIES
from octov.core.analysis.xrefs import XrefIndex
from octov.core.static.cfg import Function
from octov.core.static.pe_parser import normalize_api

Role = Literal["center", "caller", "callee", "both"]
_FAMILY_OF = {api: family for family, apis in API_FAMILIES.items() for api in apis}


@dataclass(frozen=True)
class Neighbour:
    start: int
    role: Role
    distance: int  # calls away from the centre (0 for the centre)
    hidden_callers: int  # callers that exist but are not in this neighbourhood
    hidden_callees: int


@dataclass(frozen=True)
class Neighbourhood:
    center: int
    nodes: tuple[Neighbour, ...]
    edges: tuple[tuple[int, int], ...]  # (caller, callee), both shown
    truncated: bool  # max_nodes cut the walk short


@dataclass(frozen=True)
class ApiUse:
    name: str  # without dll! and without the A/W suffix
    family: str | None
    suspicious: bool


class CallGraph:
    def __init__(
        self,
        callees: dict[int, tuple[int, ...]],
        callers: dict[int, tuple[int, ...]],
        rec: set[int],
    ) -> None:
        self._callees = callees
        self._callers = callers
        self._recursive = rec

    @classmethod
    def build(cls, functions: Mapping[int, Function], xrefs: XrefIndex | None) -> CallGraph:
        """Direct calls between discovered functions, plus tail jumps to another function."""
        out: dict[int, set[int]] = {}
        recursive: set[int] = set()
        for start, fn in functions.items():
            targets = {t for t in fn.calls if t in functions}
            if xrefs is not None:
                targets |= {
                    x.dst
                    for x in xrefs.from_function(start)
                    if x.kind == "jump" and x.dst in functions and x.dst != start
                }
            if start in targets:
                recursive.add(start)
                targets.discard(start)
            out[start] = targets
        incoming: dict[int, set[int]] = {start: set() for start in functions}
        for start, targets in out.items():
            for target in targets:
                incoming[target].add(start)
        return cls(
            {k: tuple(sorted(v)) for k, v in out.items()},
            {k: tuple(sorted(v)) for k, v in incoming.items()},
            recursive,
        )

    def callees(self, start: int) -> tuple[int, ...]:
        return self._callees.get(start, ())

    def callers(self, start: int) -> tuple[int, ...]:
        return self._callers.get(start, ())

    def recursive(self, start: int) -> bool:
        return start in self._recursive

    def _walk(
        self, center: int, step: Callable[[int], tuple[int, ...]], depth: int, cap: int
    ) -> tuple[list[tuple[int, int]], bool]:
        """Breadth-first ``(function, level)`` from ``center``; ``True`` when cut at ``cap``."""
        order: list[tuple[int, int]] = []
        seen = {center}
        frontier = [center]
        for level in range(1, depth + 1):
            reached: list[int] = []
            for node in frontier:
                for nxt in step(node):
                    if nxt in seen:
                        continue
                    if len(order) >= cap:
                        return order, True
                    seen.add(nxt)
                    order.append((nxt, level))
                    reached.append(nxt)
            frontier = reached
        return order, False

    def neighbourhood(
        self,
        center: int,
        callers_depth: int = 2,
        callees_depth: int = 2,
        max_nodes: int = 60,
        keep: Sequence[int] = (),
    ) -> Neighbourhood:
        """The functions around ``center``, at most ``max_nodes`` of them.

        ``keep`` is a call chain ending at the centre (the path from an entry point): it is
        always shown, whatever the depth. The rest of the room is shared by the two sides, so
        neither a hub of callers nor a hub of callees can push the other side out; what one
        side does not need goes to the other.
        """
        up: dict[int, int] = {}  # start -> distance on the caller side
        down: dict[int, int] = {}
        shown: set[int] = {center}
        chain = [start for start in keep if start != center][-(max_nodes // 2) :]
        for distance, start in enumerate(reversed(chain), 1):
            up[start] = distance
            shown.add(start)
        sides = (
            (down, self._walk(center, self.callees, callees_depth, max_nodes)),
            (up, self._walk(center, self.callers, callers_depth, max_nodes)),
        )

        def take(seen: dict[int, int], order: list[tuple[int, int]], quota: int) -> bool:
            """Show the next functions of one side; ``True`` when the side is exhausted."""
            for start, level in order:
                if start in shown:
                    seen.setdefault(start, level)
                    continue
                if quota <= 0:
                    return False
                quota -= 1
                shown.add(start)
                seen[start] = level
            return True

        room = max_nodes - len(shown)
        finished = [take(sides[0][0], sides[0][1][0], room // 2)]
        finished.append(take(sides[1][0], sides[1][1][0], max_nodes - len(shown)))
        finished[0] = take(sides[0][0], sides[0][1][0], max_nodes - len(shown))
        truncated = not all(finished) or sides[0][1][1] or sides[1][1][1]

        def role(start: int) -> Role:
            if start == center:
                return "center"
            if start in up and start in down:
                return "both"
            return "caller" if start in up else "callee"

        nodes = tuple(
            Neighbour(
                start=start,
                role=role(start),
                distance=0 if start == center else min(up.get(start, 99), down.get(start, 99)),
                hidden_callers=sum(1 for c in self.callers(start) if c not in shown),
                hidden_callees=sum(1 for c in self.callees(start) if c not in shown),
            )
            for start in sorted(shown)
        )
        edges = tuple(
            (start, callee)
            for start in sorted(shown)
            for callee in self.callees(start)
            if callee in shown
        )
        return Neighbourhood(center, nodes, edges, truncated)

    def path_to(self, center: int, roots: Iterable[int]) -> tuple[int, ...]:
        """Shortest call chain from any root to ``center`` (root first); ``()`` if none."""
        wanted = set(roots)
        if center in wanted or center not in self._callers:
            return ()
        via: dict[int, int] = {}  # caller -> the function it calls on the way to the centre
        queue = deque([center])
        seen = {center}
        while queue:
            node = queue.popleft()
            for caller in self.callers(node):
                if caller in seen:
                    continue
                seen.add(caller)
                via[caller] = node
                if caller in wanted:
                    path = [caller]
                    while path[-1] != center:
                        path.append(via[path[-1]])
                    return tuple(path)
                queue.append(caller)
        return ()


def apis_of(xrefs: XrefIndex | None, start: int) -> tuple[ApiUse, ...]:
    """Imported APIs a function references: suspicious families first, then by name."""
    if xrefs is None:
        return ()
    names = {normalize_api(full.rpartition("!")[2]) for full in xrefs.imports_called(start)}
    uses = [
        ApiUse(name, _FAMILY_OF.get(name), _FAMILY_OF.get(name) in SUSPICIOUS_FAMILIES)
        for name in names
    ]
    return tuple(sorted(uses, key=lambda u: (not u.suspicious, u.family is None, u.name)))
