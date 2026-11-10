"""Call graph: who calls whom, bounded neighbourhoods and the path from an entry point.

Built from results the slow lane already has (direct calls per function and the xref index);
it adds no facts and no score. A whole-program picture is unreadable beyond a few dozen
functions, so the unit shown to the analyst is the neighbourhood of one function.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
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

    def neighbourhood(
        self, center: int, callers_depth: int = 2, callees_depth: int = 2, max_nodes: int = 60
    ) -> Neighbourhood:
        """Breadth-first both ways from ``center``; at most ``max_nodes`` functions."""
        up: dict[int, int] = {}  # start -> distance on the caller side
        down: dict[int, int] = {}
        shown: set[int] = {center}
        truncated = False
        # Alternate the two sides level by level so a hub on one side cannot starve the other.
        frontiers = {"up": [center], "down": [center]}
        for level in range(1, max(callers_depth, callees_depth) + 1):
            for side, depth, seen, step in (
                ("down", callees_depth, down, self.callees),
                ("up", callers_depth, up, self.callers),
            ):
                if level > depth:
                    continue
                reached: list[int] = []
                for node in frontiers[side]:
                    for nxt in step(node):
                        if nxt == center or nxt in seen:
                            continue
                        if nxt not in shown and len(shown) >= max_nodes:
                            truncated = True
                            continue
                        seen[nxt] = level
                        shown.add(nxt)
                        reached.append(nxt)
                frontiers[side] = reached

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
