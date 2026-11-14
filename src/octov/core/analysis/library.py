"""Which signature matches count as "this function is known library code".

The matcher (``octov.ext.library_worker``) reports every name a function's bytes could have.
A wrong library name hides the sample's own code, a missed one only costs reading time, so
this policy accepts a name only when nothing speaks against it.

Why the rules are this strict: the FLARE signature files hold 700 000 signatures and the
matcher sees only a function's first bytes, so a big program collects look-alikes by chance
(measured 2026-11-14: twinui.dll, 18 551 functions, got 123 MFC and 93 Crypto++ names
although it contains neither). Real library code differs from look-alikes in two ways: each
function exists once, and the linker puts a library's functions next to each other.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

MIN_SIZE = 16  # shorter functions are too generic to name (getters, thunks, stubs)
MIN_PER_SET = 5  # fewer matches from one signature file = the library is not really there
NEIGHBOUR_REACH = 2  # a match needs another one within this many functions (address order)


@dataclass(frozen=True)
class Candidate:
    """Names one signature file has for the function at ``rva`` (``count`` distinct names)."""

    rva: int
    set: str
    names: tuple[str, ...]
    count: int


@dataclass(frozen=True)
class LibraryMatch:
    start: int
    name: str
    source: str  # signature file


def accept(candidates: Sequence[Candidate], sizes: Mapping[int, int]) -> dict[int, LibraryMatch]:
    """Accepted matches by function start; ``sizes`` are the sizes of *all* discovered functions.

    A function is named only if (1) it has exactly one possible name, (2) it is not tiny,
    (3) no other function got the same name, (4) a function at most ``NEIGHBOUR_REACH``
    places away in address order passed 1-3 with the same signature file, and (5) that
    signature file has at least ``MIN_PER_SET`` such functions in the sample.
    """
    by_rva: dict[int, list[Candidate]] = {}
    for c in candidates:
        by_rva.setdefault(c.rva, []).append(c)

    kept: dict[int, LibraryMatch] = {}
    for rva, group in by_rva.items():
        names = {n for c in group for n in c.names}
        if len(names) != 1 or any(c.count != 1 for c in group):
            continue  # more than one possible name
        if sizes.get(rva, 0) < MIN_SIZE:
            continue  # tiny, or not a discovered function
        kept[rva] = LibraryMatch(rva, next(iter(names)), min(c.set for c in group))

    uses = Counter(m.name for m in kept.values())
    kept = {rva: m for rva, m in kept.items() if uses[m.name] == 1}

    order = sorted(sizes)
    position = {start: i for i, start in enumerate(order)}

    def has_neighbour(m: LibraryMatch) -> bool:
        i = position[m.start]
        for j in range(max(0, i - NEIGHBOUR_REACH), min(len(order), i + NEIGHBOUR_REACH + 1)):
            other = kept.get(order[j])
            if j != i and other is not None and other.source == m.source:
                return True
        return False

    kept = {rva: m for rva, m in kept.items() if has_neighbour(m)}
    per_set = Counter(m.source for m in kept.values())
    return {rva: m for rva, m in sorted(kept.items()) if per_set[m.source] >= MIN_PER_SET}
