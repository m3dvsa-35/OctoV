"""Which signature matches count as "this function is known library code".

The matcher (``octov.ext.library_worker``) reports every name a function's bytes could have.
A wrong library name hides the sample's own code, a missed one only costs reading time, so
this policy accepts a name only when nothing speaks against it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

MIN_SIZE = 16  # shorter functions are too generic to name (getters, thunks, stubs)
MIN_PER_SET = 5  # fewer matches from one signature file = the library is not really there


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
    """Accepted matches by function start; ``sizes`` are the discovered functions' sizes."""
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

    per_set = Counter(m.source for m in kept.values())
    return {rva: m for rva, m in sorted(kept.items()) if per_set[m.source] >= MIN_PER_SET}
