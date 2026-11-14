from __future__ import annotations

from octov.core.analysis.library import MIN_PER_SET, MIN_SIZE, Candidate, LibraryMatch, accept


def _one(rva: int, name: str, sig: str = "a.sig") -> Candidate:
    return Candidate(rva=rva, set=sig, names=(name,), count=1)


def _good(n: int, sig: str = "a.sig", base: int = 0x1000) -> list[Candidate]:
    return [_one(base + i * 0x100, f"{sig}_fn{i}", sig) for i in range(n)]


def _sizes(candidates: list[Candidate], size: int = 40) -> dict[int, int]:
    return {c.rva: size for c in candidates}


def test_constants_match_the_design() -> None:
    assert (MIN_SIZE, MIN_PER_SET) == (16, 5)


def test_unique_names_from_a_present_library_are_accepted() -> None:
    cands = _good(6)
    got = accept(cands, _sizes(cands))
    assert len(got) == 6
    assert got[0x1000] == LibraryMatch(start=0x1000, name="a.sig_fn0", source="a.sig")


def test_two_names_for_one_function_are_dropped() -> None:
    cands = _good(6)
    cands.append(Candidate(rva=0x9000, set="a.sig", names=("x", "y"), count=2))
    # the same function named differently by two signature files
    cands += [_one(0xA000, "p", "a.sig"), _one(0xA000, "q", "b.sig")]
    got = accept(cands, _sizes(cands))
    assert 0x9000 not in got and 0xA000 not in got
    assert len(got) == 6


def test_tiny_functions_are_dropped() -> None:
    cands = _good(7)
    sizes = _sizes(cands)
    sizes[0x1000] = 15
    sizes[0x1100] = 16
    got = accept(cands, sizes)
    assert 0x1000 not in got
    assert 0x1100 in got


def test_a_lone_match_of_a_set_is_dropped() -> None:
    cands = _good(5) + _good(1, "b.sig", base=0x8000)
    got = accept(cands, _sizes(cands))
    assert sorted(got) == [c.rva for c in cands[:5]]


def test_unknown_function_start_is_dropped() -> None:
    cands = _good(6)
    sizes = _sizes(cands)
    del sizes[0x1000]
    assert 0x1000 not in accept(cands, sizes)


def test_tiny_and_ambiguous_do_not_count_towards_the_set() -> None:
    cands = _good(5)
    sizes = _sizes(cands)
    sizes[0x1000] = 8  # four good ones left: below MIN_PER_SET
    assert accept(cands, sizes) == {}


def test_a_name_given_to_two_functions_is_dropped_for_both() -> None:
    cands = _good(6)
    cands += [_one(0x1600, "twin"), _one(0x1700, "twin")]
    got = accept(cands, _sizes(cands))
    assert 0x1600 not in got and 0x1700 not in got
    assert len(got) == 6


def test_scattered_matches_are_dropped() -> None:
    # library code sits together; six look-alikes spread over the sample's own code do not
    starts = [0x1000 + i * 0x100 for i in range(60)]
    sizes = dict.fromkeys(starts, 40)
    scattered = [_one(s, f"fn{s:x}") for s in starts[::10]]
    assert accept(scattered, sizes) == {}


def test_matches_need_a_neighbour_from_the_same_set() -> None:
    starts = [0x1000 + i * 0x100 for i in range(60)]
    sizes = dict.fromkeys(starts, 40)
    block = [_one(s, f"fn{s:x}") for s in starts[20:26]]  # six in a row
    reach = _one(starts[28], "two_functions_away")  # 26 and 27 are not library code
    far = _one(starts[40], "alone")
    other_set = _one(starts[19], "other", "b.sig")  # adjacent, but another signature file
    got = accept([*block, reach, far, other_set], sizes)
    assert sorted(got) == starts[20:26]
    near = _one(starts[27], "next_but_one")  # one function between it and the block
    assert starts[27] in accept([*block, near], sizes)
