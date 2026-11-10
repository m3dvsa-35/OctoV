from __future__ import annotations

import time

from octov.core.analysis.callgraph import ApiUse, CallGraph, apis_of
from octov.core.analysis.xrefs import Xref, XrefIndex
from octov.core.static.cfg import Function


def fns(calls: dict[int, list[int]]) -> dict[int, Function]:
    return {start: Function(start, {}, list(targets)) for start, targets in calls.items()}


#   1 -> 2 -> 4 -> 5
#   1 -> 3 -> 4
#   6 -> 3
CHAIN = {1: [2, 3], 2: [4], 3: [4], 4: [5], 5: [], 6: [3]}


def test_callers_and_callees() -> None:
    g = CallGraph.build(fns(CHAIN), None)
    assert g.callees(1) == (2, 3)
    assert g.callers(4) == (2, 3)
    assert g.callers(3) == (1, 6)
    assert g.callees(5) == () and g.callers(1) == ()
    assert g.callees(99) == ()  # unknown function: empty, no error


def test_calls_to_undiscovered_targets_are_ignored() -> None:
    g = CallGraph.build(fns({1: [2, 0x9999], 2: []}), None)
    assert g.callees(1) == (2,)


def test_tail_jump_counts_as_call() -> None:
    xrefs = XrefIndex(
        [
            Xref(0x10, 2, "jump", 1),  # tail call into function 2
            Xref(0x14, 0x18, "jump", 1),  # a jump inside function 1
            Xref(0x20, 1, "jump", 1),  # a loop back to its own start
        ],
        {},
    )
    g = CallGraph.build(fns({1: [], 2: []}), xrefs)
    assert g.callees(1) == (2,) and g.callers(2) == (1,)
    assert not g.recursive(1)


def test_neighbourhood_depth_limits() -> None:
    g = CallGraph.build(fns(CHAIN), None)
    near = g.neighbourhood(4, callers_depth=1, callees_depth=1)
    assert {n.start: (n.role, n.distance) for n in near.nodes} == {
        4: ("center", 0),
        2: ("caller", 1),
        3: ("caller", 1),
        5: ("callee", 1),
    }
    assert set(near.edges) == {(2, 4), (3, 4), (4, 5)}
    assert not near.truncated
    hidden = {n.start: (n.hidden_callers, n.hidden_callees) for n in near.nodes}
    assert hidden[2] == (1, 0)  # its caller 1 is one step too far
    assert hidden[3] == (2, 0)  # callers 1 and 6
    assert hidden[4] == (0, 0) and hidden[5] == (0, 0)

    far = g.neighbourhood(4, callers_depth=2, callees_depth=1)
    assert {n.start for n in far.nodes} == {1, 2, 3, 4, 5, 6}
    assert {(n.start, n.distance) for n in far.nodes if n.role == "caller"} == {
        (2, 1),
        (3, 1),
        (1, 2),
        (6, 2),
    }
    assert {(1, 2), (1, 3), (6, 3)} <= set(far.edges)
    assert all(n.hidden_callers == 0 for n in far.nodes)


def test_mutual_recursion_terminates_and_marks_both() -> None:
    g = CallGraph.build(fns({1: [2], 2: [1, 3], 3: [1]}), None)
    hood = g.neighbourhood(1, callers_depth=3, callees_depth=3)
    roles = {n.start: n.role for n in hood.nodes}
    assert roles == {1: "center", 2: "both", 3: "both"}
    assert len(hood.nodes) == 3 and len(set(hood.edges)) == len(hood.edges) == 4
    assert set(hood.edges) == {(1, 2), (2, 1), (2, 3), (3, 1)}


def test_self_call_is_recursive_not_an_edge() -> None:
    g = CallGraph.build(fns({1: [1, 2], 2: []}), None)
    assert g.recursive(1) and not g.recursive(2)
    assert g.callees(1) == (2,) and g.callers(1) == ()
    assert g.neighbourhood(1).edges == ((1, 2),)


def test_hub_is_truncated_with_hidden_counts() -> None:
    calls: dict[int, list[int]] = {1: [2]}
    calls[2] = []
    for caller in range(100, 600):
        calls[caller] = [1]
        calls[caller + 1000] = [caller]  # each caller has its own caller
    g = CallGraph.build(fns(calls), None)
    start = time.perf_counter()
    hood = g.neighbourhood(1, callers_depth=2, callees_depth=2, max_nodes=60)
    assert time.perf_counter() - start < 0.5
    assert hood.truncated and len(hood.nodes) == 60
    center = next(n for n in hood.nodes if n.role == "center")
    shown_callers = sum(1 for n in hood.nodes if n.role == "caller" and n.distance == 1)
    assert shown_callers + center.hidden_callers == 500
    assert center.hidden_callees == 0  # the callee side is small: it is always shown
    assert 2 in {n.start for n in hood.nodes}
    shown = {n.start for n in hood.nodes}
    assert all(src in shown and dst in shown for src, dst in hood.edges)


def test_path_from_entry() -> None:
    #  10 -> 11 -> 12 -> 13 (long)   and   10 -> 14 -> 13 (short)
    g = CallGraph.build(fns({10: [11, 14], 11: [12], 12: [13], 13: [], 14: [13], 20: [13]}), None)
    assert g.path_to(13, [10]) == (10, 14, 13)
    assert g.path_to(13, [20, 10]) == (20, 13)  # the nearest root wins


def test_path_empty_when_unreachable_or_root() -> None:
    g = CallGraph.build(fns(CHAIN), None)
    assert g.path_to(6, [1]) == ()  # nobody calls 6
    assert g.path_to(1, [1]) == ()  # the centre is the entry point itself
    assert g.path_to(99, [1]) == ()


def test_apis_of_normalises_and_orders() -> None:
    imports = {
        0x3000: "kernel32.dll!CreateRemoteThread",
        0x3008: "kernel32.dll!GetTickCount",
        0x3010: "kernel32.dll!CreateFileW",
        0x3018: "advapi32.dll!RegSetValueExA",
    }
    xrefs = XrefIndex(
        [
            Xref(0x1000, 0x3008, "import", 1),
            Xref(0x1004, 0x3010, "import", 1),
            Xref(0x1008, 0x3000, "import", 1),
            Xref(0x100C, 0x3018, "import", 1),
            Xref(0x1010, 0x3010, "import", 1),  # the same API twice
            Xref(0x2000, 0x3008, "import", 2),
        ],
        imports,
    )
    assert apis_of(xrefs, 1) == (
        ApiUse("CreateRemoteThread", "thread_inject", True),
        ApiUse("RegSetValueEx", "registry", True),
        ApiUse("CreateFile", "file_io", False),
        ApiUse("GetTickCount", None, False),
    )
    assert apis_of(xrefs, 3) == () and apis_of(None, 1) == ()
