"""Terminology: Verifier Standard (VSTD).

The `.m` ordinal inside a rung is a topological order: a prerequisite always sorts
before what depends on it. That property held across all 734 edges before anything
checked it, which is exactly why it needs a gate -- an invariant maintained by care
stops being maintained the moment the catalogue grows faster than one reader.

It is also the property that makes a flat ordinal the right encoding. An implicit
heap array was considered and rejected: a heap gives each node exactly one parent,
and 94 of the 106 rungs contain a row with two or more prerequisites (in-degree
reaches 13), so a heap index could not carry the causal structure it was wanted for.
A directed acyclic graph (DAG) has
edges that do not fit in one scalar per node. What a scalar can carry is this:
numeric order is a legal execution order, and the numbering is dense.
"""

from __future__ import annotations

from verifier.core.profile_obligations import (
    DOMAIN_OBLIGATIONS,
    GRAPH_OBLIGATIONS,
    OBLIGATIONS,
)


def _rows():
    """Yield (rung, index, identifier, parent_identifiers) over every axis.

    The base-object ladder numbers itself `1.1` with no object prefix, so its rows
    and its `depends_on` entries are qualified here to keep identifiers disjoint.
    """
    for o in DOMAIN_OBLIGATIONS:
        yield (o.object_name, o.profile), o.index, o.id, tuple(o.depends_on)
    for o in GRAPH_OBLIGATIONS:
        yield ("GRAPH", o.profile), o.index, o.id, tuple(o.depends_on)
    for o in OBLIGATIONS:
        yield (("VSTD", o.profile), o.index, "VSTD-" + o.id,
               tuple("VSTD-" + p for p in o.depends_on))


def test_every_prerequisite_resolves() -> None:
    known = {ident for _, _, ident, _ in _rows()}
    dangling = sorted({p for _, _, ident, parents in _rows()
                       for p in parents if p not in known})
    assert not dangling, f"depends_on names obligations that do not exist: {dangling}"


def test_no_prerequisite_crosses_a_rung() -> None:
    rung = {ident: r for r, _, ident, _ in _rows()}
    crossing = sorted((ident, p) for _, _, ident, parents in _rows()
                      for p in parents if rung[p] != rung[ident])
    assert not crossing, (
        "an inner ladder must be self-contained, so a rung's prerequisites stay "
        f"inside it; these cross: {crossing}")


def test_the_ordinal_is_a_topological_order() -> None:
    """A parent always sorts strictly before the row that depends on it."""
    index = {ident: i for _, i, ident, _ in _rows()}
    inverted = sorted((ident, index[ident], p, index[p])
                      for _, _, ident, parents in _rows()
                      for p in parents if index[p] >= index[ident])
    assert not inverted, (
        "the .m ordinal must be a topological order -- reading a rung in numeric "
        f"order must never reach a row before its prerequisite: {inverted}")


def test_the_numbering_is_dense() -> None:
    """No holes: each rung numbers 1..n with nothing skipped and nothing repeated.

    Density is not decoration. It is the property a heap encoding would have lost,
    and it is what lets a rung's size be read off its last ordinal.
    """
    seen: dict[tuple[str, int], list[int]] = {}
    for rung, i, _, _ in _rows():
        seen.setdefault(rung, []).append(i)
    broken = {rung: sorted(ix) for rung, ix in seen.items()
              if sorted(ix) != list(range(1, len(ix) + 1))}
    assert not broken, f"rungs whose ordinals are not a dense 1..n run: {broken}"


def test_the_gate_measures_the_whole_catalogue() -> None:
    """Guard the guard: a gate over an axis it forgot to load is a green no-op."""
    rows = list(_rows())
    expected = len(DOMAIN_OBLIGATIONS) + len(GRAPH_OBLIGATIONS) + len(OBLIGATIONS)
    assert len(rows) == expected, (
        f"the gate sees {len(rows)} rows but the catalogue holds {expected}; "
        "an axis is missing and every assert above is weaker than it reads")
    assert len({ident for _, _, ident, _ in rows}) == len(rows), (
        "two obligations share an identifier, so the index map silently drops one")
    assert sum(len(p) for _, _, _, p in rows) > 700, (
        "edge count collapsed; the gate would pass over a catalogue with no edges")
