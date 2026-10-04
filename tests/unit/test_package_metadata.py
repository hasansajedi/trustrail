"""Distribution metadata guarantees for downstream library consumers."""

from __future__ import annotations

from importlib.resources import files


def test_distribution_declares_inline_typing() -> None:
    assert files("trustrail").joinpath("py.typed").is_file()
