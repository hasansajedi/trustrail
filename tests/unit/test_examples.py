"""Keep the repository's developer examples runnable and discoverable."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIRECTORY = REPOSITORY_ROOT / "examples"
EXAMPLE_PATHS = sorted(EXAMPLES_DIRECTORY.glob("*.py"))


@pytest.mark.parametrize("example_path", EXAMPLE_PATHS, ids=lambda path: path.name)
def test_example_runs_without_external_services(
    example_path: Path, capsys: pytest.CaptureFixture[str]
):
    runpy.run_path(str(example_path), run_name="__main__")
    capsys.readouterr()


def test_examples_index_links_every_runnable_example():
    examples_index = (EXAMPLES_DIRECTORY / "README.md").read_text(encoding="utf-8")

    for example_path in EXAMPLE_PATHS:
        assert f"({example_path.name})" in examples_index
