"""Overview tree walk: dot directories (incl. the .oceanids artifacts dir) are pruned."""

from pathlib import Path

from oceanids.pipeline.overview import build_overview


def test_overview_skips_dot_directories(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def f() -> None:\n    pass\n", encoding="utf-8")
    artifacts = tmp_path / ".oceanids" / "probes"
    artifacts.mkdir(parents=True)
    (artifacts / "probe_leftover.py").write_text("def g() -> None:\n    pass\n", encoding="utf-8")
    git = tmp_path / ".git"
    git.mkdir()
    (git / "hook.py").write_text("def h() -> None:\n    pass\n", encoding="utf-8")

    overview = build_overview(tmp_path)
    # The artifacts dir and VCS metadata are never treated as target code.
    assert [file.path for file in overview.files] == ["app.py"]
