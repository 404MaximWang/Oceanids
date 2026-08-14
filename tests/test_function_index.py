"""Function-index tree walk: dot directories (incl. the .oceanids artifacts dir) are pruned."""

from pathlib import Path

from oceanids.pipeline.function_index import build_function_index


def test_index_skips_dot_directories(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def f() -> None:\n    pass\n", encoding="utf-8")
    artifacts = tmp_path / ".oceanids" / "probes"
    artifacts.mkdir(parents=True)
    (artifacts / "probe_leftover.py").write_text("def g() -> None:\n    pass\n", encoding="utf-8")
    git = tmp_path / ".git"
    git.mkdir()
    (git / "hook.py").write_text("def h() -> None:\n    pass\n", encoding="utf-8")

    index = build_function_index(tmp_path)
    # The artifacts dir and VCS metadata are never treated as target code.
    assert [file.path for file in index.files] == ["app.py"]


def test_index_never_follows_symlinks(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("def s() -> None:\n    pass\n", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("def f() -> None:\n    pass\n", encoding="utf-8")
    (target / "link_file.py").symlink_to(outside / "secret.py")
    (target / "link_dir").symlink_to(outside, target_is_directory=True)

    index = build_function_index(target)
    # Neither a symlinked file nor files reached through a symlinked dir are indexed.
    assert [file.path for file in index.files] == ["app.py"]
