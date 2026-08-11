"""``python -m oceanids`` entry point (used by the tmux launcher)."""

from oceanids.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
