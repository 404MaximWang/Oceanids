"""Intentionally buggy micro-library: the e2e target for Oceanids."""


def average(numbers: list[float]) -> float:
    """Arithmetic mean. Planted bug: crashes with ZeroDivisionError on []."""
    total = 0.0
    for value in numbers:
        total += value
    return total / len(numbers)


def clamp(value: float, low: float, high: float) -> float:
    """Bound ``value`` into [low, high]; correct, here as a control."""
    return max(low, min(high, value))
