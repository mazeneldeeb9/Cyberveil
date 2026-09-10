"""CYBERVEIL safe behavior-monitoring demonstrator."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cyberveil")
except PackageNotFoundError:  # pragma: no cover - source checkout before installation
    __version__ = "0.1.0"

__all__ = ["__version__"]
