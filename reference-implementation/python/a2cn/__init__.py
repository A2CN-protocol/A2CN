"""A2CN reference implementation."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("a2cn")
except PackageNotFoundError:  # a source tree that is not installed
    __version__ = "0.0.0+source"

from a2cn.versions import PROTOCOL_VERSIONS

__all__ = ["PROTOCOL_VERSIONS", "__version__"]
