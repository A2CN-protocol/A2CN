"""A2CN reference implementation."""

import json
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import url2pathname

_SOURCE_VERSION = "0.0.0+source"


def _installed_version() -> str:
    """The version of the installed distribution that owns this source tree.

    Another distribution named ``a2cn`` may be installed while Python imports a
    different tree, so its version is reported only when that distribution's
    files, or its editable install root, are the tree imported here.
    """
    try:
        dist = distribution("a2cn")
    except PackageNotFoundError:
        return _SOURCE_VERSION
    here = Path(__file__).resolve()
    if Path(dist.locate_file("a2cn/__init__.py")).resolve() == here:
        return dist.version
    direct_url = dist.read_text("direct_url.json")
    if direct_url:
        info = json.loads(direct_url)
        url = urlparse(info.get("url", ""))
        if info.get("dir_info", {}).get("editable") and url.scheme == "file":
            if Path(url2pathname(url.path)).resolve() == here.parent.parent:
                return dist.version
    return _SOURCE_VERSION


__version__ = _installed_version()

from a2cn.versions import PROTOCOL_VERSIONS  # noqa: E402

__all__ = ["PROTOCOL_VERSIONS", "__version__"]
