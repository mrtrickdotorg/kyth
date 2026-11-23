"""Pull Qt off the live display before any test module is imported.

Individual modules do `os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")`,
which is a silent no-op in a desktop session that already exports the
variable — and it only protects the module that remembered to write it.
pytest loads this file first, so forcing it here covers every module,
including ones added later that forget.
"""

import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

# Nothing under test should reach the session compositor or its GPU, so make
# it unreachable rather than merely unpreferred.
os.environ.pop("WAYLAND_DISPLAY", None)
os.environ.pop("DISPLAY", None)
os.environ.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")
