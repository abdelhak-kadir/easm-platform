class ToolScanError(Exception):
    """Base class every tool-specific scan error should inherit from.

    The orchestrator (`app.tasks.run_tool_scan`) catches the two
    subclasses below generically, so a new tool never needs new
    dispatch logic in tasks.py -- it only needs to raise the right one
    of these via its own subclass, e.g. `ShodanRateLimitError` inherits
    from both `ShodanScanError` and `ToolRateLimitError`.
    """


class ToolRateLimitError(ToolScanError):
    """Transient failure (API throttling, etc.) -- safe to retry."""


class ToolNoDataError(ToolScanError):
    """The tool ran fine but has nothing for this target -- not a failure."""
