"""Custom exceptions used across Argis."""


class ArgisError(Exception):
    """Base class for all Argis-specific errors."""


class SiteConfigError(ArgisError):
    """Raised when sites.json is missing, malformed, or fails validation."""


class SiteBlockedError(ArgisError):
    """Raised when a target site actively blocks or rate-limits the scanner."""

    def __init__(self, site_name: str, detail: str = ""):
        self.site_name = site_name
        self.detail = detail
        message = f"{site_name} blocked the request"
        if detail:
            message += f": {detail}"
        super().__init__(message)


class HistoryError(ArgisError):
    """Raised when reading or writing scan history fails."""
