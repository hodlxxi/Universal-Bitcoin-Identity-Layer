class HODLXXIMCPError(RuntimeError):
    """Base error for the standalone read-only wrapper."""


class InvalidIdentifierError(HODLXXIMCPError):
    """An identifier or pagination parameter failed local validation."""


class UpstreamHTTPError(HODLXXIMCPError):
    """The fixed HODLXXI upstream returned a non-success response."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"HODLXXI upstream returned HTTP {status_code}")


class UpstreamContentTypeError(HODLXXIMCPError):
    """The upstream response was not a permitted JSON media type."""


class ResponseTooLargeError(HODLXXIMCPError):
    """The upstream response exceeded the configured byte ceiling."""


class InvalidJSONError(HODLXXIMCPError):
    """The upstream response was not a JSON object."""
