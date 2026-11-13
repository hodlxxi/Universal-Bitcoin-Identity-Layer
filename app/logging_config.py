"""Optional legacy file logging for runtimes with immutable source directories."""

import logging
import os
from logging.handlers import RotatingFileHandler


def configure_legacy_file_logging(logger: logging.Logger, log_file: str) -> None:
    """Add the existing rotating handler only for an explicitly configured file."""
    if not log_file:
        return

    directory = os.path.dirname(log_file)
    if directory:
        os.makedirs(directory, exist_ok=True)

    handler = RotatingFileHandler(log_file, maxBytes=10485760, backupCount=10)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"))
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
