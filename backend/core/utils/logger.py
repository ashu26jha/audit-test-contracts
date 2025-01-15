import logging
import sys

import colorlog

# Create a logger
logger = logging.getLogger("Audit Agent")

# Set the logging level to DEBUG
logger.setLevel(logging.DEBUG)

# Define primary log level colors
log_colors = {
    "DEBUG": "cyan",
    "INFO": "green",
    "WARNING": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold_red",
}


# Create a color formatter
formatter = colorlog.ColoredFormatter(
    "%(log_color)s%(levelname)s%(reset)s: %(asctime)s - %(name)s - "
    "%(message_log_color)s%(message)s%(reset)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    log_colors=log_colors,
    reset=True,
)

# Create a stream handler (for console output)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(stream_handler)

# Export the logger instance
error = logger.error
exception = logger.exception
info = logger.info
warning = logger.warning
debug = logger.debug
critical = logger.critical
